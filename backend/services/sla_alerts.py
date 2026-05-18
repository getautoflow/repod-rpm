"""
Vérification quotidienne des SLA CVE.

Cron planifié chaque matin (08:00) via APScheduler.
Pour chaque décision active (accept_risk, exception, upgrade_required) :
  - Si expirée → repasse le manifest en pending_review + audit log
  - Si expire dans ≤7 jours → collecte pour alerte webhook

Déclenché aussi manuellement via POST /security/check-sla.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
import os

from services.security_decisions import (
    list_all_decisions,
    get_sla_status,
    is_decision_expired,
)
from services.manifest import load_manifest, save_manifest
from services.audit import log as audit_log
from services.notifications import notify_sla_expiring
from services.email_notifications import notify_sla_expiring_email

logger = logging.getLogger("sla_alerts")

MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))


def _manifest_path(name: str, version: str, arch: str) -> Path | None:
    version_safe = version.replace(":", "_").replace("/", "_")
    candidates = [
        MANIFEST_DIR / f"{name}_{version}_{arch}.manifest.json",
        MANIFEST_DIR / f"{name}_{version_safe}_{arch}.manifest.json",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def run_sla_check() -> dict:
    """
    Vérifie toutes les décisions actives.
    Retourne un résumé {expired, expiring_soon, notified}.
    """
    decisions = list_all_decisions()
    expired_list = []
    expiring_soon = []

    for dec in decisions:
        action = dec.get("action")
        # reject n'a pas de SLA
        if action not in ("accept_risk", "exception", "upgrade_required"):
            continue

        sla = get_sla_status(dec)
        if not sla.get("has_sla"):
            continue

        name    = dec["package"]
        version = dec["version"]
        arch    = dec.get("arch", "amd64")

        if sla["expired"]:
            # Repasser en pending_review
            mpath = _manifest_path(name, version, arch)
            if mpath:
                try:
                    m = load_manifest(str(mpath))
                    m["status"] = "pending_review"
                    save_manifest(m)
                    audit_log(
                        "SLA_EXPIRED", "scheduler", "FAILURE",
                        package=name, version=version,
                        detail=(
                            f"Décision '{action}' expirée — repassé en pending_review. "
                            f"Expirait le {dec.get('expires_at', '?')}"
                        ),
                    )
                    logger.warning(f"[sla] {name} {version} — décision expirée → pending_review")
                    expired_list.append({**dec, "remaining_days": sla["remaining_days"]})
                except Exception as e:
                    logger.error(f"[sla] Erreur manifest {name} {version} : {e}")
            else:
                logger.warning(f"[sla] Manifest introuvable pour {name} {version} {arch}")
                expired_list.append({**dec, "remaining_days": sla["remaining_days"]})

        elif sla.get("warning"):
            # Expire dans ≤7 jours → alerte
            expiring_soon.append({
                **dec,
                "remaining_days": sla["remaining_days"],
                "expires_at":     sla["expires_at"],
            })

    # Envoyer webhook + email si des décisions expirent bientôt (ou sont expirées)
    to_notify = expiring_soon + expired_list
    notified = False
    if to_notify:
        notified = notify_sla_expiring(to_notify)
        notify_sla_expiring_email(to_notify)

    logger.info(
        f"[sla] Check terminé — {len(expired_list)} expirées, "
        f"{len(expiring_soon)} bientôt expirantes, webhook={'oui' if notified else 'non'}"
    )

    return {
        "expired":        len(expired_list),
        "expiring_soon":  len(expiring_soon),
        "notified":       notified,
        "expired_list":   expired_list,
        "expiring_list":  expiring_soon,
    }
