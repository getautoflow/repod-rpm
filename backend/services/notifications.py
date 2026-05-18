"""
Service de notifications webhook.

Envoie des alertes au webhook configuré (Slack / Teams / Mattermost) pour :
  - notify_pending_review  : paquet bloqué en révision RSSI
  - notify_sla_expiring    : décisions CVE expirantes (SLA J-7)
  - notify_decision        : confirmation d'une décision RSSI
"""

import logging

import requests as http_requests

from services.settings import get_settings

logger = logging.getLogger("notifications")


def _send(payload: dict) -> bool:
    """Envoie le payload JSON au webhook configuré. Retourne True si OK."""
    settings = get_settings()
    notif = settings.get("notifications", {})

    if not notif.get("webhook_enabled") or not notif.get("webhook_url", "").strip():
        return False

    url = notif["webhook_url"].strip()
    try:
        resp = http_requests.post(url, json=payload, timeout=5)
        resp.raise_for_status()
        logger.info(f"[notifications] Webhook envoyé → {resp.status_code}")
        return True
    except http_requests.exceptions.Timeout:
        logger.warning("[notifications] Webhook timeout")
    except http_requests.exceptions.HTTPError as e:
        logger.warning(f"[notifications] Webhook HTTP error : {e}")
    except Exception as e:
        logger.warning(f"[notifications] Webhook error : {e}")
    return False


def notify_pending_review(
    package: str,
    version: str,
    arch: str,
    distribution: str,
    cve_counts: dict,
    worst_severity: str | None,
    kev_count: int = 0,
) -> bool:
    """
    Alerte immédiate quand un paquet entre en file d'attente RSSI.
    """
    sev_icon = {
        "Critical": "🔴",
        "High":     "🟠",
        "Medium":   "🟡",
        "Low":      "🔵",
    }.get(worst_severity, "⚪")

    kev_warn = f"\n⚠️ *{kev_count} CVE(s) dans le catalogue KEV CISA* (exploitation active confirmée)" if kev_count else ""

    cve_line = " | ".join(
        f"{k.capitalize()}: {v}"
        for k, v in cve_counts.items()
        if v > 0
    )

    text = (
        f"{sev_icon} *repod — Paquet en attente de révision RSSI*\n"
        f"📦 `{package} {version}` ({arch}, {distribution})\n"
        f"🔎 CVE détectées : {cve_line or 'aucune'}"
        f"{kev_warn}\n"
        f"👉 Action requise : <votre-instance>/security#review-queue"
    )

    return _send({"text": text})


def notify_sla_expiring(expiring: list[dict]) -> bool:
    """
    Alerte quotidienne listant les décisions CVE qui expirent dans ≤7 jours.
    expiring : liste de dicts {package, version, action, expires_at, remaining_days, decided_by}
    """
    if not expiring:
        return False

    lines = ["⏰ *repod — Décisions CVE expirantes*"]
    for d in expiring:
        days = d.get("remaining_days", 0)
        if days < 0:
            suffix = "⛔ *expirée*"
        elif days == 0:
            suffix = "⚠️ *expire aujourd'hui*"
        else:
            suffix = f"expire dans *{days}j*"

        action_labels = {
            "accept_risk":      "Risque accepté",
            "exception":        "Exception",
            "upgrade_required": "Upgrade requis",
        }
        label = action_labels.get(d.get("action", ""), d.get("action", ""))

        lines.append(
            f"  • `{d['package']} {d.get('version', '')}` — {label} — {suffix}"
            f" (décidé par {d.get('decided_by', '?')})"
        )

    lines.append("👉 Consultez la file de révision pour renouveler ou modifier les décisions.")

    return _send({"text": "\n".join(lines)})


def notify_decision(
    package: str,
    version: str,
    action: str,
    decided_by: str,
    justification: str,
    expires_in_days: int | None = None,
) -> bool:
    """
    Notifie qu'une décision RSSI vient d'être prise.
    """
    action_icons = {
        "accept_risk":      "✅ Risque accepté",
        "exception":        "🔓 Exception accordée",
        "reject":           "🚫 Rejeté / Quarantaine",
        "upgrade_required": "🔼 Upgrade requis",
    }
    label = action_icons.get(action, action)

    expire_line = ""
    if expires_in_days:
        expire_line = f"\n📅 Expire dans {expires_in_days} jours"

    just_short = justification[:200] + ("…" if len(justification) > 200 else "")

    text = (
        f"{label} — `{package} {version}`\n"
        f"👤 Décidé par : {decided_by}\n"
        f"📝 Justification : {just_short}"
        f"{expire_line}"
    )

    return _send({"text": text})
