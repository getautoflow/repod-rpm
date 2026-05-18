"""
Synchronisation automatique des sources de sécurité RPM.

Planifié via APScheduler (main.py) → cron quotidien configurable.
Déclenché manuellement via POST /import/sync-security.
"""
import logging
from datetime import datetime, timezone

import requests as http_requests

from services.package_index import DEFAULT_SOURCES, sync_source
from services.audit import log as audit_log
from services.settings import get_settings

logger = logging.getLogger("security_sync")

ALL_SECURITY_SOURCES = [s for s in DEFAULT_SOURCES if s.get("security", False)]


def _get_active_security_sources() -> list[dict]:
    settings = get_settings()
    enabled = settings.get("sources", {})
    return [s for s in ALL_SECURITY_SOURCES if enabled.get(s["id"], True)]


def _send_webhook(summary: dict) -> None:
    settings = get_settings()
    notif = settings.get("notifications", {})

    if not notif.get("webhook_enabled") or not notif.get("webhook_url"):
        return

    total_packages = sum(
        r.get("pkg_count", 0) for r in summary["sources"] if r.get("status") == "ok"
    )
    min_packages = notif.get("webhook_min_packages", 1)
    if total_packages < min_packages:
        return

    icon = "✅" if summary["total_error"] == 0 else "⚠️"
    lines = [f"{icon} *Sync sécurité RPM* — {summary['total_ok']} source(s) OK"]
    for r in summary["sources"]:
        if r["status"] == "ok":
            lines.append(f"  • {r['label']} : {r.get('pkg_count', 0)} paquets indexés")
        else:
            lines.append(f"  • ❌ {r['label']} : {r.get('error', 'erreur')}")

    payload = {"text": "\n".join(lines)}
    try:
        resp = http_requests.post(notif["webhook_url"], json=payload, timeout=5)
        resp.raise_for_status()
        logger.info("[security_sync] Webhook envoyé avec succès.")
    except Exception as e:
        logger.warning(f"[security_sync] Échec webhook : {e}")


def run_security_sync() -> dict:
    """
    Synchronise toutes les sources de sécurité RPM activées.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    sources = _get_active_security_sources()

    results = []
    total_ok = 0
    total_error = 0

    for source in sources:
        logger.info(f"[security_sync] Synchronisation de {source['label']}...")
        try:
            result = sync_source(source)
            if result["status"] == "ok":
                total_ok += 1
                logger.info(f"[security_sync] {source['label']} — {result['pkg_count']} paquets")
            else:
                total_error += 1
                logger.error(f"[security_sync] {source['label']} — erreur : {result.get('error')}")
            results.append({
                "source_id": source["id"],
                "label":     source["label"],
                "status":    result["status"],
                "pkg_count": result.get("pkg_count", 0),
                "error":     result.get("error"),
            })
        except Exception as exc:
            total_error += 1
            logger.error(f"[security_sync] {source['label']} — exception : {exc}")
            results.append({
                "source_id": source["id"],
                "label":     source["label"],
                "status":    "error",
                "pkg_count": 0,
                "error":     str(exc),
            })

    finished_at = datetime.now(timezone.utc).isoformat()
    summary = {
        "started_at":  started_at,
        "finished_at": finished_at,
        "sources":     results,
        "total_ok":    total_ok,
        "total_error": total_error,
        "skipped":     len(ALL_SECURITY_SOURCES) - len(sources),
    }

    audit_log(
        "SYNC_SECURITY", "scheduler",
        "SUCCESS" if total_error == 0 else "PARTIAL",
        detail=f"{total_ok} sources OK, {total_error} erreurs",
    )

    _send_webhook(summary)
    return summary
