"""
Route dashboard :
- GET /dashboard/stats → toutes les métriques en une requête
"""
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi import APIRouter, Depends

from auth.dependencies import get_current_user
from services.indexer import list_packages_from_index
from services.manifest import list_manifests
from services.audit import get_recent_logs
from services.security_decisions import list_all_decisions, get_sla_status
from routers.security_router import _get_clamav_status

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))


@router.get("/stats")
def get_dashboard_stats(current_user: str = Depends(get_current_user)):
    packages = list_packages_from_index()

    # ── Stats paquets ──────────────────────────────────────────────────────────
    total_packages = len(packages)
    deps_missing = [p for p in packages if p.get("deps_missing")]
    total_size = sum(p.get("size_bytes", 0) for p in packages)

    # ── Activité audit (7 derniers jours) ─────────────────────────────────────
    logs = get_recent_logs(limit=500)
    today = datetime.now(timezone.utc).date()

    # Imports d'aujourd'hui
    imports_today = sum(
        1 for e in logs
        if e.get("action") in ("UPLOAD", "IMPORT")
        and e.get("result") == "SUCCESS"
        and e.get("timestamp", "")[:10] == str(today)
    )

    # Activité par jour sur 7 jours
    activity = {}
    for i in range(6, -1, -1):
        day = (today - timedelta(days=i)).isoformat()
        activity[day] = {"imports": 0, "failures": 0}

    for entry in logs:
        ts = entry.get("timestamp", "")[:10]
        if ts in activity:
            action = entry.get("action", "")
            result = entry.get("result", "")
            if action in ("UPLOAD", "IMPORT") and result == "SUCCESS":
                activity[ts]["imports"] += 1
            elif result == "FAILURE":
                activity[ts]["failures"] += 1

    activity_list = [
        {"date": day, **vals}
        for day, vals in activity.items()
    ]

    # ── Imports récents ────────────────────────────────────────────────────────
    recent_imports = [
        e for e in logs
        if e.get("action") in ("UPLOAD", "IMPORT") and e.get("result") == "SUCCESS"
    ][:8]

    # ── Alertes ───────────────────────────────────────────────────────────────
    alerts = []
    for p in deps_missing:
        alerts.append({
            "type": "deps_missing",
            "package": p["name"],
            "message": f"{len(p['deps_missing'])} dépendance(s) manquante(s)",
            "deps": p["deps_missing"],
        })

    # Alertes sécurité (rejets ClamAV ou provenance)
    security_failures = [
        e for e in logs
        if e.get("result") == "FAILURE"
        and e.get("action") in ("UPLOAD", "IMPORT", "VALIDATE")
    ][:3]
    for e in security_failures:
        alerts.append({
            "type": "security",
            "package": e.get("package", "inconnu"),
            "message": e.get("detail", "Validation échouée"),
            "timestamp": e.get("timestamp"),
        })

    # ── Posture CVE (agrégat depuis l'index) ──────────────────────────────────
    _sevs = ["critical", "high", "medium", "low", "negligible"]
    cve_scanned = [p for p in packages if p.get("cve_summary")]
    cve_totals = {s: 0 for s in _sevs}
    for p in cve_scanned:
        s = p["cve_summary"]
        for sev in _sevs:
            cve_totals[sev] += s.get(sev, 0)

    security_posture = {
        "scanned": len(cve_scanned),
        "total": total_packages,
        **cve_totals,
    }

    # ── Métriques de révision RSSI (depuis manifests = source de vérité) ──────
    status_counts: dict[str, int] = {}
    for m in list_manifests():
        st = m.get("status", "validated")
        status_counts[st] = status_counts.get(st, 0) + 1

    # Décisions actives et expirantes
    decisions = list_all_decisions()
    expiring_soon = []
    for dec in decisions:
        if dec.get("action") in ("accept_risk", "exception", "upgrade_required"):
            sla = get_sla_status(dec)
            if sla.get("warning") or sla.get("expired"):
                expiring_soon.append({
                    "package":        dec["package"],
                    "version":        dec["version"],
                    "action":         dec["action"],
                    "expires_at":     sla.get("expires_at"),
                    "remaining_days": sla.get("remaining_days"),
                    "expired":        sla.get("expired", False),
                    "decided_by":     dec.get("decided_by"),
                })

    security_review = {
        "pending_review":    status_counts.get("pending_review", 0),
        "blocked":           status_counts.get("blocked", 0),
        "quarantined":       status_counts.get("quarantined", 0),
        "accepted_risk":     status_counts.get("accepted_risk", 0),
        "exception":         status_counts.get("exception", 0),
        "upgrade_required":  status_counts.get("upgrade_required", 0),
        "expiring_soon":     sorted(expiring_soon, key=lambda d: d.get("remaining_days", 9999)),
        "total_decisions":   len(decisions),
    }

    # ── Alertes CVE expirantes → injecter dans les alertes dashboard ──────────
    for item in expiring_soon:
        days = item["remaining_days"]
        if item["expired"]:
            msg = f"Décision CVE expirée — repassé en révision"
            atype = "sla_expired"
        else:
            msg = f"Décision CVE expire dans {days}j"
            atype = "sla_warning"
        alerts.append({
            "type":    atype,
            "package": item["package"],
            "message": msg,
            "action":  item["action"],
            "expires_at": item["expires_at"],
        })

    # ── ClamAV statut (léger) ─────────────────────────────────────────────────
    try:
        clamav = _get_clamav_status()
        clamav_summary = {
            "available": clamav["available"],
            "db_version": clamav.get("db_version"),
            "db_date": clamav.get("db_date"),
            "daemon_running": clamav.get("daemon_running"),
        }
    except Exception:
        clamav_summary = {"available": False}

    return {
        "packages": {
            "total": total_packages,
            "total_size_bytes": total_size,
            "deps_missing_count": len(deps_missing),
            "imports_today": imports_today,
        },
        "activity": activity_list,
        "recent_imports": recent_imports,
        "alerts": alerts[:10],
        "clamav": clamav_summary,
        "security_posture": security_posture,
        "security_review": security_review,
    }


@router.get("/history")
def get_dashboard_history(days: int = 30, current_user: str = Depends(get_current_user)):
    """
    Retourne les données historiques sur N jours pour les graphiques :
    - Imports / jour
    - CVE détectées / jour
    - Décisions RSSI / jour
    - Failures / jour
    """
    from datetime import date
    logs = get_recent_logs(limit=2000)
    today = datetime.now(timezone.utc).date()

    # Initialiser les buckets
    buckets = {}
    for i in range(days - 1, -1, -1):
        day = (today - timedelta(days=i)).isoformat()
        buckets[day] = {"date": day, "imports": 0, "failures": 0, "decisions": 0, "cve_scans": 0}

    for entry in logs:
        ts = entry.get("timestamp", "")[:10]
        if ts not in buckets:
            continue
        action = entry.get("action", "").upper()
        result = entry.get("result", "").upper()

        if action in ("UPLOAD", "IMPORT") and result == "SUCCESS":
            buckets[ts]["imports"] += 1
        if result == "FAILURE":
            buckets[ts]["failures"] += 1
        if action == "DECISION":
            buckets[ts]["decisions"] += 1
        if action in ("UPLOAD", "IMPORT") and result == "SUCCESS":
            buckets[ts]["cve_scans"] += 1

    return {"history": list(buckets.values()), "days": days}
