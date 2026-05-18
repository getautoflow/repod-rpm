"""
Routes de sécurité :
- GET  /security/clamav/status                        → version DB, date, statut
- POST /security/clamav/update                        → mise à jour manuelle (SSE)
- GET  /security/vulnerabilities                      → vue consolidée des CVE cross-paquets
- GET  /security/packages-posture                     → posture CVE par paquet (avec fallback validation_steps)
- GET  /security/packages/{name}/{version}/cve        → CVE détaillées d'un paquet
- POST /security/packages/{name}/{version}/quarantine → mise en quarantaine immédiate
"""
import os
import re
import shutil
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from pydantic import BaseModel
from auth.dependencies import get_current_user, get_admin_user, get_maintainer_user
from services.audit import log as audit_log
from services.manifest import list_manifests, load_manifest, save_manifest
from services.security_decisions import (
    save_decision, load_decision, list_all_decisions,
    get_sla_status, is_decision_expired, ACTION_TO_STATUS,
)
from services.notifications import notify_decision

router = APIRouter(prefix="/security", tags=["Security"])

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))
STAGING_QUARANTINE = Path(os.getenv("STAGING_QUARANTINE", "/repos/staging/quarantine"))
MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))

CLAMAV_DB_DIR = Path(os.getenv("CLAMAV_DB_DIR", "/var/lib/clamav"))


def _get_clamav_status() -> dict:
    """Retourne le statut actuel de ClamAV et sa base de signatures."""
    status = {
        "available": False,
        "version": None,
        "db_version": None,
        "db_date": None,
        "db_files": [],
        "daemon_running": False,
    }

    # Version de clamscan
    try:
        r = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            status["available"] = True
            # Ex: "ClamAV 1.4.3/27969/Sun Apr 12 06:24:30 2026"
            parts = r.stdout.strip().split("/")
            if len(parts) >= 3:
                status["version"] = parts[0].replace("ClamAV ", "").strip()
                status["db_version"] = parts[1].strip()
                status["db_date"] = parts[2].strip()
    except Exception:
        pass

    # Fichiers de la DB sur le volume
    if CLAMAV_DB_DIR.exists():
        db_files = []
        for f in sorted(CLAMAV_DB_DIR.glob("*.cv*")):
            stat = f.stat()
            db_files.append({
                "name": f.name,
                "size_bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            })
        status["db_files"] = db_files

    # Vérifier si freshclam daemon tourne
    try:
        r = subprocess.run(["pgrep", "-x", "freshclam"], capture_output=True, text=True, timeout=3)
        status["daemon_running"] = r.returncode == 0
    except Exception:
        pass

    # Lire le cooldown depuis freshclam.dat
    cooldown_until = None
    freshclam_dat = CLAMAV_DB_DIR / "freshclam.dat"
    if freshclam_dat.exists():
        try:
            content = freshclam_dat.read_text()
            # Le fichier contient une ligne avec le timestamp de fin de cooldown
            for line in content.splitlines():
                if "cool" in line.lower() or line.strip().isdigit():
                    ts = int(line.strip())
                    if ts > 0:
                        cooldown_until = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                        break
        except Exception:
            pass
    status["cooldown_until"] = cooldown_until

    return status


@router.get("/vulnerabilities")
def get_vulnerabilities(
    severity: str = Query(None, description="Filtrer par sévérité: critical, high, medium, low"),
    fix_state: str = Query(None, description="Filtrer par état du fix: fixed, not-fixed, unknown"),
    distribution: str = Query(None, description="Filtrer par distribution APT"),
    current_user: str = Depends(get_current_user),
):
    """
    Vue consolidée des CVE sur tous les paquets du dépôt.
    Agrège les résultats Grype depuis les manifests — une ligne par CVE,
    avec la liste des paquets affectés.
    """
    manifests = list_manifests()

    # Index CVE → paquets affectés
    cve_index: dict[str, dict] = {}
    packages_scanned: list[dict] = []
    _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

    for m in manifests:
        cve_results = m.get("cve_results", [])
        distrib = m.get("distribution", "almalinux8")

        if distribution and distrib != distribution:
            continue

        if not cve_results:
            continue

        pkg_ref = {
            "name": m["name"],
            "version": m["version"],
            "distribution": distrib,
        }

        counts: dict[str, int] = {s.lower(): 0 for s in _sev_order}
        for cve in cve_results:
            sev = cve.get("severity", "Unknown")
            counts[sev.lower()] = counts.get(sev.lower(), 0) + 1

            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            if cve_id not in cve_index:
                cve_index[cve_id] = {
                    "id": cve_id,
                    "severity": sev,
                    "cvss": cve.get("cvss"),
                    "description": cve.get("description", ""),
                    "fix_state": cve.get("fix_state", "unknown"),
                    "fix_versions": cve.get("fix_versions", []),
                    "urls": cve.get("urls", []),
                    "affected_packages": [],
                }

            # Ajouter ce paquet à la liste des affectés (éviter les doublons)
            pkg_entry = {
                **pkg_ref,
                "package_name": cve.get("package_name", m["name"]),
                "package_version": cve.get("package_version", m["version"]),
                "fix_state": cve.get("fix_state", "unknown"),
                "fix_versions": cve.get("fix_versions", []),
            }
            existing_ids = {
                (p["name"], p["package_version"], p["package_name"])
                for p in cve_index[cve_id]["affected_packages"]
            }
            key = (pkg_ref["name"], pkg_entry["package_version"], pkg_entry["package_name"])
            if key not in existing_ids:
                cve_index[cve_id]["affected_packages"].append(pkg_entry)

        packages_scanned.append({**pkg_ref, **counts})

    # Convertir en liste + filtres
    vulns = list(cve_index.values())

    if severity:
        vulns = [v for v in vulns if v["severity"].lower() == severity.lower()]
    if fix_state:
        vulns = [v for v in vulns if v["fix_state"].lower() == fix_state.lower()]

    # Trier par sévérité puis CVSS desc
    def _sort_key(v):
        sev_idx = _sev_order.index(v["severity"]) if v["severity"] in _sev_order else 99
        return (sev_idx, -(v["cvss"] or 0))

    vulns.sort(key=_sort_key)

    # Résumé global
    summary: dict[str, int] = {s.lower(): 0 for s in _sev_order}
    for v in cve_index.values():
        sev = v["severity"].lower()
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "summary": summary,
        "total": len(vulns),
        "packages_scanned": len(packages_scanned),
        "vulnerabilities": vulns,
        "packages": packages_scanned,
    }


def _parse_cve_message(msg: str) -> dict:
    """
    Parse un message CVE compact en comptages par sévérité.
    Ex: "Grype — 3 High | 18 Medium | 34 Low | 1 Negligible"
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
    if not msg:
        return counts
    lower = msg.lower()
    if "non disponible" in lower or "ignoré" in lower or "timeout" in lower:
        return counts
    for part in (msg + " ").replace("|", " ").split():
        pass  # handled below
    # Parse "N Severity" pairs wherever they appear
    import re as _re
    for m in _re.finditer(r"(\d+)\s+(critical|high|medium|low|negligible|unknown)", msg, _re.IGNORECASE):
        sev = m.group(2).lower()
        counts[sev] = int(m.group(1))
    return counts


@router.get("/packages-posture")
def get_packages_posture(
    distribution: str = Query(None, description="Filtrer par distribution APT"),
    current_user: str = Depends(get_current_user),
):
    """
    Vue posture CVE par paquet :
    - CVE counts par sévérité (depuis cve_results ou fallback validation_steps)
    - Statut hash, date d'import, pire sévérité
    - Actions disponibles selon la sévérité
    """
    _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

    manifests = list_manifests()
    packages = []

    for m in manifests:
        if distribution and m.get("distribution") != distribution:
            continue

        cve_results = m.get("cve_results", [])
        counts = {s.lower(): 0 for s in _sev_order}
        scanned = False
        scan_source = None

        if cve_results:
            # Données structurées depuis Grype
            scanned = True
            scan_source = "grype"
            for cve in cve_results:
                sev = cve.get("severity", "Unknown").lower()
                if sev in counts:
                    counts[sev] += 1
                else:
                    counts["unknown"] += 1
        else:
            # Fallback : parser le message dans validation_steps[cve]
            for step in m.get("validation_steps", []):
                if step.get("name") == "cve":
                    msg = step.get("message", "")
                    lower = msg.lower()
                    if "non disponible" not in lower and "ignoré" not in lower and "timeout" not in lower:
                        scanned = True
                        scan_source = "grype-legacy"
                        parsed = _parse_cve_message(msg)
                        counts.update(parsed)
                    break

        # Sévérité la plus grave présente
        worst = None
        for sev in _sev_order:
            if counts.get(sev.lower(), 0) > 0:
                worst = sev
                break

        # Actions recommandées selon la posture
        actions = ["view_cve"]
        if counts.get("critical", 0) > 0:
            actions.append("quarantine")
        if scanned and counts.get("critical", 0) == 0:
            actions.append("accept")

        integrity = m.get("integrity", {})

        # ── Décision RSSI enrichie ───────────────────────────────────────────
        decision = load_decision(m["name"], m.get("version", ""), m.get("arch", "amd64"))
        sla      = get_sla_status(decision) if decision else None

        # KEV & EPSS synthèse
        def _epss_float(c):
            v = c.get("epss_percent") or c.get("epss") or 0
            try: return float(v)
            except: return 0.0

        kev_count    = sum(1 for c in cve_results if c.get("in_kev") or c.get("kev"))
        high_epss    = [c for c in cve_results if _epss_float(c) >= 10.0]

        packages.append({
            "name": m["name"],
            "version": m.get("version", ""),
            "arch": m.get("arch", "amd64"),
            "distribution": m.get("distribution", ""),
            "imported_at": m.get("source", {}).get("imported_at"),
            "imported_by": m.get("source", {}).get("imported_by"),
            "scanned": scanned,
            "scan_source": scan_source,
            "cve_counts": counts,
            "worst_severity": worst,
            "total_cve": sum(counts.values()),
            "kev_count": kev_count,
            "high_epss_count": len(high_epss),
            "hash_verified": bool(integrity.get("sha256")),
            "status": m.get("status", "validated"),
            "actions": actions,
            # Décision RSSI résumée
            "decision_action":  decision.get("action")  if decision else None,
            "decision_expires": decision.get("expires_at") if decision else None,
            "sla_days":         sla.get("days_remaining") if sla else None,
            "sla_status":       sla.get("status") if sla else None,
        })

    # Tri : pire sévérité d'abord, puis par total CVE décroissant, puis par nom
    _rank = {s.lower(): i for i, s in enumerate(_sev_order)}
    packages.sort(key=lambda p: (
        _rank.get((p["worst_severity"] or "").lower(), 99),
        -p["total_cve"],
        p["name"],
    ))

    # Résumé global
    summary = {s.lower(): 0 for s in _sev_order}
    for p in packages:
        for sev, cnt in p["cve_counts"].items():
            summary[sev] = summary.get(sev, 0) + cnt

    return {
        "summary": summary,
        "total_packages": len(packages),
        "scanned_packages": sum(1 for p in packages if p["scanned"]),
        "unscanned_packages": sum(1 for p in packages if not p["scanned"]),
        "packages": packages,
    }


@router.get("/packages/{name}/{version}/cve")
def get_package_cve(
    name: str,
    version: str,
    arch: str = Query("amd64"),
    current_user: str = Depends(get_current_user),
):
    """
    Retourne la liste structurée des CVE d'un paquet spécifique,
    avec fallback sur validation_steps si cve_results est vide.
    """
    manifest = load_manifest(name, version, arch)
    if not manifest:
        # Chercher parmi tous les manifests (arch variable)
        for m in list_manifests():
            if m["name"] == name and m.get("version") == version:
                manifest = m
                break
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Manifest introuvable pour {name} {version}")

    cve_results = manifest.get("cve_results", [])
    _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    counts = {s.lower(): 0 for s in _sev_order}

    if cve_results:
        for cve in cve_results:
            sev = cve.get("severity", "Unknown").lower()
            counts[sev] = counts.get(sev, 0) + 1
    else:
        # Extraire le résumé depuis validation_steps pour l'affichage
        for step in manifest.get("validation_steps", []):
            if step.get("name") == "cve":
                counts = _parse_cve_message(step.get("message", ""))
                break

    # Trier les CVE par sévérité
    def _sev_sort(c):
        s = c.get("severity", "Unknown")
        return _sev_order.index(s) if s in _sev_order else 99

    return {
        "package": name,
        "version": version,
        "arch": arch,
        "distribution": manifest.get("distribution", ""),
        "cve_counts": counts,
        "total": len(cve_results),
        "cve_results": sorted(cve_results, key=_sev_sort),
        "has_structured_data": len(cve_results) > 0,
    }


@router.get("/review-queue")
def get_review_queue(
    current_user: str = Depends(get_current_user),
):
    """
    File de révision RSSI : paquets en attente de décision.
    Inclut les paquets bloqués (CRITICAL) et en révision (HIGH avec policy=review).
    Pour chaque paquet, affiche les CVE enrichies (EPSS, KEV).
    """
    _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    manifests = list_manifests()
    queue = []

    for m in manifests:
        status = m.get("status", "validated")
        if status not in ("pending_review", "blocked"):
            continue

        cve_results = m.get("cve_results", [])
        counts = {s.lower(): 0 for s in _sev_order}
        for cve in cve_results:
            sev = cve.get("severity", "Unknown").lower()
            counts[sev] = counts.get(sev, 0) + 1

        worst = next((s for s in _sev_order if counts.get(s.lower(), 0) > 0), None)

        # CVE bloquantes / en révision
        kev_cves  = [c for c in cve_results if c.get("in_kev")]
        def _epss_float(c):
            v = c.get("epss_percent", "0%")
            try:
                return float(str(v).rstrip("%"))
            except (ValueError, TypeError):
                return 0.0
        high_epss = [c for c in cve_results if _epss_float(c) >= 10.0]

        # Décision existante éventuelle
        decision = load_decision(m["name"], m.get("version", ""), m.get("arch", "amd64"))
        sla      = get_sla_status(decision) if decision else {"has_sla": False}

        queue.append({
            "name":         m["name"],
            "version":      m.get("version", ""),
            "arch":         m.get("arch", "amd64"),
            "distribution": m.get("distribution", ""),
            "imported_at":  m.get("source", {}).get("imported_at"),
            "imported_by":  m.get("source", {}).get("imported_by"),
            "status":       status,
            "worst_severity": worst,
            "cve_counts":   counts,
            "total_cve":    sum(counts.values()),
            "kev_count":    len(kev_cves),
            "high_epss_count": len(high_epss),
            "cve_results":  cve_results,
            "decision":     decision,
            "sla":          sla,
        })

    # Tri : bloqués d'abord, puis par worst severity, puis date
    _rank = {s.lower(): i for i, s in enumerate(_sev_order)}
    queue.sort(key=lambda p: (
        0 if p["status"] == "blocked" else 1,
        _rank.get((p["worst_severity"] or "").lower(), 99),
        p["imported_at"] or "",
    ))

    return {
        "total":           len(queue),
        "blocked_count":   sum(1 for p in queue if p["status"] == "blocked"),
        "review_count":    sum(1 for p in queue if p["status"] == "pending_review"),
        "packages":        queue,
    }


@router.post("/check-sla")
def trigger_sla_check(current_user: str = Depends(get_admin_user)):
    """Déclenche manuellement la vérification des SLA CVE."""
    from services.sla_alerts import run_sla_check
    result = run_sla_check()
    return result


@router.get("/report")
def get_security_report(current_user: str = Depends(get_current_user)):
    """
    Rapport d'audit complet pour export PDF / ISO 27001 / NIS2.
    Retourne toutes les métriques, décisions, posture CVE consolidée.
    """
    from services.settings import get_settings

    now = datetime.now(timezone.utc)
    settings = get_settings()
    cve_policy = settings.get("cve_policy", {})

    # ── Tous les manifests ────────────────────────────────────────────────────
    manifests = list_manifests()

    # Posture CVE agrégée
    _sevs = ["critical", "high", "medium", "low", "negligible"]
    cve_totals = {s: 0 for s in _sevs}
    packages_with_cve = []
    status_counts: dict[str, int] = {}

    for m in manifests:
        st = m.get("status", "validated")
        status_counts[st] = status_counts.get(st, 0) + 1

        cves = m.get("cve_results", [])
        if cves:
            pkg_counts = {s: 0 for s in _sevs}
            kev = 0
            for cve in cves:
                sev = cve.get("severity", "Unknown").lower()
                if sev in pkg_counts:
                    pkg_counts[sev] += 1
                    cve_totals[sev] += 1
                if cve.get("in_kev"):
                    kev += 1
            worst = next((s for s in _sevs if pkg_counts[s] > 0), None)
            packages_with_cve.append({
                "name":         m["name"],
                "version":      m.get("version", ""),
                "distribution": m.get("distribution", ""),
                "status":       st,
                "cve_counts":   pkg_counts,
                "kev_count":    kev,
                "worst":        worst,
                "total_cve":    sum(pkg_counts.values()),
            })

    packages_with_cve.sort(key=lambda p: (
        _sevs.index(p["worst"]) if p["worst"] in _sevs else 99,
    ))

    # ── Toutes les décisions ──────────────────────────────────────────────────
    all_decisions = list_all_decisions()
    decisions_enriched = []
    for dec in all_decisions:
        sla = get_sla_status(dec)
        decisions_enriched.append({**dec, "sla": sla})

    decisions_enriched.sort(key=lambda d: d.get("decided_at", ""), reverse=True)

    # ── Queue de révision actuelle ────────────────────────────────────────────
    pending = [m for m in manifests if m.get("status") in ("pending_review", "blocked")]

    # ── Résumé ───────────────────────────────────────────────────────────────
    summary = {
        "total_packages":    len(manifests),
        "packages_scanned":  len(packages_with_cve),
        "status_counts":     status_counts,
        "cve_totals":        cve_totals,
        "total_cve":         sum(cve_totals.values()),
        "decisions_count":   len(all_decisions),
        "pending_count":     len(pending),
        "expiring_soon":     sum(
            1 for d in decisions_enriched
            if d["sla"].get("warning") or d["sla"].get("expired")
        ),
    }

    return {
        "generated_at":     now.isoformat(),
        "generated_by":     current_user,
        "period":           "Toutes les décisions enregistrées",
        "cve_policy":       cve_policy,
        "summary":          summary,
        "packages_with_cve": packages_with_cve,
        "decisions":        decisions_enriched,
        "pending_review":   [
            {
                "name":        m["name"],
                "version":     m.get("version", ""),
                "arch":        m.get("arch", "amd64"),
                "distribution": m.get("distribution", ""),
                "status":      m.get("status"),
                "imported_at": m.get("source", {}).get("imported_at"),
                "cve_counts":  {
                    s: sum(1 for c in m.get("cve_results", [])
                           if c.get("severity", "").lower() == s)
                    for s in _sevs
                },
            }
            for m in pending
        ],
    }


class DecisionRequest(BaseModel):
    action:          str           # accept_risk | exception | reject | upgrade_required
    justification:   str           # obligatoire
    expires_in_days: int | None = None   # pour accept_risk et exception
    target_version:  str | None = None   # pour upgrade_required
    cve_ids:         list[str] = []      # CVE IDs couverts (vide = tous)
    arch:            str = "amd64"


@router.get("/packages/{name}/{version}/decision")
def get_package_decision(
    name: str,
    version: str,
    arch: str = "amd64",
    current_user: str = Depends(get_current_user),
):
    """Retourne le manifest + la décision RSSI + le statut SLA pour un paquet."""
    manifest = load_manifest(name, version, arch)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"{name} {version} introuvable")
    decision = load_decision(name, version, arch)
    sla = get_sla_status(decision) if decision else None
    return {
        "manifest": manifest,
        "decision": decision,
        "sla": sla,
        "status": manifest.get("status", "unknown"),
    }


@router.post("/packages/{name}/{version}/decide")
def decide_package(
    name: str,
    version: str,
    body: DecisionRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """
    Enregistre la décision RSSI pour un paquet en attente.

    Actions :
      accept_risk      → accepte les CVE existantes, paquet promu dans APT
      exception        → exception temporaire (même effet + date d'expiration)
      reject           → quarantaine définitive
      upgrade_required → paquet bloqué jusqu'à la version cible
    """
    from datetime import datetime, timezone

    VALID_ACTIONS = {"accept_risk", "exception", "reject", "upgrade_required"}
    if body.action not in VALID_ACTIONS:
        raise HTTPException(status_code=400,
                            detail=f"Action invalide. Valeurs : {sorted(VALID_ACTIONS)}")

    if not body.justification.strip():
        raise HTTPException(status_code=400, detail="La justification est obligatoire")

    # Charger le manifest
    manifest = load_manifest(name, version, body.arch)
    if not manifest:
        for m in list_manifests():
            if m["name"] == name and m.get("version") == version:
                manifest = m
                body.arch = m.get("arch", body.arch)
                break
    if not manifest:
        raise HTTPException(status_code=404,
                            detail=f"Manifest introuvable pour {name} {version}")

    current_status = manifest.get("status", "validated")
    if current_status not in ("pending_review", "blocked", "accepted_risk",
                               "exception", "upgrade_required"):
        raise HTTPException(status_code=409,
                            detail=f"Ce paquet n'est pas en révision (statut: {current_status})")

    # Persister la décision
    decision = save_decision(
        name=name, version=version, arch=body.arch,
        action=body.action,
        justification=body.justification,
        decided_by=current_user,
        expires_in_days=body.expires_in_days,
        target_version=body.target_version,
        cve_ids=body.cve_ids or [c["id"] for c in manifest.get("cve_results", []) if c.get("id")],
    )

    # Mettre à jour le manifest
    new_status = ACTION_TO_STATUS[body.action]
    manifest["status"]        = new_status
    manifest["decision"]      = decision
    save_manifest(manifest)

    # Actions système selon la décision
    ADD_DEB_SCRIPT = os.getenv("ADD_DEB_SCRIPT", "/scripts/add-deb.sh")

    if body.action in ("accept_risk", "exception"):
        # Promouvoir dans APT via le script add-deb.sh (qui appelle reprepro dans depot-apt)
        distrib  = manifest.get("distribution", "almalinux8")
        filename = manifest.get("filename", f"{name}-{version}.{body.arch}.rpm")
        pool_deb = POOL_DIR / filename
        if pool_deb.exists():
            subprocess.run(
                ["sh", ADD_DEB_SCRIPT, distrib, filename],
                capture_output=True, text=True,
            )

    elif body.action == "reject":
        # Déplacer vers quarantaine
        STAGING_QUARANTINE.mkdir(parents=True, exist_ok=True)
        filename = manifest.get("filename", f"{name}-{version}.{body.arch}.rpm")
        pool_deb = POOL_DIR / filename
        if pool_deb.exists():
            shutil.move(str(pool_deb), str(STAGING_QUARANTINE / pool_deb.name))
        # Retirer des dépôts RPM (toutes distributions)
        from services.distributions import REPO_BASE, _run_createrepo
        for arch_dir in REPO_BASE.glob("*/*"):
            for rpm_file in arch_dir.glob(f"{name}-*.rpm"):
                rpm_file.unlink(missing_ok=True)
            if arch_dir.is_dir() and (arch_dir / "repodata" / "repomd.xml").exists():
                _run_createrepo(arch_dir)

    audit_log(
        "SECURITY_DECISION", current_user, "SUCCESS",
        package=name, version=version,
        detail=(
            f"Action : {body.action} | "
            f"Justification : {body.justification[:100]} | "
            f"Expire : {decision.get('expires_at') or 'jamais'}"
        ),
    )

    # ── Notification webhook ──────────────────────────────────────────────────
    try:
        notify_decision(
            package=name,
            version=version,
            action=body.action,
            decided_by=current_user,
            justification=body.justification,
            expires_in_days=body.expires_in_days,
        )
    except Exception:
        pass  # notification non bloquante

    return {
        "status":   "ok",
        "package":  name,
        "version":  version,
        "action":   body.action,
        "new_status": new_status,
        "decision": decision,
        "message": {
            "accept_risk":      f"{name} accepté avec risque — publié dans APT",
            "exception":        f"{name} exception accordée — publié dans APT",
            "reject":           f"{name} rejeté — déplacé en quarantaine",
            "upgrade_required": f"{name} en attente de mise à jour vers {body.target_version}",
        }.get(body.action, "Décision enregistrée"),
    }


@router.post("/packages/{name}/{version}/rescan")
def rescan_package(
    name: str,
    version: str,
    arch: str = Query("amd64"),
    current_user: str = Depends(get_maintainer_user),
):
    """
    Force un nouveau scan CVE Grype pour un paquet déjà importé.
    Met à jour cve_results dans le manifest.
    """
    manifest = load_manifest(name, version, arch)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"{name} {version} introuvable")

    filename = manifest.get("filename")
    deb_path = POOL_DIR / filename if filename else None

    if not deb_path or not deb_path.exists():
        # Chercher dans le pool
        candidates = list(POOL_DIR.glob(f"{name}-*.rpm"))
        deb_path = candidates[0] if candidates else None

    if not deb_path or not deb_path.exists():
        raise HTTPException(status_code=404, detail="Fichier .rpm introuvable dans le pool")

    import json as _json
    import subprocess as _sp

    grype_db_dir = os.getenv("GRYPE_DB_CACHE_DIR", "/repos/grype-db")
    distribution = manifest.get("distribution", "almalinux8")
    _DISTRO_MAP = {"almalinux8":"almalinux:8","rocky8":"rockylinux:8","centos-stream9":"centos:9","oraclelinux8":"oraclelinux:8","fedora":"fedora:latest","opensuse-leap-15.5":"opensuse/leap:15.5","opensuse-leap-15.6":"opensuse/leap:15.6","opensuse-leap":"opensuse/leap:latest","opensuse-tumbleweed":"opensuse/tumbleweed:latest"}
    grype_distro = _DISTRO_MAP.get(distribution, distribution)

    cmd = ["grype", str(deb_path), "-o", "json", "--add-cpes-if-none"]
    if grype_distro:
        cmd += ["--distro", grype_distro]

    try:
        r = _sp.run(cmd, capture_output=True, text=True, timeout=300,
                    env={**os.environ, "GRYPE_DB_CACHE_DIR": grype_db_dir})
    except _sp.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Grype timeout (> 5 min)")

    if r.returncode not in (0, 1):
        raise HTTPException(status_code=500, detail=f"Grype erreur : {r.stderr[:300]}")

    try:
        data = _json.loads(r.stdout)
    except Exception:
        raise HTTPException(status_code=500, detail="Grype réponse illisible")

    raw_matches = data.get("matches", [])
    from services.cve_enrichment import enrich_cve_list

    cve_list = []
    for m in raw_matches:
        vuln = m.get("vulnerability", {})
        cve_list.append({
            "id": vuln.get("id", ""),
            "severity": m.get("vulnerability", {}).get("severity", "Unknown"),
            "description": vuln.get("description", ""),
            "fix_state": m.get("vulnerability", {}).get("fix", {}).get("state", "unknown"),
            "fix_versions": m.get("vulnerability", {}).get("fix", {}).get("versions", []),
            "cvss": next((c.get("metrics", {}).get("baseScore") for c in vuln.get("cvss", []) if c.get("version", "").startswith("3")), None),
            "package_name": m.get("artifact", {}).get("name", ""),
            "package_version": m.get("artifact", {}).get("version", ""),
            "urls": vuln.get("urls", []),
        })

    enriched = enrich_cve_list(cve_list)
    manifest["cve_results"] = enriched
    manifest["last_scan"] = datetime.now(timezone.utc).isoformat()
    save_manifest(manifest)

    counts = {}
    for c in enriched:
        sev = c.get("severity", "Unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1

    audit_log("RESCAN", current_user, "SUCCESS", package=name, version=version,
              detail=f"Grype rescan — {len(enriched)} CVE trouvée(s)")

    return {
        "status": "ok",
        "package": name,
        "version": version,
        "cve_count": len(enriched),
        "cve_counts": counts,
    }


@router.post("/packages/{name}/{version}/quarantine")
def quarantine_package(
    name: str,
    version: str,
    arch: str = Query("amd64"),
    current_user: str = Depends(get_maintainer_user),
):
    """
    Met un paquet en quarantaine immédiatement :
    1. Déplace le .rpm du pool vers staging/quarantine/
    2. Retire des dépôts RPM (toutes distributions)
    3. Met à jour le manifest (status = quarantined)
    4. Audit log
    """
    STAGING_QUARANTINE.mkdir(parents=True, exist_ok=True)

    # Trouver le .deb dans le pool
    pattern = f"{name}-{version}.{arch}.rpm"
    deb_path = POOL_DIR / pattern
    if not deb_path.exists():
        # Chercher avec version normalisée (: → _)
        version_safe = version.replace(":", "_").replace("/", "_")
        pattern = f"{name}-{version_safe}.{arch}.rpm"
        deb_path = POOL_DIR / pattern
    if not deb_path.exists():
        # Recherche large
        candidates = list(POOL_DIR.glob(f"{name}-*.rpm"))
        deb_path = next(
            (c for c in candidates if f"_{version}_" in c.name or f"_{version.replace(':', '_')}_" in c.name),
            None
        )

    # Retirer de reprepro dans toutes les distributions
    from services.distributions import REPO_BASE, _run_createrepo
    for arch_dir in REPO_BASE.glob("*/*"):
        for rpm_file in arch_dir.glob(f"{name}-*.rpm"):
            rpm_file.unlink(missing_ok=True)
        if arch_dir.is_dir() and (arch_dir / "repodata" / "repomd.xml").exists():
            _run_createrepo(arch_dir)

    # Déplacer le .deb si trouvé
    moved_deb = None
    if deb_path and deb_path.exists():
        dest = STAGING_QUARANTINE / deb_path.name
        shutil.move(str(deb_path), str(dest))
        moved_deb = deb_path.name

    # Mettre à jour le manifest
    manifest = load_manifest(name, version, arch)
    if not manifest:
        for m in list_manifests():
            if m["name"] == name and m.get("version") == version:
                manifest = m
                arch = m.get("arch", arch)
                break

    if manifest:
        manifest["status"] = "quarantined"
        manifest["quarantined_at"] = datetime.now(timezone.utc).isoformat()
        manifest["quarantined_by"] = current_user
        save_manifest(manifest)

    audit_log(
        "QUARANTINE", current_user, "SUCCESS",
        package=name, version=version,
        detail=f"Mis en quarantaine manuellement — .rpm: {moved_deb or 'non trouvé dans pool'}",
    )

    return {
        "status": "quarantined",
        "package": name,
        "version": version,
        "deb_moved": moved_deb,
        "message": f"{name} {version} déplacé en quarantaine",
    }


@router.get("/clamav/status")
def clamav_status(current_user: str = Depends(get_current_user)):
    """Retourne le statut de ClamAV et de sa base de signatures."""
    return _get_clamav_status()


@router.post("/clamav/update")
def clamav_update(current_user: str = Depends(get_admin_user)):
    """
    Lance une mise à jour manuelle de la base ClamAV.
    Stream SSE en temps réel.
    """
    def event_stream():
        def emit(msg: str, level: str = "info") -> str:
            return f"data: {level}|{msg}\n\n"

        yield emit("Lancement de la mise à jour ClamAV...")
        yield emit(f"Répertoire DB : {CLAMAV_DB_DIR}")

        try:
            process = subprocess.Popen(
                ["freshclam",
                 "--datadir", str(CLAMAV_DB_DIR),
                 "--log=/dev/null",   # évite "Permission denied" sur /var/log/clamav/freshclam.log
                 "--stdout"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            for line in iter(process.stdout.readline, ""):
                line = line.strip()
                if not line:
                    continue
                line_lower = line.lower()
                # Coloriser selon le contenu
                if "up to date" in line_lower or "already up" in line_lower:
                    yield emit(line, "success")
                elif "updated" in line_lower or "downloading" in line_lower:
                    yield emit(line, "info")
                elif "rate limit" in line_lower or "cool-down" in line_lower or "429" in line or "403" in line:
                    yield emit(line, "warning")
                elif "error" in line_lower or "failed" in line_lower:
                    yield emit(line, "error")
                elif "warning" in line_lower:
                    yield emit(line, "warning")
                else:
                    yield emit(line, "info")

            process.wait()

            if process.returncode == 0:
                status = _get_clamav_status()
                yield emit(
                    f"Mise à jour terminée — DB version {status.get('db_version', '?')} "
                    f"({status.get('db_date', '?')})",
                    "success"
                )
                audit_log("CLAMAV_UPDATE", current_user, "SUCCESS",
                          detail=f"DB mise à jour : version {status.get('db_version')}")
            else:
                yield emit("Mise à jour terminée avec des avertissements", "warning")
                audit_log("CLAMAV_UPDATE", current_user, "WARNING",
                          detail="freshclam terminé avec code non-zéro")

        except FileNotFoundError:
            yield emit("freshclam introuvable — ClamAV n'est pas installé", "error")
        except Exception as e:
            yield emit(f"Erreur inattendue : {e}", "error")

        yield "data: done|DONE\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
