"""
GET /health — Health check pour load-balancers et supervision.
GET /health/live  — Liveness probe
GET /health/ready — Readiness probe

Vérifie :
  - Volumes montés (manifests, pool, audit)
  - Espace disque disponible
  - ClamAV daemon
  - Scheduler (jobs planifiés)
  - Stats paquets

Ne nécessite pas d'authentification.
"""

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter

router = APIRouter(tags=["Health"])

MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))
POOL_DIR     = Path(os.getenv("POOL_DIR",     "/repos/pool"))
AUDIT_DIR    = Path(os.getenv("AUDIT_DIR",    "/repos/audit"))


def _check_dir(p: Path) -> dict:
    ok = p.exists() and p.is_dir()
    try:
        usage    = shutil.disk_usage(str(p)) if ok else None
        free_gb  = round(usage.free  / 1_073_741_824, 2) if usage else None
        total_gb = round(usage.total / 1_073_741_824, 2) if usage else None
        used_pct = round((usage.used / usage.total) * 100, 1) if usage else None
    except Exception:
        free_gb = total_gb = used_pct = None
    return {"ok": ok, "free_gb": free_gb, "total_gb": total_gb, "used_pct": used_pct}


def _check_clamav() -> dict:
    import subprocess
    try:
        r = subprocess.run(["clamscan", "--version"], capture_output=True, timeout=3)
        if r.returncode == 0:
            ver = r.stdout.decode().strip()
            return {"ok": True, "version": ver.split()[1] if len(ver.split()) > 1 else ver}
        return {"ok": False, "version": None}
    except Exception:
        return {"ok": False, "version": None}


def _check_scheduler() -> dict:
    from services import scheduler_state
    sched = scheduler_state.scheduler
    if sched is None:
        return {"ok": False, "jobs": []}
    jobs = []
    for job in sched.get_jobs():
        jobs.append({
            "id":       job.id,
            "name":     job.name,
            "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            "paused":   job.next_run_time is None,
        })
    return {"ok": True, "jobs": jobs}


def _check_packages() -> dict:
    try:
        manifests = list(MANIFEST_DIR.glob("*.manifest.json"))
        pool_files = list(POOL_DIR.glob("*.rpm"))
        pool_size_bytes = sum(f.stat().st_size for f in pool_files)
        return {
            "ok": True,
            "total_manifests": len(manifests),
            "pool_files": len(pool_files),
            "pool_size_mb": round(pool_size_bytes / 1_048_576, 1),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/health")
def health_check():
    manifests  = _check_dir(MANIFEST_DIR)
    pool       = _check_dir(POOL_DIR)
    audit      = _check_dir(AUDIT_DIR)
    clamav     = _check_clamav()
    scheduler  = _check_scheduler()
    packages   = _check_packages()

    all_ok = manifests["ok"] and pool["ok"] and audit["ok"]
    status = "healthy" if all_ok else "degraded"

    return {
        "status":    status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version":   os.getenv("APP_VERSION", "dev"),
        "checks": {
            "manifests": manifests,
            "pool":      pool,
            "audit":     audit,
            "clamav":    clamav,
            "scheduler": scheduler,
            "packages":  packages,
        },
    }


@router.get("/health/live")
def liveness():
    """Liveness probe minimaliste — répond 200 si le process est vivant."""
    return {"alive": True}


@router.get("/health/ready")
def readiness():
    """Readiness probe — répond 200 si les volumes critiques sont accessibles."""
    ok = MANIFEST_DIR.exists() and POOL_DIR.exists()
    if not ok:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="Volumes not ready")
    return {"ready": True}
