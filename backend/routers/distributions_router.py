"""
Routes pour la gestion des distributions RPM.
- GET  /distributions/                      → liste + stats
- GET  /distributions/{codename}/packages   → paquets dans une distribution
- POST /distributions/promote               → promouvoir un paquet
- POST /distributions/migrate               → migration en masse
- POST /distributions/init                  → initialise les dépôts createrepo_c
"""
import os
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from auth.dependencies import get_current_user, get_maintainer_user
from services.distributions import (
    RPM_DISTRIBUTIONS, VALID_CODENAMES,
    get_distribution_stats, list_packages_in_distrib,
    promote_package, migrate_all, init_distribution,
)
from services.audit import log as audit_log

router = APIRouter(prefix="/distributions", tags=["Distributions"])

MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))
REPO_BASE    = Path(os.getenv("REPO_BASE", "/repos"))


@router.get("/")
def list_distributions(current_user: str = Depends(get_current_user)):
    """Liste toutes les distributions RPM avec leur nombre de paquets."""
    return {"distributions": get_distribution_stats()}


@router.get("/{codename}/packages")
def get_distrib_packages(
    codename: str,
    arch: str = "x86_64",
    current_user: str = Depends(get_current_user),
):
    """Liste les paquets dans une distribution/architecture spécifique."""
    if codename not in VALID_CODENAMES:
        raise HTTPException(status_code=400, detail=f"Distribution inconnue : {codename}")
    packages = list_packages_in_distrib(codename, arch)
    return {"codename": codename, "arch": arch, "packages": packages, "total": len(packages)}


class PromoteRequest(BaseModel):
    package: str
    from_dist: str
    to_dist: str


@router.post("/promote")
def promote(
    req: PromoteRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """Promeut un paquet d'une distribution RPM vers une autre."""
    if req.from_dist not in VALID_CODENAMES or req.to_dist not in VALID_CODENAMES:
        raise HTTPException(status_code=400, detail="Distribution invalide")
    if req.from_dist == req.to_dist:
        raise HTTPException(status_code=400, detail="Source et destination identiques")

    ok, message = promote_package(req.package, req.from_dist, req.to_dist)
    if not ok:
        raise HTTPException(status_code=500, detail=message)

    audit_log("PROMOTE", current_user, "SUCCESS",
              package=req.package,
              detail=f"{req.from_dist} → {req.to_dist}")

    return {"status": "ok", "message": message,
            "package": req.package, "from": req.from_dist, "to": req.to_dist}


class MigrateRequest(BaseModel):
    from_dist: str
    to_dist: str


@router.post("/migrate")
def migrate(
    req: MigrateRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """Copie TOUS les paquets d'une distribution RPM vers une autre."""
    if req.from_dist not in VALID_CODENAMES or req.to_dist not in VALID_CODENAMES:
        raise HTTPException(status_code=400, detail="Distribution invalide")
    if req.from_dist == req.to_dist:
        raise HTTPException(status_code=400, detail="Source et destination identiques")

    count, copied, errors = migrate_all(req.from_dist, req.to_dist)

    # Mettre à jour les manifests
    import json
    updated_manifests = 0
    if MANIFEST_DIR.exists():
        for mf_path in MANIFEST_DIR.glob("*.manifest.json"):
            try:
                with open(mf_path) as f:
                    mf = json.load(f)
                if mf.get("distribution") == req.from_dist:
                    mf["distribution"] = req.to_dist
                    with open(mf_path, "w") as f:
                        json.dump(mf, f, indent=2, ensure_ascii=False)
                    updated_manifests += 1
            except Exception:
                continue

    if updated_manifests > 0:
        from services.indexer import sync_index_from_pool
        sync_index_from_pool()

    audit_log("MIGRATE", current_user, "SUCCESS",
              detail=f"{count} paquets migrés de {req.from_dist} vers {req.to_dist}")

    return {
        "status": "ok",
        "from": req.from_dist,
        "to": req.to_dist,
        "migrated": count,
        "packages": copied,
        "errors": errors,
        "manifests_updated": updated_manifests,
    }


@router.post("/init")
def init_all_distributions(current_user: str = Depends(get_maintainer_user)):
    """Initialise les dépôts createrepo_c pour toutes les distributions."""
    results = []
    for dist in RPM_DISTRIBUTIONS:
        ok, message = init_distribution(dist["codename"])
        results.append({
            "codename": dist["codename"],
            "ok": ok,
            "message": message,
        })

    n_ok = sum(r["ok"] for r in results)
    audit_log("INIT_DISTS", current_user,
              "SUCCESS" if n_ok == len(results) else "PARTIAL",
              detail=f"Init createrepo_c : {n_ok}/{len(results)} distributions OK")

    return {"results": results}


def auto_init_distributions() -> bool:
    """
    Initialisation silencieuse au démarrage.
    Crée les répertoires et metadata createrepo_c si absents.
    """
    import logging
    log = logging.getLogger("distributions.auto_init")

    any_missing = False
    for dist in RPM_DISTRIBUTIONS:
        repomd = REPO_BASE / dist["codename"] / "x86_64" / "repodata" / "repomd.xml"
        if not repomd.exists():
            any_missing = True
            break

    if not any_missing:
        return False

    log.info("[auto-init] Initialisation automatique des distributions RPM...")
    ok_count = 0
    for dist in RPM_DISTRIBUTIONS:
        ok, msg = init_distribution(dist["codename"])
        if ok:
            ok_count += 1
            log.info(f"[auto-init] ✓ {dist['codename']}")
        else:
            log.warning(f"[auto-init] ✗ {dist['codename']} : {msg}")

    log.info(f"[auto-init] Terminé — {ok_count}/{len(RPM_DISTRIBUTIONS)} distributions OK")
    return True
