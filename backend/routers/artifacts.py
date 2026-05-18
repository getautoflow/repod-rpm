"""
Routes pour la gestion des artefacts :
- Liste enrichie depuis l'index
- Détail d'un paquet (toutes versions)
- Résolution de dépendances
- Suppression
- Historique d'audit
- Synchronisation de l'index
"""
import os
import subprocess
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from auth.dependencies import get_current_user, get_admin_user, get_uploader_user, get_maintainer_user, get_auditor_user
from services.indexer import (
    list_packages_from_index, get_package_info,
    remove_from_index, sync_index_from_pool, get_index,
)
from services.manifest import load_manifest, list_manifests
from services.audit import log as audit_log, get_recent_logs, get_package_history
from services.validator import validate_dependencies, ValidationResult

router = APIRouter(prefix="/artifacts", tags=["Artifacts"])

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))
MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))


# ─── Liste & détail ──────────────────────────────────────────────────────────

@router.get("/")
def list_artifacts(current_user: str = Depends(get_current_user)):
    """Liste tous les artefacts avec métadonnées enrichies depuis l'index."""
    try:
        return {"packages": list_packages_from_index()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{name}")
def get_artifact(name: str, current_user: str = Depends(get_current_user)):
    """Retourne le détail complet d'un paquet (toutes versions, historique, validation)."""
    info = get_package_info(name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' introuvable")
    history = get_package_history(name)

    # Charger les étapes de validation depuis le manifest
    latest = info.get("latest")
    version_info = info["versions"].get(latest, {}) if latest else {}
    arch = version_info.get("arch", "amd64")
    manifest = load_manifest(name, latest, arch) if latest else None
    validation_steps = manifest.get("validation_steps", []) if manifest else []

    return {"name": name, "info": info, "history": history, "validation_steps": validation_steps}


# ─── Résolution de dépendances ───────────────────────────────────────────────

@router.get("/{name}/dependencies")
def resolve_dependencies(name: str, current_user: str = Depends(get_current_user)):
    """
    Résout les dépendances d'un paquet et retourne leur disponibilité interne.
    Utilisé par le bouton 'Installer' pour valider avant de procéder.
    """
    info = get_package_info(name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' introuvable")

    latest = info.get("latest")
    if not latest:
        raise HTTPException(status_code=404, detail="Aucune version disponible")

    version_info = info["versions"][latest]
    arch = version_info.get("arch", "amd64")

    manifest = load_manifest(name, latest, arch)
    if not manifest:
        return {
            "package": name,
            "version": latest,
            "dependencies": [],
            "all_satisfied": True,
            "missing": [],
        }

    # Re-vérifier la disponibilité en temps réel dans le pool
    # (un paquet manquant au moment de l'upload a pu être ajouté depuis)
    deps = manifest.get("dependencies", [])
    for dep in deps:
        dep_name = dep["name"]
        matches = list(POOL_DIR.rglob(f"{dep_name}-*.rpm"))
        dep["available_internally"] = len(matches) > 0

    missing = [d["name"] for d in deps if not d["available_internally"]]

    return {
        "package": name,
        "version": latest,
        "dependencies": deps,
        "all_satisfied": len(missing) == 0,
        "missing": missing,
        "install_blocked": len(missing) > 0,
    }


# ─── Installation ─────────────────────────────────────────────────────────────

class InstallRequest(BaseModel):
    target: str = "localhost"


@router.post("/{name}/install")
def install_artifact(
    name: str,
    request: InstallRequest,
    current_user: str = Depends(get_uploader_user),
):
    """
    Installe un paquet sur une cible après vérification des dépendances.
    Bloque si des dépendances sont manquantes.
    """
    info = get_package_info(name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' introuvable")

    latest = info.get("latest")
    version_info = info["versions"].get(latest, {})
    missing_deps = version_info.get("deps_missing", [])

    if missing_deps:
        audit_log("INSTALL", current_user, "FAILURE", package=name, version=latest,
                  detail=f"Dépendances manquantes: {', '.join(missing_deps)}",
                  extra={"target": request.target})
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Installation bloquée — dépendances manquantes dans le repo interne",
                "missing_dependencies": missing_deps,
            }
        )

    # Lancer l'installation via SSH ou localement
    from services.download import download_package
    result = download_package(name)

    audit_log("INSTALL", current_user, "SUCCESS", package=name, version=latest,
              extra={"target": request.target})

    return {
        "status": "success",
        "package": name,
        "version": latest,
        "target": request.target,
        "result": result,
    }


# ─── Suppression ─────────────────────────────────────────────────────────────

@router.delete("/{name}")
def delete_artifact(name: str, current_user: str = Depends(get_maintainer_user)):
    """Supprime un paquet du dépôt (toutes versions)."""
    info = get_package_info(name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' introuvable")

    # Supprimer les .rpm du pool et les répertoires distributions
    import os
    from services.distributions import RPM_DISTRIBUTIONS, REPO_BASE, _run_createrepo
    for arch_dir in REPO_BASE.glob(f"*/*"):
        for rpm_file in arch_dir.glob(f"{name}-*.rpm"):
            rpm_file.unlink(missing_ok=True)
        if arch_dir.is_dir() and (arch_dir / "repodata" / "repomd.xml").exists():
            _run_createrepo(arch_dir)

    # Supprimer les fichiers .rpm du pool
    for rpm_file in POOL_DIR.glob(f"{name}-*.rpm"):
        rpm_file.unlink(missing_ok=True)

    # Supprimer les manifests
    for mf in MANIFEST_DIR.glob(f"{name}_*.manifest.json"):
        mf.unlink(missing_ok=True)

    # Mettre à jour l'index
    remove_from_index(name)

    audit_log("DELETE", current_user, "SUCCESS", package=name,
              detail="Toutes les versions supprimées")

    return {"status": "deleted", "package": name}


@router.delete("/{name}/{version}")
def delete_artifact_version(
    name: str, version: str,
    current_user: str = Depends(get_maintainer_user),
):
    """Supprime une version spécifique d'un paquet."""
    info = get_package_info(name)
    if not info or version not in info.get("versions", {}):
        raise HTTPException(status_code=404, detail=f"{name} {version} introuvable")

    arch = info["versions"][version].get("arch", "x86_64")
    filename = info["versions"][version].get("filename", f"{name}-{version}.{arch}.rpm")

    # Supprimer le .rpm des répertoires distributions
    from services.distributions import REPO_BASE, _run_createrepo
    for arch_dir in REPO_BASE.glob(f"*/{arch}"):
        for rpm_file in arch_dir.glob(f"{name}-*.rpm"):
            rpm_file.unlink(missing_ok=True)
        if arch_dir.is_dir() and (arch_dir / "repodata" / "repomd.xml").exists():
            _run_createrepo(arch_dir)

    # Supprimer le fichier .rpm du pool
    rpm_path = POOL_DIR / filename
    rpm_path.unlink(missing_ok=True)

    # Supprimer le manifest
    version_safe = version.replace(":", "_").replace("/", "_")
    manifest_path = MANIFEST_DIR / f"{name}_{version_safe}_{arch}.manifest.json"
    manifest_path.unlink(missing_ok=True)

    remove_from_index(name, version)
    audit_log("DELETE", current_user, "SUCCESS", package=name, version=version)

    return {"status": "deleted", "package": name, "version": version}


# ─── Audit & Sync ─────────────────────────────────────────────────────────────

@router.get("/audit/logs")
def get_audit_logs(
    limit: int = 200,
    package: str = None,
    action: str = None,
    result: str = None,
    current_user: str = Depends(get_auditor_user),
):
    """Retourne les entrées du journal d'audit avec filtres optionnels."""
    if package:
        logs = get_package_history(package)
    else:
        logs = get_recent_logs(limit=limit)

    if action:
        logs = [l for l in logs if l.get("action", "").upper() == action.upper()]
    if result:
        logs = [l for l in logs if l.get("result", "").upper() == result.upper()]

    return {"logs": logs[:limit], "total": len(logs)}


@router.post("/admin/sync-index")
def sync_index(current_user: str = Depends(get_maintainer_user)):
    """Resynchronise l'index depuis les fichiers manifests existants."""
    count = sync_index_from_pool()
    audit_log("SYNC", current_user, "SUCCESS", detail=f"{count} paquets indexés")
    return {"status": "ok", "packages_indexed": count}


@router.get("/admin/index")
def get_full_index(current_user: str = Depends(get_admin_user)):
    """Retourne l'index complet (pour debug/inspection)."""
    return get_index()
