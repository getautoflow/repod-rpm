"""
Service d'import depuis internet pour les paquets RPM.
Télécharge un paquet et ses dépendances depuis l'index SQLite,
les valide et les ajoute au repo interne.
"""
import os
import shutil
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))
IMPORTS_DIR = Path(os.getenv("IMPORTS_DIR", "/repos/imports"))
ADD_RPM_SCRIPT = os.getenv("ADD_RPM_SCRIPT", "/scripts/add-rpm.sh")


def _run(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def _get_repo_base_url(repomd_url: str) -> str:
    """Extrait l'URL de base depuis une URL repomd.xml."""
    return repomd_url.rsplit("/repodata/", 1)[0]


def _download_rpm(pkg_name: str, tmp_dir: str) -> tuple[Path | None, str, str | None]:
    """
    Télécharge un .rpm depuis l'index SQLite local.
    Retourne (chemin_fichier, source_label, sha256_attendu) ou (None, message_erreur, None).
    """
    from services.package_index import get_package_info, DEFAULT_SOURCES

    row = get_package_info(pkg_name)
    if not row or not row.get("rpm_url"):
        return None, f"'{pkg_name}' introuvable dans l'index — lancez une synchronisation", None

    source = next((s for s in DEFAULT_SOURCES if s["id"] == row["source_id"]), None)
    if not source:
        return None, f"Source '{row['source_id']}' inconnue", None

    base_url = _get_repo_base_url(source["repomd_url"])
    rpm_href = row["rpm_url"]
    if rpm_href.startswith("http"):
        download_url = rpm_href
    else:
        download_url = f"{base_url}/{rpm_href.lstrip('/')}"

    expected_sha256 = row.get("sha256")
    filename = Path(rpm_href).name
    dest = Path(tmp_dir) / filename

    try:
        req = urllib.request.Request(download_url, headers={"User-Agent": "RPM-Repo-Manager/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            dest.write_bytes(resp.read())
        return dest, source["label"], expected_sha256
    except urllib.error.URLError as e:
        return None, f"Erreur téléchargement {pkg_name}: {e}", None


def resolve_deps_online(package_name: str) -> dict:
    """Résout les dépendances d'un paquet depuis l'index SQLite."""
    from services.package_index import get_package_info
    from services.indexer import get_package_info as repo_get_info

    row = get_package_info(package_name)
    if not row:
        return {
            "success": False,
            "error": f"Paquet '{package_name}' introuvable dans l'index local. "
                     "Lancez une synchronisation d'abord.",
            "packages": [],
        }

    dep_names = {package_name}
    if row.get("requires"):
        for part in row["requires"].split(","):
            part = part.strip().split()[0] if part.strip() else ""
            if part and all(c.isalnum() or c in ".-+_" for c in part):
                dep_names.add(part)

    packages = []
    for dep in sorted(dep_names):
        already_present = repo_get_info(dep) is not None
        packages.append({"name": dep, "already_in_repo": already_present})

    to_download = [p for p in packages if not p["already_in_repo"]]

    return {
        "success": True,
        "packages": packages,
        "to_download": to_download,
        "total": len(packages),
        "already_present": len(packages) - len(to_download),
    }


def import_package(
    package_name: str,
    distribution: str,
    current_user: str = "system",
) -> dict:
    """
    Importe un paquet RPM et ses dépendances depuis l'index.
    """
    import tempfile
    from services.validator import run_validation_pipeline
    from services.manifest import generate_manifest, save_manifest
    from services.indexer import add_to_index
    from services.audit import log as audit_log

    results = []
    errors = []

    deps_info = resolve_deps_online(package_name)
    if not deps_info["success"]:
        return {"success": False, "error": deps_info["error"], "results": []}

    packages_to_get = [p["name"] for p in deps_info["packages"] if not p["already_in_repo"]]
    if not packages_to_get:
        return {
            "success": True,
            "message": f"Tous les paquets sont déjà présents dans le repo",
            "results": [],
            "skipped": [p["name"] for p in deps_info["packages"]],
        }

    group_files = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        for pkg_name in packages_to_get:
            rpm_path, source_label, expected_sha256 = _download_rpm(pkg_name, tmp_dir)
            if rpm_path is None:
                errors.append({"name": pkg_name, "error": source_label})
                continue

            validation = run_validation_pipeline(
                str(rpm_path),
                expected_sha256=expected_sha256,
                distro=distribution,
            )

            if not validation.passed:
                errors.append({
                    "name": pkg_name,
                    "error": "Validation échouée",
                    "steps": validation.steps,
                })
                audit_log("IMPORT", current_user, "FAILURE",
                          package=pkg_name, detail="Validation échouée")
                continue

            pool_path = POOL_DIR / rpm_path.name
            shutil.copy2(str(rpm_path), str(pool_path))

            manifest = generate_manifest(
                str(pool_path),
                imported_by=current_user,
                import_method="import",
                validated_deps=validation.deps or None,
                validation_steps=validation.steps,
                cve_results=validation.cve_results or None,
                distribution=distribution,
            )
            save_manifest(manifest)
            add_to_index(manifest)

            # Ajout au dépôt RPM via add-rpm.sh
            r = subprocess.run(
                ["sh", ADD_RPM_SCRIPT, distribution, pool_path.name],
                capture_output=True, text=True,
                env={**os.environ, "GNUPG_HOME": os.getenv("GNUPG_HOME", "/repos/gnupg"),
                     "REPO_BASE": os.getenv("REPO_BASE", "/repos")},
            )
            createrepo_ok = r.returncode == 0

            audit_log("IMPORT", current_user, "SUCCESS",
                      package=manifest["name"], version=manifest["version"],
                      detail=f"source={source_label}, sha256={manifest['integrity']['sha256']}")

            group_files.append({
                "filename":   pool_path.name,
                "size_bytes": pool_path.stat().st_size if pool_path.exists() else 0,
            })

            results.append({
                "name":         manifest["name"],
                "version":      manifest["version"],
                "arch":         manifest["arch"],
                "sha256":       manifest["integrity"]["sha256"],
                "source":       source_label,
                "createrepo_ok": createrepo_ok,
            })

    # Enregistrer le groupe d'import pour l'historique
    if group_files:
        from services.package_index import record_import_group
        import time
        group_name = f"{package_name}-{int(time.time())}"
        record_import_group(
            name=group_name,
            files=group_files,
            distribution=distribution,
            imported_by=current_user,
        )

    return {
        "success": True,
        "imported": len(results),
        "errors":   len(errors),
        "results":  results,
        "error_details": errors,
    }
