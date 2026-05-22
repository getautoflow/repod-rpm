"""
Pipeline d'upload complet pour paquets RPM :
1. Réception du fichier → staging/incoming/
2. Validation (format, checksum, GPG, dépendances)
3. Si OK → déplacement vers pool/, génération manifest, mise à jour index
4. Si KO → déplacement vers staging/quarantine/
5. Audit log dans tous les cas

POST /upload/        → réponse JSON
POST /upload/stream  → réponse SSE workflow en temps réel
"""
import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from auth.dependencies import get_uploader_user
from limiter import limiter
from services.distributions import VALID_CODENAMES
from services.validator import run_validation_pipeline
from services.manifest import generate_manifest, save_manifest
from services.indexer import add_to_index
from services.audit import log as audit_log
from services.notifications import notify_pending_review
from services.email_notifications import notify_pending_review_email
from services.cve_utils import compute_cve_summary

router = APIRouter(prefix="/upload", tags=["Upload"])

STAGING_INCOMING   = Path(os.getenv("STAGING_INCOMING", "/repos/staging/incoming"))
STAGING_QUARANTINE = Path(os.getenv("STAGING_QUARANTINE", "/repos/staging/quarantine"))
POOL_DIR           = Path(os.getenv("POOL_DIR", "/repos/pool"))
ADD_RPM_SCRIPT     = os.getenv("ADD_RPM_SCRIPT", "/scripts/add-rpm.sh")

for d in [STAGING_INCOMING, STAGING_QUARANTINE, POOL_DIR]:
    d.mkdir(parents=True, exist_ok=True)


@router.post("/")
@limiter.limit("20/minute")
async def upload_package(
    request: Request,
    file: UploadFile = File(...),
    distribution: str = Form("almalinux8"),
    current_user: str = Depends(get_uploader_user),
):
    """
    Pipeline complet d'import d'un paquet .rpm :
    - Validation format, checksum, GPG, dépendances
    - Génération du manifest
    - Mise à jour de l'index
    - Ajout au dépôt RPM via createrepo_c
    """
    if distribution not in VALID_CODENAMES:
        raise HTTPException(
            status_code=400,
            detail=f"Distribution invalide. Valeurs acceptées : {', '.join(sorted(VALID_CODENAMES))}",
        )

    filename = file.filename
    if not filename:
        raise HTTPException(status_code=400, detail="Nom de fichier manquant")

    if not filename.endswith(".rpm"):
        raise HTTPException(status_code=400, detail="Seuls les fichiers .rpm sont acceptés")

    safe_filename = Path(filename).name
    staging_path = STAGING_INCOMING / safe_filename

    try:
        with open(staging_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)
    except Exception as e:
        audit_log("UPLOAD", current_user, "FAILURE", package=safe_filename,
                  detail=f"Erreur écriture staging: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la sauvegarde du fichier")

    # Pipeline de validation (Grype ≤ 300 s) — exécuté dans le thread pool
    validation = await asyncio.to_thread(
        run_validation_pipeline, str(staging_path), strict_deps=False, distro=distribution
    )

    if not validation.passed:
        quarantine_path = STAGING_QUARANTINE / safe_filename
        shutil.move(str(staging_path), str(quarantine_path))
        audit_log("VALIDATE", current_user, "FAILURE", package=safe_filename,
                  detail="Validation échouée — déplacé en quarantaine",
                  extra={"validation_steps": validation.steps})
        return {
            "status": "rejected",
            "filename": safe_filename,
            "message": "Le paquet a été rejeté et mis en quarantaine",
            "validation": validation.to_dict(),
        }

    pool_path = POOL_DIR / safe_filename
    shutil.move(str(staging_path), str(pool_path))

    cve_status = validation.cve_status
    manifest_status = "pending_review" if cve_status == "pending_review" else "validated"

    manifest = generate_manifest(
        str(pool_path),
        imported_by=current_user,
        validated_deps=validation.deps if validation.deps else None,
        validation_steps=validation.steps,
        cve_results=validation.cve_results if validation.cve_results else None,
        distribution=distribution,
    )
    manifest["status"] = manifest_status
    manifest_path = save_manifest(manifest)
    add_to_index(manifest)

    # Ajout au dépôt RPM via add-rpm.sh (createrepo_c) — thread pool
    createrepo_ok = False
    if cve_status != "pending_review":
        r = await asyncio.to_thread(
            subprocess.run,
            ["sh", ADD_RPM_SCRIPT, distribution, pool_path.name],
            capture_output=True, text=True,
            env={**os.environ,
                 "GNUPG_HOME": os.getenv("GNUPG_HOME", "/repos/gnupg"),
                 "REPO_BASE": os.getenv("REPO_BASE", "/repos")},
        )
        createrepo_ok = r.returncode == 0

    audit_log(
        "UPLOAD", current_user,
        "PENDING_REVIEW" if cve_status == "pending_review" else "SUCCESS",
        package=manifest["name"],
        version=manifest["version"],
        detail=(
            "En attente de révision RSSI — CVE politique déclenchée"
            if cve_status == "pending_review"
            else f"sha256={manifest['integrity']['sha256']}"
        ),
        extra={"validation_steps": validation.steps, "cve_status": cve_status},
    )

    warnings = [s for s in validation.steps if s.get("warning") and not s["passed"]]

    if cve_status == "pending_review":
        try:
            cve_counts, kev_count, worst = compute_cve_summary(validation.cve_results or [])
            notify_pending_review(
                package=manifest["name"],
                version=manifest["version"],
                arch=manifest["arch"],
                distribution=distribution,
                cve_counts=cve_counts,
                worst_severity=worst,
                kev_count=kev_count,
            )
            notify_pending_review_email(
                package=manifest["name"],
                version=manifest["version"],
                arch=manifest["arch"],
                distribution=distribution,
                cve_counts=cve_counts,
                worst_severity=worst,
                kev_count=kev_count,
            )
        except Exception:
            pass

    if cve_status == "pending_review":
        return {
            "status":    "pending_review",
            "filename":  safe_filename,
            "package":   manifest["name"],
            "version":   manifest["version"],
            "arch":      manifest["arch"],
            "sha256":    manifest["integrity"]["sha256"],
            "validation": validation.to_dict(),
            "warnings":  warnings,
            "message": (
                f"{manifest['name']} {manifest['version']} importé mais "
                "en attente de révision RSSI — non publié dans le dépôt RPM"
            ),
        }

    return {
        "status":    "accepted",
        "filename":  safe_filename,
        "package":   manifest["name"],
        "version":   manifest["version"],
        "arch":      manifest["arch"],
        "sha256":    manifest["integrity"]["sha256"],
        "validation": validation.to_dict(),
        "warnings":  warnings,
        "message":   f"{manifest['name']} {manifest['version']} ajouté au dépôt {distribution}",
    }


# ─── Upload streaming SSE ──────────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


async def _upload_stream_generator(safe_filename: str, staging_path: Path, distribution: str, current_user: str):
    def step(name: str, label: str, status: str, message: str = "", detail: str = ""):
        return _sse("step", {"name": name, "label": label, "status": status,
                             "message": message, "detail": detail})
    try:
        yield step("reception", "Réception du fichier", "done",
                   f"{safe_filename} — {staging_path.stat().st_size // 1024} Ko")

        yield step("validation", "Pipeline de validation", "running",
                   "Vérification format, intégrité, antivirus, CVE, dépendances...")

        # Grype peut prendre jusqu'à 300 s — exécuté dans le thread pool
        validation = await asyncio.to_thread(
            run_validation_pipeline, str(staging_path), strict_deps=False, distro=distribution
        )

        step_labels = {
            "format":       "Format .rpm",
            "checksum":     "Intégrité SHA-256",
            "gpg":          "Signature GPG",
            "antivirus":    "Scan antivirus ClamAV",
            "cve":          "Analyse CVE (Grype)",
            "dependencies": "Dépendances RPM",
            "provenance":   "Provenance SHA256",
        }
        for vs in validation.steps:
            name  = vs.get("name", "")
            passed  = vs.get("passed", False)
            warning = vs.get("warning", False)
            status  = "done" if (passed or warning) else "error"
            yield step(f"sub_{name}", step_labels.get(name, name), status,
                       vs.get("message", ""), vs.get("detail", ""))

        if not validation.passed:
            quarantine_path = STAGING_QUARANTINE / safe_filename
            shutil.move(str(staging_path), str(quarantine_path))
            audit_log("VALIDATE", current_user, "FAILURE", package=safe_filename,
                      detail="Validation échouée — déplacé en quarantaine",
                      extra={"validation_steps": validation.steps})
            yield step("validation", "Pipeline de validation", "error", "Paquet rejeté")
            yield _sse("result", {"status": "rejected",
                                  "message": "Le paquet a échoué à la validation.",
                                  "validation": validation.to_dict()})
            yield "data: done|DONE\n\n"
            return

        yield step("validation", "Pipeline de validation", "done", "Toutes les vérifications passées")

        yield step("pool", "Déplacement vers le pool", "running")
        pool_path = POOL_DIR / safe_filename
        shutil.move(str(staging_path), str(pool_path))
        yield step("pool", "Déplacement vers le pool", "done", f"pool/{safe_filename}")

        yield step("manifest", "Génération du manifest", "running")
        cve_status = validation.cve_status
        manifest_status = "pending_review" if cve_status == "pending_review" else "validated"
        manifest = generate_manifest(
            str(pool_path), imported_by=current_user,
            validated_deps=validation.deps if validation.deps else None,
            validation_steps=validation.steps,
            cve_results=validation.cve_results if validation.cve_results else None,
            distribution=distribution,
        )
        manifest["status"] = manifest_status
        save_manifest(manifest)
        yield step("manifest", "Génération du manifest", "done",
                   f"{manifest['name']} {manifest['version']} · {manifest['arch']}")

        yield step("index", "Mise à jour de l'index", "running")
        add_to_index(manifest)
        yield step("index", "Mise à jour de l'index", "done")

        createrepo_ok = False
        if cve_status != "pending_review":
            yield step("createrepo", "Mise à jour dépôt RPM (createrepo_c)", "running",
                       f"Distribution : {distribution}")
            r = await asyncio.to_thread(
                subprocess.run,
                ["sh", ADD_RPM_SCRIPT, distribution, pool_path.name],
                capture_output=True, text=True,
                env={**os.environ,
                     "GNUPG_HOME": os.getenv("GNUPG_HOME", "/repos/gnupg"),
                     "REPO_BASE": os.getenv("REPO_BASE", "/repos")},
            )
            createrepo_ok = r.returncode == 0
            yield step("createrepo", "Mise à jour dépôt RPM (createrepo_c)",
                       "done" if createrepo_ok else "warn",
                       (r.stdout or r.stderr or "").strip()[:120])
        else:
            yield step("createrepo", "Mise à jour dépôt RPM (createrepo_c)", "warn",
                       "En attente de révision RSSI — non publié dans le dépôt")

        audit_log("UPLOAD", current_user,
                  "PENDING_REVIEW" if cve_status == "pending_review" else "SUCCESS",
                  package=manifest["name"], version=manifest["version"],
                  detail=f"sha256={manifest['integrity']['sha256']}",
                  extra={"validation_steps": validation.steps, "cve_status": cve_status})

        yield _sse("result", {
            "status": "pending_review" if cve_status == "pending_review" else "accepted",
            "package": manifest["name"], "version": manifest["version"],
            "arch": manifest["arch"], "sha256": manifest["integrity"]["sha256"],
            "distribution": distribution,
            "message": (
                f"{manifest['name']} {manifest['version']} importé — en attente de révision RSSI"
                if cve_status == "pending_review"
                else f"{manifest['name']} {manifest['version']} ajouté au dépôt {distribution}"
            ),
            "validation": validation.to_dict(),
        })

    except Exception as exc:
        yield step("error", "Erreur inattendue", "error", str(exc))
        yield _sse("result", {"status": "error", "message": str(exc)})

    yield "data: done|DONE\n\n"


@router.post("/stream")
@limiter.limit("20/minute")
async def upload_package_stream(
    request: Request,
    file: UploadFile = File(...),
    distribution: str = Form("almalinux8"),
    current_user: str = Depends(get_uploader_user),
):
    """Upload avec workflow SSE en temps réel."""
    if distribution not in VALID_CODENAMES:
        raise HTTPException(status_code=400,
                            detail=f"Distribution invalide : {', '.join(sorted(VALID_CODENAMES))}")
    filename = file.filename or "unknown.rpm"
    if not filename.endswith(".rpm"):
        raise HTTPException(status_code=400, detail="Seuls les fichiers .rpm sont acceptés")
    safe_filename = Path(filename).name
    staging_path = STAGING_INCOMING / safe_filename
    try:
        with open(staging_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur écriture staging: {e}")

    return StreamingResponse(
        _upload_stream_generator(safe_filename, staging_path, distribution, current_user),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
