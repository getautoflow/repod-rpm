"""
GET /sbom/export          → SBOM global (tous les paquets ou filtré par distribution)
GET /sbom/{name}/{version} → SBOM d'un paquet précis

Query params :
  format       : cyclonedx (défaut) | spdx
  distribution : almalinux8 | rocky8 | centos-stream9 | ... | ...
  arch         : x86_64 (défaut)
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from auth.dependencies import get_current_user
from services.sbom import generate_sbom
from services.sarif import generate_sarif

router = APIRouter(prefix="/sbom", tags=["SBOM"])


def _json_response(data: dict, filename: str) -> Response:
    content = json.dumps(data, indent=2, ensure_ascii=False)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export")
def export_sbom(
    format: str = Query("cyclonedx", pattern="^(cyclonedx|spdx)$"),
    distribution: str | None = Query(None),
    arch: str = Query("x86_64"),
    _user: str = Depends(get_current_user),
):
    """Exporte le SBOM de tous les paquets du dépôt (optionnellement filtré)."""
    if format not in ("cyclonedx", "spdx"):
        raise HTTPException(status_code=400, detail="Format invalide. Valeurs acceptées : cyclonedx, spdx")

    try:
        doc = generate_sbom(fmt=format, distribution=distribution, arch=arch)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    now      = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    distrib  = f"-{distribution}" if distribution else ""
    ext      = "cdx" if format == "cyclonedx" else "spdx"
    filename = f"sbom{distrib}-{now}.{ext}.json"

    return _json_response(doc, filename)


@router.get("/{name}/{version}")
def export_package_sbom(
    name: str,
    version: str,
    format: str = Query("cyclonedx", pattern="^(cyclonedx|spdx)$"),
    arch: str = Query("x86_64"),
    _user: str = Depends(get_current_user),
):
    """Exporte le SBOM d'un paquet précis."""
    if format not in ("cyclonedx", "spdx"):
        raise HTTPException(status_code=400, detail="Format invalide.")

    try:
        doc = generate_sbom(fmt=format, name=name, version=version, arch=arch)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    components = doc.get("components") or doc.get("packages") or []
    # On exclut le paquet racine "SPDXRef-REPO" du comptage
    real = [c for c in components if c.get("SPDXID", "") != "SPDXRef-REPO"]
    if not real:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' version '{version}' introuvable.")

    version_safe = version.replace(":", "_").replace("/", "_")
    ext      = "cdx" if format == "cyclonedx" else "spdx"
    filename = f"sbom-{name}-{version_safe}-{arch}.{ext}.json"

    return _json_response(doc, filename)


@router.get("/sarif")
def export_sarif_global(
    distribution: str | None = Query(None),
    arch: str = Query("x86_64"),
    _user: str = Depends(get_current_user),
):
    """Exporte les vulnérabilités RPM au format SARIF 2.1.0 (tous paquets ou filtré)."""
    try:
        doc = generate_sarif(distribution=distribution, arch=arch)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    now     = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    distrib = f"-{distribution}" if distribution else ""
    filename = f"repod{distrib}-{now}.sarif.json"

    content = json.dumps(doc, indent=2, ensure_ascii=False)
    return Response(
        content=content,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{name}/{version}/sarif")
def export_sarif_package(
    name: str,
    version: str,
    arch: str = Query("x86_64"),
    _user: str = Depends(get_current_user),
):
    """Exporte les vulnérabilités d'un paquet RPM précis au format SARIF 2.1.0."""
    try:
        doc = generate_sarif(name=name, version=version, arch=arch)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    run = doc["runs"][0]
    if not run["results"]:
        raise HTTPException(
            status_code=404,
            detail=f"Paquet RPM '{name}' version '{version}' introuvable ou sans CVE.",
        )

    version_safe = version.replace(":", "_").replace("/", "_")
    filename = f"repod-{name}-{version_safe}-{arch}.sarif.json"

    content = json.dumps(doc, indent=2, ensure_ascii=False)
    return Response(
        content=content,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/preview")
def preview_sbom(
    format: str = Query("cyclonedx", pattern="^(cyclonedx|spdx)$"),
    distribution: str | None = Query(None),
    arch: str = Query("x86_64"),
    limit: int = Query(5, ge=1, le=50),
    _user: str = Depends(get_current_user),
):
    """Retourne un aperçu JSON (N premiers composants) sans déclencher de téléchargement."""
    doc = generate_sbom(fmt=format, distribution=distribution, arch=arch)

    # Tronquer pour l'aperçu
    if format == "cyclonedx":
        preview = {**doc, "components": doc.get("components", [])[:limit]}
    else:
        pkgs = [p for p in doc.get("packages", []) if p.get("SPDXID") != "SPDXRef-REPO"]
        preview = {**doc, "packages": pkgs[:limit], "relationships": doc.get("relationships", [])[:limit * 2]}

    total = len(doc.get("components") or [p for p in doc.get("packages", []) if p.get("SPDXID") != "SPDXRef-REPO"])
    return {"total_packages": total, "format": format, "preview": preview}
