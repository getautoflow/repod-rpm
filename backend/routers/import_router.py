"""
Routes d'import de paquets RPM depuis les miroirs upstream.

Architecture :
  GET  /import/sync-status      → état de synchro de toutes les sources
  GET  /import/sync-schedule    → config du cron de sync
  POST /import/sync             → déclencher une synchro complète (SSE)
  POST /import/sync-security    → synchro des sources de sécurité (SSE)
  GET  /import/search           → rechercher dans l'index local
  GET  /import/resolve/{pkg}    → résoudre les dépendances sans télécharger
  POST /import/                 → importer un paquet + ses dépendances
  GET  /import/stats            → statistiques détaillées (alias sync-status)
  GET  /import/groups           → groupes d'import (paquets importés ensemble)
  DELETE /import/groups/{name}  → supprimer un groupe
"""
import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from auth.dependencies import get_current_user, get_uploader_user, get_maintainer_user
from limiter import limiter
from fastapi import Request
from services.distributions import VALID_CODENAMES
from services.audit import log as audit_log
from services.importer import import_package, resolve_deps_online
from services.package_index import resolve_provide_to_package
from services.package_index import (
    search_packages, get_sync_stats,
    DEFAULT_SOURCES, sync_source,
    get_import_groups, delete_import_group,
)
from services.security_sync import run_security_sync

router = APIRouter(prefix="/import", tags=["Import"])


# ─── Modèles ─────────────────────────────────────────────────────────────────

class ImportRequest(BaseModel):
    package: str
    distribution: str = "almalinux8"
    with_deps: bool = True


class BatchImportRequest(BaseModel):
    packages: list[str]
    distribution: str = "almalinux8"
    with_deps: bool = False


class SyncRequest(BaseModel):
    source_ids: list[str] | None = None  # None = toutes les sources


# ─── Statut de synchronisation ───────────────────────────────────────────────

@router.get("/sync-status")
async def get_sync_status(current_user: str = Depends(get_current_user)):
    """
    Retourne l'état de synchronisation de chaque source RPM.

    Chaque source correspond à un dépôt upstream (BaseOS, AppStream, EPEL…).
    Le statut est 'never' si jamais synchronisé, 'ok'/'error' sinon.
    """
    return {"sources": get_sync_stats()}


@router.get("/stats")
async def get_import_stats(current_user: str = Depends(get_current_user)):
    """Alias de /sync-status pour compatibilité."""
    return {"sources": get_sync_stats()}


@router.get("/sync-schedule")
async def get_sync_schedule(current_user: str = Depends(get_current_user)):
    """Retourne la configuration du cron de synchronisation automatique."""
    from services.settings import get_settings
    settings = get_settings()
    sync = settings.get("sync", {})
    return {
        "enabled": sync.get("enabled", True),
        "hour":    sync.get("hour", 2),
        "minute":  sync.get("minute", 0),
        "next_run": None,
    }


# ─── Synchronisation SSE ─────────────────────────────────────────────────────

@router.post("/sync")
@limiter.limit("3/hour")
async def sync_all_sources_sse(
    request: Request,
    body: SyncRequest = SyncRequest(),
    current_user: str = Depends(get_uploader_user),
):
    """
    Synchronise les sources RPM avec streaming SSE des logs.

    Processus par source :
      1. Télécharger repomd.xml
      2. Extraire primary.xml.gz, le décompresser
      3. Parser les paquets et insérer dans SQLite
    """
    sources_to_sync = DEFAULT_SOURCES
    if body.source_ids:
        sources_to_sync = [s for s in DEFAULT_SOURCES if s["id"] in body.source_ids]

    audit_log("SYNC_INDEX", current_user, "STARTED",
              detail=f"Sync de {len(sources_to_sync)} source(s)")

    def _sse_data(level: str, msg: str) -> str:
        return f"data: {level}|{msg}\n\n"

    async def _sync_with_keepalive(source: dict, out: list, interval: float = 3.0):
        """
        Lance sync_source() dans un thread et envoie des keepalives SSE pendant
        l'attente pour éviter les timeouts réseau.

        Le problème : primary.xml.gz peut faire 2-50 MB selon la distro.
        AlmaLinux 8 BaseOS : ~5 MB compressé, ~50 MB décompressé, 1800+ paquets.
        Le téléchargement + parsing peut prendre 30-90s → connexion SSE coupée.
        Solution : commentaire SSE (": keepalive") toutes les 3s = zéro timeout.
        Le résultat est stocké dans `out[0]` (async generators ne peuvent pas
        retourner de valeur avec return).
        """
        loop = asyncio.get_event_loop()
        fut  = asyncio.ensure_future(loop.run_in_executor(None, sync_source, source))
        while not fut.done():
            try:
                await asyncio.wait_for(asyncio.shield(fut), timeout=interval)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"   # commentaire SSE — ignoré par le client
        out.append(fut.result())

    async def event_stream():
        total_ok    = 0
        total_error = 0

        yield _sse_data("info", f"Démarrage de la synchronisation — {len(sources_to_sync)} source(s)")

        for source in sources_to_sync:
            yield _sse_data("info", f"Synchronisation de {source['label']}…")

            out = []
            try:
                async for chunk in _sync_with_keepalive(source, out):
                    yield chunk   # transmet les keepalives
            except Exception as exc:
                total_error += 1
                yield _sse_data("error", f"{source['label']} — exception : {exc}")
                continue

            if out:
                result = out[0]
            else:
                # Fallback : relire depuis DB si le résultat n'a pas été stocké
                from services.package_index import get_sync_stats
                stats = {s["id"]: s for s in get_sync_stats()}
                stat  = stats.get(source["id"], {})
                if stat.get("status") == "ok":
                    result = {"status": "ok", "pkg_count": stat["pkg_count"]}
                else:
                    result = {"status": "error", "error": stat.get("error", "inconnu")}

            if result["status"] == "ok":
                total_ok += 1
                yield _sse_data("success",
                                f"{source['label']} — {result['pkg_count']:,} paquets indexés")
            else:
                total_error += 1
                yield _sse_data("error",
                                f"{source['label']} — {result.get('error', 'erreur')}")

        status = "SUCCESS" if total_error == 0 else "PARTIAL"
        audit_log("SYNC_INDEX", current_user, status,
                  detail=f"{total_ok} OK, {total_error} erreurs")

        yield _sse_data("done", f"Terminé — {total_ok} source(s) OK, {total_error} erreur(s)")

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":      "no-cache",
            "X-Accel-Buffering":  "no",
            "Connection":         "keep-alive",
        },
    )


@router.post("/sync-security")
@limiter.limit("3/hour")
async def sync_security_sources(
    request: Request,
    current_user: str = Depends(get_uploader_user),
):
    """
    Synchronise les sources de sécurité RPM (sources avec security=True).
    Ces sources contiennent des updateinfo.xml.gz avec les avis CVE.
    """
    audit_log("SYNC_SECURITY", current_user, "STARTED",
              detail="Sync sécurité RPM déclenchée manuellement")

    def _sse_line(level: str, msg: str) -> str:
        return f"data: {level}|{msg}\n\n"

    async def event_stream():
        security_sources = [s for s in DEFAULT_SOURCES if s.get("security")]
        yield _sse_line("info", f"Synchronisation sécurité — {len(security_sources)} source(s)")

        total_ok = 0
        total_error = 0

        for source in security_sources:
            yield _sse_line("info", f"Sync {source['label']}…")
            await asyncio.sleep(0)
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, sync_source, source
                )
                if result["status"] == "ok":
                    total_ok += 1
                    yield _sse_line("success", f"{source['label']} — {result['pkg_count']:,} paquets")
                else:
                    total_error += 1
                    yield _sse_line("error", f"{source['label']} — {result.get('error')}")
            except Exception as exc:
                total_error += 1
                yield _sse_line("error", f"{source['label']} — {exc}")
            await asyncio.sleep(0)

        status = "SUCCESS" if total_error == 0 else "PARTIAL"
        audit_log("SYNC_SECURITY", current_user, status,
                  detail=f"{total_ok} OK, {total_error} erreurs")
        yield _sse_line("done", f"Terminé — {total_ok} OK, {total_error} erreur(s)")

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── Recherche & résolution ───────────────────────────────────────────────────

@router.get("/search")
async def search_rpm_packages(
    q: str = Query(..., min_length=2, description="Terme de recherche"),
    limit: int = Query(50, ge=1, le=200),
    source_id: str | None = Query(None, description="Filtrer par source"),
    current_user: str = Depends(get_current_user),
):
    """
    Recherche dans l'index local de paquets RPM.

    Prérequis : au moins une source doit avoir été synchronisée via /import/sync.
    La recherche porte sur le nom du paquet ET le résumé (summary).
    """
    if not source_id:
        # Vérifier que l'index n'est pas vide
        stats = get_sync_stats()
        total = sum(s["pkg_count"] for s in stats)
        if total == 0:
            raise HTTPException(
                status_code=424,
                detail="L'index RPM est vide. Lancez une synchronisation via l'onglet Synchronisation.",
            )

    results = search_packages(q, limit=limit, source_id=source_id)
    return {"query": q, "results": results, "total": len(results)}


@router.get("/resolve/{package_name}")
async def resolve_dependencies(
    package_name: str,
    current_user: str = Depends(get_current_user),
):
    """
    Résout les dépendances d'un paquet depuis l'index local.
    Ne télécharge rien — utile pour prévisualiser avant import.
    """
    result = resolve_deps_online(package_name)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ─── Import ──────────────────────────────────────────────────────────────────

@router.post("/")
@limiter.limit("10/minute")
async def import_rpm_package(
    request: Request,
    body: ImportRequest,
    current_user: str = Depends(get_uploader_user),
):
    """
    Importe un paquet RPM et ses dépendances depuis les miroirs upstream.

    Processus :
      1. Résoudre les dépendances depuis l'index local
      2. Télécharger les .rpm manquants
      3. Valider chaque fichier (format, ClamAV, Grype CVE)
      4. Copier dans le pool + ajouter au dépôt via createrepo_c
    """
    if body.distribution not in VALID_CODENAMES:
        raise HTTPException(
            status_code=400,
            detail=f"Distribution invalide. Valeurs acceptées : {', '.join(sorted(VALID_CODENAMES))}",
        )

    result = import_package(
        package_name=body.package,
        distribution=body.distribution,
        current_user=current_user,
    )

    if not result["success"]:
        raise HTTPException(status_code=404, detail=result.get("error", "Import échoué"))

    return result


@router.post("/batch")
@limiter.limit("5/minute")
async def import_rpm_batch(
    request: Request,
    body: BatchImportRequest,
    current_user: str = Depends(get_uploader_user),
):
    """
    Importe une liste de paquets RPM en une seule requête (max 50).
    Utilisé pour importer les dépendances manquantes d'un paquet.
    """
    if not body.packages:
        raise HTTPException(status_code=400, detail="La liste de paquets est vide.")
    if len(body.packages) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 paquets par requête batch.")
    if body.distribution not in VALID_CODENAMES:
        raise HTTPException(
            status_code=400,
            detail=f"Distribution invalide. Valeurs acceptées : {', '.join(sorted(VALID_CODENAMES))}",
        )

    results = []
    total_imported = 0
    total_errors = 0

    # Déduplique les noms de paquets résolus pour éviter les imports en double
    resolved_names: set[str] = set()

    for capability in body.packages:
        # Résoudre la capability RPM vers un vrai nom de paquet
        pkg_row = resolve_provide_to_package(capability)
        if not pkg_row:
            total_errors += 1
            results.append({
                "package": capability,
                "status": "error",
                "error": f"Capability '{capability}' introuvable dans l'index. Lancez une synchronisation.",
            })
            continue

        pkg_name = pkg_row["name"]

        # Éviter de réimporter le même paquet résolu plusieurs fois
        if pkg_name in resolved_names:
            results.append({
                "package": capability,
                "status": "ok",
                "imported": 0,
                "skipped": 1,
                "resolved_as": pkg_name,
            })
            continue
        resolved_names.add(pkg_name)

        result = import_package(
            package_name=pkg_name,
            distribution=body.distribution,
            current_user=current_user,
        )
        if result["success"]:
            total_imported += result.get("imported", 0)
            results.append({
                "package": capability,
                "status": "ok",
                "imported": result.get("imported", 0),
                "skipped": len(result.get("skipped", [])),
                "resolved_as": pkg_name,
            })
        else:
            total_errors += 1
            results.append({
                "package": capability,
                "status": "error",
                "error": result.get("error", "Import échoué"),
                "resolved_as": pkg_name,
            })

    return {
        "success": total_errors == 0,
        "total": len(body.packages),
        "imported": total_imported,
        "errors": total_errors,
        "results": results,
    }


# ─── Groupes d'import ────────────────────────────────────────────────────────

@router.get("/groups")
async def list_import_groups(current_user: str = Depends(get_current_user)):
    """
    Retourne les groupes d'import : ensembles de paquets .rpm
    téléchargés et importés ensemble dans le dépôt.
    """
    groups = get_import_groups()
    return {"groups": groups}


@router.delete("/groups/{name}")
async def delete_group(
    name: str,
    current_user: str = Depends(get_maintainer_user),
):
    """Supprime un groupe d'import de l'historique (ne supprime pas les .rpm du pool)."""
    delete_import_group(name)
    audit_log("DELETE_GROUP", current_user, "SUCCESS", detail=f"Groupe '{name}' supprimé")
    return {"status": "deleted", "name": name}
