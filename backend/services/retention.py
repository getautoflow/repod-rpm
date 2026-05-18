"""
Politique de rétention automatique.

Tâches planifiées chaque nuit (02:00) via APScheduler :
  1. Purge des logs d'audit  → supprime les fichiers JSONL plus vieux que audit_days
  2. Purge des vieux paquets → supprime les versions périmées (manifests + pool)
     - Pour chaque (nom, arch) → conserve la version la plus récente
     - Supprime les versions plus vieilles que import_cleanup_days SEULEMENT
       si une version plus récente existe (on ne supprime jamais la dernière version)

Peut aussi être déclenché manuellement via POST /settings/run-retention.
"""

import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

from services.audit import log as audit_log, AUDIT_DIR
from services.manifest import list_manifests, MANIFEST_DIR
from services.settings import get_settings

logger = logging.getLogger("retention")

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))


# ─── Audit logs ───────────────────────────────────────────────────────────────

def _purge_audit_logs(audit_days: int) -> dict:
    """
    Supprime les fichiers JSONL d'audit dont la date est antérieure à audit_days.
    Retourne {"deleted": N, "kept": M, "freed_bytes": B}.
    """
    if audit_days <= 0:
        return {"deleted": 0, "kept": 0, "freed_bytes": 0}

    cutoff = datetime.now(timezone.utc).date() - timedelta(days=audit_days)
    deleted = 0
    kept = 0
    freed_bytes = 0

    for log_file in sorted(AUDIT_DIR.glob("*.jsonl")):
        # Le nom du fichier est YYYY-MM-DD.jsonl
        stem = log_file.stem  # e.g. "2025-11-01"
        try:
            file_date = datetime.strptime(stem, "%Y-%m-%d").date()
        except ValueError:
            kept += 1
            continue

        if file_date < cutoff:
            size = log_file.stat().st_size
            try:
                log_file.unlink()
                freed_bytes += size
                deleted += 1
                logger.info(f"[retention] Audit log supprimé : {log_file.name}")
            except Exception as e:
                logger.error(f"[retention] Impossible de supprimer {log_file.name} : {e}")
                kept += 1
        else:
            kept += 1

    return {"deleted": deleted, "kept": kept, "freed_bytes": freed_bytes}


# ─── Vieux paquets ────────────────────────────────────────────────────────────

def _parse_imported_at(manifest: dict) -> datetime | None:
    """Extrait la date d'import depuis le manifest."""
    try:
        raw = manifest.get("source", {}).get("imported_at", "")
        if not raw:
            return None
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _purge_old_packages(import_cleanup_days: int) -> dict:
    """
    Pour chaque (nom, arch, distribution), conserve uniquement la version
    la plus récente. Supprime les versions plus anciennes si leur date
    d'import est antérieure à import_cleanup_days.

    Ne supprime jamais la seule version disponible d'un paquet.

    Retourne {"deleted": N, "freed_bytes": B, "packages": [...]}.
    """
    if import_cleanup_days <= 0:
        return {"deleted": 0, "freed_bytes": 0, "packages": []}

    cutoff = datetime.now(timezone.utc) - timedelta(days=import_cleanup_days)
    manifests = list_manifests()

    # Grouper par (nom, arch, distribution)
    groups: dict[tuple, list[dict]] = {}
    for m in manifests:
        key = (m.get("name", ""), m.get("arch", "x86_64"), m.get("distribution", "almalinux8"))
        groups.setdefault(key, []).append(m)

    deleted = 0
    freed_bytes = 0
    deleted_packages = []

    for (name, arch, distrib), versions in groups.items():
        if len(versions) <= 1:
            # Une seule version — ne jamais supprimer
            continue

        # Trier par date d'import (la plus récente en dernier)
        def sort_key(m):
            dt = _parse_imported_at(m)
            return dt or datetime.min.replace(tzinfo=timezone.utc)

        versions_sorted = sorted(versions, key=sort_key)

        # Garder la plus récente (dernière après tri)
        latest = versions_sorted[-1]
        candidates = versions_sorted[:-1]

        for m in candidates:
            imported_at = _parse_imported_at(m)
            if imported_at is None:
                continue
            # S'assurer que la date est timezone-aware
            if imported_at.tzinfo is None:
                imported_at = imported_at.replace(tzinfo=timezone.utc)

            if imported_at >= cutoff:
                # Pas encore assez vieux → on garde
                continue

            version = m.get("version", "unknown")
            filename = m.get("filename", "")

            # Supprimer le manifest
            version_safe = version.replace(":", "_").replace("/", "_")
            manifest_path = MANIFEST_DIR / f"{name}_{version_safe}_{arch}.manifest.json"
            manifest_deleted = False
            if manifest_path.exists():
                try:
                    manifest_path.unlink()
                    manifest_deleted = True
                    logger.info(f"[retention] Manifest supprimé : {manifest_path.name}")
                except Exception as e:
                    logger.error(f"[retention] Erreur manifest {manifest_path.name} : {e}")

            # Supprimer le fichier .rpm du pool
            pool_deleted = False
            pool_freed = 0
            if filename:
                pool_path = POOL_DIR / filename
                if pool_path.exists():
                    try:
                        pool_freed = pool_path.stat().st_size
                        pool_path.unlink()
                        pool_deleted = True
                        logger.info(f"[retention] Pool supprimé : {pool_path.name}")
                    except Exception as e:
                        logger.error(f"[retention] Erreur pool {pool_path.name} : {e}")

            if manifest_deleted or pool_deleted:
                deleted += 1
                freed_bytes += pool_freed
                deleted_packages.append({
                    "name":        name,
                    "version":     version,
                    "arch":        arch,
                    "distribution": distrib,
                    "imported_at": imported_at.isoformat(),
                })

    return {
        "deleted":  deleted,
        "freed_bytes": freed_bytes,
        "packages": deleted_packages,
    }


# ─── Point d'entrée principal ─────────────────────────────────────────────────

def run_retention() -> dict:
    """
    Exécute la politique de rétention complète.
    Retourne un résumé des actions effectuées.
    Enregistre le résultat dans l'audit log.
    """
    settings = get_settings()
    retention_cfg = settings.get("retention", {})
    audit_days          = int(retention_cfg.get("audit_days", 90))
    import_cleanup_days = int(retention_cfg.get("import_cleanup_days", 30))

    logger.info(
        f"[retention] Démarrage — audit_days={audit_days}, "
        f"import_cleanup_days={import_cleanup_days}"
    )

    audit_result   = _purge_audit_logs(audit_days)
    package_result = _purge_old_packages(import_cleanup_days)

    total_freed = audit_result["freed_bytes"] + package_result["freed_bytes"]

    summary = {
        "ran_at":          datetime.now(timezone.utc).isoformat(),
        "audit_logs":      audit_result,
        "packages":        package_result,
        "total_freed_bytes": total_freed,
    }

    audit_log(
        "RETENTION", "scheduler", "SUCCESS",
        detail=(
            f"Audit logs supprimés : {audit_result['deleted']} fichiers, "
            f"Paquets supprimés : {package_result['deleted']}, "
            f"Libéré : {total_freed / 1024 / 1024:.1f} Mo"
        ),
    )

    logger.info(
        f"[retention] Terminé — "
        f"audit:{audit_result['deleted']} logs, "
        f"paquets:{package_result['deleted']}, "
        f"libéré:{total_freed/1024/1024:.1f} Mo"
    )

    return summary
