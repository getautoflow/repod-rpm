"""
Enrichissement des CVE avec des sources de threat intelligence :

  EPSS (Exploit Prediction Scoring System) — FIRST.org
    → Score 0-100% : probabilité qu'une CVE soit exploitée dans les 30 jours
    → API : https://api.first.org/data/1.0/epss

  KEV (Known Exploited Vulnerabilities) — CISA
    → Liste des CVE activement exploitées en ce moment
    → Feed : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Cache disque (TTL 24h) dans /repos/security/ pour fonctionner en air-gap après
la première récupération.
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

logger = logging.getLogger("cve_enrichment")

SECURITY_CACHE_DIR = Path(os.getenv("SECURITY_CACHE_DIR", "/repos/security"))
SECURITY_CACHE_DIR.mkdir(parents=True, exist_ok=True)

KEV_CACHE_PATH  = SECURITY_CACHE_DIR / "kev_cache.json"
EPSS_CACHE_PATH = SECURITY_CACHE_DIR / "epss_cache.json"

KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/1.0/epss"

CACHE_TTL_HOURS = 24
REQUEST_TIMEOUT = 10


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _cache_fresh(path: Path, ttl_hours: int = CACHE_TTL_HOURS) -> bool:
    if not path.exists():
        return False
    age = datetime.now(timezone.utc) - datetime.fromtimestamp(
        path.stat().st_mtime, tz=timezone.utc
    )
    return age < timedelta(hours=ttl_hours)


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# ─── KEV CISA ────────────────────────────────────────────────────────────────

def refresh_kev() -> bool:
    """Force le rechargement du KEV CISA. Retourne True si succès."""
    try:
        resp = requests.get(KEV_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        cve_ids = [
            v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")
        ]
        _save_json(KEV_CACHE_PATH, {
            "cve_ids": cve_ids,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "total": len(cve_ids),
            "catalog_version": data.get("catalogVersion", ""),
        })
        logger.info(f"[KEV] Mis à jour — {len(cve_ids)} vulnérabilités actives exploitées")
        return True
    except Exception as e:
        logger.warning(f"[KEV] Impossible de mettre à jour : {e}")
        return False


def get_kev_set() -> set[str]:
    """
    Retourne l'ensemble des CVE IDs du CISA KEV.
    Utilise le cache si frais, sinon tente une mise à jour (graceful fallback).
    """
    if not _cache_fresh(KEV_CACHE_PATH):
        refresh_kev()

    cached = _load_json(KEV_CACHE_PATH)
    return set(cached.get("cve_ids", []))


def get_kev_meta() -> dict:
    """Retourne les métadonnées du cache KEV (date, total)."""
    cached = _load_json(KEV_CACHE_PATH)
    return {
        "total": cached.get("total", 0),
        "fetched_at": cached.get("fetched_at"),
        "catalog_version": cached.get("catalog_version", ""),
        "cache_fresh": _cache_fresh(KEV_CACHE_PATH),
    }


# ─── EPSS FIRST.org ──────────────────────────────────────────────────────────

def _load_epss_cache() -> dict[str, float]:
    cached = _load_json(EPSS_CACHE_PATH)
    return cached.get("scores", {})


def _save_epss_cache(scores: dict[str, float]) -> None:
    _save_json(EPSS_CACHE_PATH, {
        "scores": scores,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


def get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Retourne les scores EPSS pour une liste de CVE IDs.
    Valeur : float 0.0 – 1.0 (probabilité d'exploitation à 30 jours).
    """
    if not cve_ids:
        return {}

    scores = _load_epss_cache() if _cache_fresh(EPSS_CACHE_PATH) else {}
    missing = [c for c in cve_ids if c not in scores]

    if missing:
        try:
            # Batch par 100 (limite API FIRST.org)
            for i in range(0, len(missing), 100):
                batch = missing[i : i + 100]
                resp = requests.get(
                    EPSS_URL,
                    params={"cve": ",".join(batch), "limit": len(batch)},
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                for item in resp.json().get("data", []):
                    cve_id = item.get("cve", "")
                    if cve_id:
                        scores[cve_id] = round(float(item.get("epss", 0)), 6)
            _save_epss_cache(scores)
            logger.info(f"[EPSS] {len(missing)} nouveaux scores récupérés")
        except Exception as e:
            logger.warning(f"[EPSS] Impossible de récupérer les scores : {e}")

    return {cve: scores.get(cve, 0.0) for cve in cve_ids}


# ─── Enrichissement d'une liste de CVE ───────────────────────────────────────

def enrich_cve_list(cve_list: list[dict]) -> list[dict]:
    """
    Enrichit chaque CVE de la liste avec :
      - epss          : score brut (float 0.0–1.0)
      - epss_percent  : score en % (ex: 2.34)
      - epss_label    : "Critique" | "Élevé" | "Modéré" | "Faible"
      - in_kev        : bool — activement exploitée (CISA KEV)

    Modifie la liste en place et la retourne.
    """
    if not cve_list:
        return cve_list

    cve_ids = [c["id"] for c in cve_list if c.get("id")]

    try:
        kev_set    = get_kev_set()
        epss_map   = get_epss_scores(cve_ids)
    except Exception as e:
        logger.warning(f"[enrich] Enrichissement partiel ou ignoré : {e}")
        kev_set  = set()
        epss_map = {}

    for cve in cve_list:
        cid  = cve.get("id", "")
        epss = epss_map.get(cid, 0.0)
        pct  = round(epss * 100, 2)

        if pct >= 10:
            label = "Critique"
        elif pct >= 1:
            label = "Élevé"
        elif pct >= 0.1:
            label = "Modéré"
        else:
            label = "Faible"

        cve["epss"]         = epss
        cve["epss_percent"] = pct
        cve["epss_label"]   = label
        cve["in_kev"]       = cid in kev_set

    return cve_list
