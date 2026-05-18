"""
Statistiques de téléchargements APT.

Source : /repos/logs/downloads.log (nginx access log, format "main")
  Format : $remote_addr - $remote_user [$time_local] "$request" $status
            $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"

Exemple :
  192.168.1.10 - - [12/May/2026:10:00:00 +0000] "GET /repos/almalinux8/x86_64/libssl-1.1.1-1.x86_64.rpm HTTP/1.1" 200 487321 "-" "Debian APT-HTTP/1.3 (2.4.9)" "-"

Cache en mémoire de 2 min (résultat recalculé si le fichier log a grossi).
"""

import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

NGINX_LOGS_DIR = Path(os.getenv("NGINX_LOGS_DIR", "/repos/logs"))
DOWNLOADS_LOG  = NGINX_LOGS_DIR / "downloads.log"

# Regex pour le format nginx "main"
_LOG_RE = re.compile(
    r'(?P<ip>\S+) - \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\d+) '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)

# Cache en mémoire
_cache: dict = {}
_cache_mtime: float = 0.0
_cache_size:  int   = 0


def _parse_log() -> list[dict]:
    """Lit et parse le fichier downloads.log. Retourne uniquement les 200/206."""
    entries = []
    if not DOWNLOADS_LOG.exists():
        return entries

    with open(DOWNLOADS_LOG, "r", errors="replace") as f:
        for line in f:
            m = _LOG_RE.match(line.strip())
            if not m:
                continue
            status = int(m.group("status"))
            if status not in (200, 206):
                continue

            path = m.group("path")
            # Extraire le nom du fichier .deb depuis l'URL
            filename = path.rstrip("/").split("/")[-1]
            if not filename.endswith(".rpm"):
                continue

            # Décomposer le nom : name_version_arch.deb
            stem = filename[:-4]
            parts = stem.rsplit("_", 2)
            pkg_name = parts[0] if parts else stem
            pkg_version = parts[1] if len(parts) > 1 else "unknown"
            pkg_arch = parts[2] if len(parts) > 2 else "unknown"

            # Parser la date nginx : "12/May/2026:10:00:00 +0000"
            try:
                dt = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
                date_str = dt.strftime("%Y-%m-%d")
            except Exception:
                date_str = "unknown"

            ua = m.group("ua")
            # Détecter les clients APT
            is_apt = "apt" in ua.lower() or "debian" in ua.lower()

            entries.append({
                "ip":        m.group("ip"),
                "date":      date_str,
                "filename":  filename,
                "name":      pkg_name,
                "version":   pkg_version,
                "arch":      pkg_arch,
                "bytes":     int(m.group("bytes")),
                "user_agent": ua,
                "is_apt":    is_apt,
                "status":    status,
                "path":      path,
            })

    return entries


def _get_entries() -> list[dict]:
    """Retourne les entrées parsées avec cache basé sur la taille du fichier."""
    global _cache, _cache_mtime, _cache_size

    if not DOWNLOADS_LOG.exists():
        return []

    stat = DOWNLOADS_LOG.stat()
    now  = time.time()

    # Invalider si le fichier a grossi ou cache > 2 min
    if stat.st_size != _cache_size or (now - _cache_mtime) > 120:
        _cache       = {"entries": _parse_log()}
        _cache_mtime = now
        _cache_size  = stat.st_size

    return _cache["entries"]


def get_download_stats(days: int = 30) -> dict:
    """
    Calcule les statistiques de téléchargements pour les N derniers jours.
    Retourne un dict avec summary, per_package, per_day, recent.
    """
    entries = _get_entries()

    # Filtrer sur la période demandée
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    entries = [e for e in entries if e["date"] >= cutoff]

    if not entries:
        return {
            "summary": {
                "total_downloads": 0,
                "unique_packages":  0,
                "unique_clients":   0,
                "total_bytes":      0,
                "apt_downloads":    0,
                "log_available":    DOWNLOADS_LOG.exists(),
            },
            "per_package": [],
            "per_day":     [],
            "recent":      [],
        }

    # ── Summary ───────────────────────────────────────────────────────────────
    total_downloads = len(entries)
    unique_packages  = len({e["name"] for e in entries})
    unique_clients   = len({e["ip"] for e in entries})
    total_bytes      = sum(e["bytes"] for e in entries)
    apt_downloads    = sum(1 for e in entries if e["is_apt"])

    # ── Par paquet ────────────────────────────────────────────────────────────
    pkg_counts: dict[str, dict] = defaultdict(lambda: {
        "downloads": 0, "bytes": 0, "versions": set(), "clients": set()
    })
    for e in entries:
        d = pkg_counts[e["name"]]
        d["downloads"] += 1
        d["bytes"]     += e["bytes"]
        d["versions"].add(e["version"])
        d["clients"].add(e["ip"])

    per_package = sorted(
        [
            {
                "name":      name,
                "downloads": d["downloads"],
                "bytes":     d["bytes"],
                "versions":  sorted(d["versions"]),
                "clients":   len(d["clients"]),
            }
            for name, d in pkg_counts.items()
        ],
        key=lambda x: x["downloads"],
        reverse=True,
    )[:50]

    # ── Par jour ──────────────────────────────────────────────────────────────
    day_counts: dict[str, dict] = defaultdict(lambda: {"downloads": 0, "bytes": 0})
    for e in entries:
        day_counts[e["date"]]["downloads"] += 1
        day_counts[e["date"]]["bytes"]     += e["bytes"]

    per_day = sorted(
        [{"date": d, **v} for d, v in day_counts.items()],
        key=lambda x: x["date"],
    )

    # ── Récents (50 derniers) ─────────────────────────────────────────────────
    recent = entries[-50:][::-1]

    return {
        "summary": {
            "total_downloads": total_downloads,
            "unique_packages":  unique_packages,
            "unique_clients":   unique_clients,
            "total_bytes":      total_bytes,
            "apt_downloads":    apt_downloads,
            "log_available":    True,
        },
        "per_package": per_package,
        "per_day":     per_day,
        "recent":      recent,
    }
