"""
services/logging_config.py — [T] Logging JSON structuré

Fournit :
  • setup_logging()    — configure le logger racine avec JsonFormatter
  • request_id_var     — ContextVar propagé dans chaque log via _RequestIdFilter

Usage dans main.py :
    from services.logging_config import setup_logging
    setup_logging()

Usage dans les services (inchangé — les getLogger() existants héritent du root) :
    import logging
    logger = logging.getLogger("mon_service")
    logger.info("message")   # → {"timestamp": "...", "level": "INFO",
                             #    "name": "mon_service", "message": "...",
                             #    "request_id": "<uuid|->"}

Le champ request_id vaut "-" hors contexte de requête HTTP.
Il est positionné par RequestIdMiddleware via contextvars.
"""
import logging
import sys
from contextvars import ContextVar
from typing import IO

from pythonjsonlogger import jsonlogger

# ── ContextVar de corrélation ─────────────────────────────────────────────────
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


# ── Filtre d'injection du request_id ─────────────────────────────────────────

class _RequestIdFilter(logging.Filter):
    """
    Lit request_id_var et l'injecte dans chaque LogRecord.
    Compatible avec tous les handlers ajoutés au root logger.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


# ── Configuration principale ──────────────────────────────────────────────────

def setup_logging(
    level: int = logging.INFO,
    stream: IO[str] | None = None,
) -> None:
    """
    Configure le logger racine avec un JsonFormatter (python-json-logger).

    Paramètres
    ----------
    level  : niveau de log (défaut : INFO)
    stream : flux de sortie (défaut : sys.stderr) — passez un StringIO en test
             pour capturer la sortie sans polluer stderr.

    Après appel, tout logger obtenu par logging.getLogger("x") émet du JSON :
        {"timestamp": "...", "level": "INFO", "name": "x",
         "message": "...", "request_id": "-"}
    """
    formatter = jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        rename_fields={"levelname": "level", "asctime": "timestamp"},
    )

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(formatter)
    handler.addFilter(_RequestIdFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
