"""
routers/webhook_router.py — [K] Endpoints webhooks entrants

  POST /webhooks/github  → GitHub Security Advisory / Dependabot
  POST /webhooks/kev     → CISA KEV (Known Exploited Vulnerabilities)

Authentification : HMAC-SHA256 via X-Hub-Signature-256 (convention GitHub).
  Secret : variable d'environnement WEBHOOK_SECRET.
  Si WEBHOOK_SECRET est vide → vérification désactivée (mode dev uniquement).

Authentification : signature HMAC uniquement — pas de JWT utilisateur.
Les webhooks proviennent de systèmes externes (GitHub, scripts internes).
"""

from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from services.webhook import (
    parse_github_advisory,
    parse_kev_entry,
    update_kev_flag,
    verify_github_signature,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

_WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")


def _check_signature(body: bytes, sig_header: str | None) -> None:
    """
    Lève HTTPException(401) si la signature est invalide.
    Si WEBHOOK_SECRET est vide, la vérification est ignorée (dev/local).
    """
    if not _WEBHOOK_SECRET:
        logger.warning("[webhook] WEBHOOK_SECRET non défini — vérification de signature désactivée")
        return
    if not verify_github_signature(body, sig_header or "", _WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


# ── GitHub Security Advisory ──────────────────────────────────────────────────

@router.post("/github")
async def receive_github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
    x_github_event: str | None = Header(None),
) -> JSONResponse:
    """
    Reçoit les webhooks GitHub (security_advisory, Dependabot alerts).

    Payload attendu : https://docs.github.com/en/webhooks/webhook-events-and-payloads#security_advisory
    """
    body = await request.body()
    _check_signature(body, x_hub_signature_256)

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event = x_github_event or "unknown"
    logger.info("[webhook] GitHub event reçu : %s", event)

    if event == "security_advisory":
        parsed = parse_github_advisory(payload)
        if parsed:
            cve_id = parsed["cve_id"]
            _audit("webhook_github_advisory", parsed)
            logger.info("[webhook] Advisory traitée : %s (%s)", cve_id, parsed.get("severity"))
            return JSONResponse({"status": "processed", "cve_id": cve_id})

    return JSONResponse({"status": "ignored", "event": event})


# ── CISA KEV ──────────────────────────────────────────────────────────────────

@router.post("/kev")
async def receive_kev_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
) -> JSONResponse:
    """
    Reçoit les mises à jour CISA KEV.

    Accepte un objet JSON unique ou une liste d'entrées KEV.
    Pour chaque entrée valide, propage in_kev=True sur les manifests RPM affectés.
    """
    body = await request.body()
    _check_signature(body, x_hub_signature_256)

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Accepte un objet unique OU une liste
    entries = payload if isinstance(payload, list) else [payload]

    processed: list[str] = []
    total_manifests_updated = 0

    for entry in entries:
        parsed = parse_kev_entry(entry)
        if not parsed:
            continue

        cve_id = parsed["cve_id"]
        n = update_kev_flag(cve_id)
        total_manifests_updated += n

        _audit("webhook_kev_entry", {**parsed, "manifests_updated": n})
        logger.info("[webhook] KEV %s → %d manifest(s) mis à jour", cve_id, n)
        processed.append(cve_id)

    return JSONResponse({
        "status": "processed",
        "cve_ids": processed,
        "count": len(processed),
        "manifests_updated": total_manifests_updated,
    })


# ── Audit ─────────────────────────────────────────────────────────────────────

def _audit(action: str, details: dict) -> None:
    """Enregistre l'événement dans le journal d'audit si disponible."""
    try:
        from services.audit import log as audit_log
        audit_log(action, user="webhook", result="SUCCESS", extra=details)
    except Exception as exc:   # pragma: no cover
        logger.warning("[webhook] Impossible d'auditer %s : %s", action, exc)
