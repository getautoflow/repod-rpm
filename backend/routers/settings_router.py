"""
Routes pour les paramètres de l'application (admin uniquement).
- GET  /settings/           → lire tous les paramètres (mots de passe masqués)
- PATCH /settings/          → mettre à jour (partiel, deep-merge)
- POST /settings/test-webhook → tester le webhook configuré
- GET  /settings/next-sync  → prochaine exécution du cron sécurité
"""

import copy
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

import requests as http_requests
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth.dependencies import get_admin_user
from services import scheduler_state
from services.settings import get_settings, update_settings
from services.audit import log as audit_log

logger = logging.getLogger("settings_router")

# Répertoire du trousseau GPG partagé entre rpm-repo et backend
GNUPG_HOME = os.getenv("GNUPG_HOME", "/repos/gnupg")

# Champs sensibles à masquer dans les réponses GET /settings
_SENSITIVE_KEYS = {"smtp_password", "bind_password"}
_MASK = "••••••••"


def _mask_secrets(obj: Any) -> Any:
    """Masque récursivement les champs sensibles dans un dict/list."""
    if isinstance(obj, dict):
        return {
            k: _MASK if k in _SENSITIVE_KEYS and obj[k] else _mask_secrets(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_mask_secrets(i) for i in obj]
    return obj


def _strip_masked_secrets(obj: Any) -> Any:
    """Supprime les placeholders masqués pour ne pas écraser les vrais mots de passe."""
    if isinstance(obj, dict):
        return {
            k: _strip_masked_secrets(v)
            for k, v in obj.items()
            if not (k in _SENSITIVE_KEYS and v == _MASK)
        }
    if isinstance(obj, list):
        return [_strip_masked_secrets(i) for i in obj]
    return obj

router = APIRouter(prefix="/settings", tags=["Settings"])


# ─── Lecture ──────────────────────────────────────────────────────────────────

@router.get("/")
def read_settings(current_user: str = Depends(get_admin_user)):
    """Retourne tous les paramètres courants (mots de passe masqués)."""
    return _mask_secrets(get_settings())


# ─── Mise à jour ──────────────────────────────────────────────────────────────

class SettingsPatch(BaseModel):
    app_url:       str | None = None
    sync:          dict[str, Any] | None = None
    sources:       dict[str, Any] | None = None
    notifications: dict[str, Any] | None = None
    email:         dict[str, Any] | None = None
    ldap:          dict[str, Any] | None = None
    retention:     dict[str, Any] | None = None
    validation:    dict[str, Any] | None = None
    cve_policy:    dict[str, Any] | None = None


@router.patch("/")
def patch_settings(
    body: SettingsPatch,
    current_user: str = Depends(get_admin_user),
):
    """
    Met à jour les paramètres par fusion profonde.
    Si les paramètres sync changent, le scheduler est mis à jour immédiatement.
    """
    partial = {k: v for k, v in body.model_dump().items() if v is not None}
    partial = _strip_masked_secrets(partial)
    updated = update_settings(partial)
    audit_log("SETTINGS_CHANGE", current_user, "SUCCESS",
              detail=f"Sections modifiées : {', '.join(partial.keys())}")

    # ── Reschedule à chaud si le cron a changé ─────────────────────────────
    if "sync" in partial and scheduler_state.scheduler is not None:
        sync = updated["sync"]
        try:
            if sync.get("enabled", True):
                scheduler_state.scheduler.reschedule_job(
                    "security_sync_daily",
                    trigger="cron",
                    hour=int(sync["hour"]),
                    minute=int(sync["minute"]),
                )
                logger.info(
                    f"[settings] Cron replanifié → {sync['hour']:02d}:{sync['minute']:02d}"
                )
            else:
                scheduler_state.scheduler.pause_job("security_sync_daily")
                logger.info("[settings] Cron sécurité mis en pause.")
        except Exception as e:
            logger.warning(f"[settings] Impossible de mettre à jour le scheduler : {e}")

    return _mask_secrets(updated)


# ─── Test webhook ─────────────────────────────────────────────────────────────

@router.post("/test-webhook")
def test_webhook(current_user: str = Depends(get_admin_user)):
    """Envoie un message de test au webhook configuré (Slack/Teams/Mattermost)."""
    settings = get_settings()
    url = settings["notifications"].get("webhook_url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Aucune URL webhook configurée.")

    payload = {
        "text": (
            "🔒 *repod — Test de notification*\n"
            "Le webhook est correctement configuré. "
            "Vous recevrez ici les rapports de synchronisation de sécurité APT."
        )
    }
    try:
        resp = http_requests.post(url, json=payload, timeout=5)
        resp.raise_for_status()
        return {"status": "ok", "http_status": resp.status_code}
    except http_requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Timeout : le webhook ne répond pas.")
    except http_requests.exceptions.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Erreur HTTP webhook : {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erreur : {e}")


# ─── GPG ──────────────────────────────────────────────────────────────────────

def _gpg_cmd(args: list[str]) -> list[str]:
    """Préfixe une commande GPG avec --homedir et options batch-safe."""
    return [
        "gpg",
        "--homedir", GNUPG_HOME,
        "--no-default-keyring",
        "--keyring", f"{GNUPG_HOME}/pubring.kbx",
        "--pinentry-mode", "loopback",   # évite le besoin d'un terminal/agent PIN
    ] + args


def _ensure_gnupg_permissions() -> None:
    """S'assure que le homedir GPG a les bons droits (700) pour éviter le warning unsafe ownership."""
    import stat
    path = Path(GNUPG_HOME)
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(stat.S_IRWXU)   # 700 — owner only


@router.get("/gpg")
def get_gpg_info(current_user: str = Depends(get_admin_user)):
    """Retourne les infos de la clé GPG du dépôt (fingerprint, UID, expiration)."""
    try:
        result = subprocess.run(
            _gpg_cmd(["--list-keys", "--with-colons", "--fingerprint"]),
            capture_output=True, text=True, timeout=10,
        )
        keys = []
        current_key: dict = {}
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "pub":
                if current_key:
                    keys.append(current_key)
                current_key = {
                    "type":        "pub",
                    "algo":        parts[3] if len(parts) > 3 else "",
                    "key_id":      parts[4] if len(parts) > 4 else "",
                    "created":     parts[5] if len(parts) > 5 else "",
                    "expires":     parts[6] if len(parts) > 6 else "",
                    "uids":        [],
                    "fingerprint": "",
                }
            elif parts[0] == "fpr" and current_key:
                current_key["fingerprint"] = parts[9] if len(parts) > 9 else ""
            elif parts[0] == "uid" and current_key:
                uid_str = parts[9] if len(parts) > 9 else ""
                if uid_str:
                    current_key["uids"].append(uid_str)
        if current_key:
            keys.append(current_key)

        export = subprocess.run(
            _gpg_cmd(["--armor", "--export"]),
            capture_output=True, text=True, timeout=10,
        )
        return {
            "keys": keys,
            "public_key_armored": export.stdout.strip() if export.returncode == 0 else None,
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="GPG timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gpg/generate")
def generate_gpg_key(current_user: str = Depends(get_admin_user)):
    """Génère une nouvelle paire de clés GPG dans le trousseau partagé."""
    _ensure_gnupg_permissions()
    batch = (
        "%no-protection\n"
        "Key-Type: RSA\n"
        "Key-Length: 4096\n"
        "Subkey-Type: RSA\n"
        "Subkey-Length: 4096\n"
        "Name-Real: Repod APT Repository\n"
        "Name-Email: repod@localhost\n"
        "Expire-Date: 2y\n"
        "%commit\n"
    )
    try:
        env = {**os.environ, "GNUPGHOME": GNUPG_HOME}
        result = subprocess.run(
            _gpg_cmd(["--batch", "--gen-key"]),
            input=batch, capture_output=True, text=True, timeout=120, env=env,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Erreur GPG inconnue"
            raise HTTPException(status_code=500, detail=detail)
        audit_log("GPG_GENERATE", current_user, "SUCCESS", detail="Nouvelle clé GPG générée")
        return {"status": "ok", "message": "Clé GPG générée avec succès. La configuration createrepo_c sera mise à jour au prochain redémarrage."}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Génération GPG timeout (>120s) — le système manque peut-être d'entropie")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── Infos scheduler ──────────────────────────────────────────────────────────

@router.get("/next-sync")
def get_next_sync(current_user: str = Depends(get_admin_user)):
    """Retourne la date/heure de la prochaine sync sécurité planifiée."""
    if scheduler_state.scheduler is None:
        return {"next_run": None, "status": "scheduler_not_started"}

    try:
        job = scheduler_state.scheduler.get_job("security_sync_daily")
        if job is None:
            return {"next_run": None, "status": "job_not_found"}
        if job.next_run_time is None:
            return {"next_run": None, "status": "paused"}
        return {
            "next_run": job.next_run_time.isoformat(),
            "status": "scheduled",
        }
    except Exception as e:
        return {"next_run": None, "status": f"error: {e}"}


# ─── Test LDAP ────────────────────────────────────────────────────────────────

@router.post("/test-ldap")
def test_ldap(current_user: str = Depends(get_admin_user)):
    """Teste la connexion au serveur LDAP configuré."""
    from services.ldap_auth import test_connection
    result = test_connection()
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return {"status": "ok", "message": result["message"], "server_info": result.get("server_info")}


# ─── Rétention manuelle ───────────────────────────────────────────────────────

@router.post("/run-retention")
def run_retention_now(current_user: str = Depends(get_admin_user)):
    """Déclenche immédiatement la politique de rétention (audit logs + vieux paquets)."""
    from services.retention import run_retention
    try:
        result = run_retention()
        return {"status": "ok", "result": result}
    except Exception as e:
        logger.error(f"[retention] Erreur déclenchement manuel : {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Test email ───────────────────────────────────────────────────────────────

class TestEmailPayload(BaseModel):
    to_override: str | None = None

@router.post("/test-email")
def test_email(payload: TestEmailPayload = TestEmailPayload(), current_user: str = Depends(get_admin_user)):
    """Envoie un email de test pour vérifier la configuration SMTP."""
    from services.email_notifications import send_test_email
    result = send_test_email(to_override=payload.to_override)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Échec envoi"))
    return {"status": "ok", "message": "Email de test envoyé"}
