"""
Router SSO OIDC — Authorization Code + PKCE
Endpoints (tous sous /api/v1/auth/oidc/) :

  GET  /public-config   → config publique pour la page de login (sans auth)
  POST /authorize       → retourne l'URL d'autorisation IdP
  POST /callback        → échange code → JWT repod-rpm (+ auto-provision)
  POST /test-discovery  → teste le discovery endpoint (utilisateur connecté)
"""

import secrets as _secrets
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from services.oidc_service import (
    get_oidc_config, is_enabled,
    build_authorization_url, exchange_code_and_get_user,
    test_discovery, OidcError,
)
from services.settings import get_settings
from auth.jwt import create_access_token
from auth.users import get_user_any, create_user
from auth.dependencies import get_current_user_full
from services.audit import log as audit_log

router = APIRouter(prefix="/auth/oidc", tags=["SSO OIDC"])


def _effective_redirect_uri(provided: str = "") -> str:
    """Calcule le redirect_uri : fourni > settings.oidc.redirect_uri > app_url + /oidc-callback."""
    if provided:
        return provided
    cfg = get_oidc_config()
    if cfg.get("redirect_uri"):
        return cfg["redirect_uri"]
    base = get_settings().get("app_url", "http://localhost:3003").rstrip("/")
    return f"{base}/oidc-callback"


# ── Endpoint public — config de login ─────────────────────────────────────────

@router.get("/public-config")
def oidc_public_config():
    """
    Retourne la configuration OIDC publique pour la page de login.
    Pas d'authentification requise — appelé avant le login.
    """
    cfg = get_oidc_config()
    if not cfg.get("enabled"):
        return {"enabled": False}
    return {
        "enabled":       True,
        "provider_name": cfg.get("provider_name", "SSO"),
    }


# ── Étape 1 du flow : obtenir l'URL d'autorisation ────────────────────────────

class AuthorizeRequest(BaseModel):
    code_challenge: str   # SHA-256(code_verifier) base64url, généré côté frontend
    state: str            # Random nonce, vérifié côté frontend sur le callback
    redirect_uri: str = ""


@router.post("/authorize")
def oidc_authorize(body: AuthorizeRequest):
    """
    Retourne l'URL d'autorisation IdP pour démarrer le flow PKCE.
    Le frontend redirige l'utilisateur vers cette URL.
    """
    if not is_enabled():
        raise HTTPException(status_code=400, detail="SSO OIDC non activé")
    try:
        redirect_uri = _effective_redirect_uri(body.redirect_uri)
        url = build_authorization_url(body.code_challenge, body.state, redirect_uri)
        return {"authorization_url": url, "redirect_uri": redirect_uri}
    except OidcError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


# ── Étape 2 du flow : callback — échange code → JWT repod-rpm ─────────────────

class CallbackRequest(BaseModel):
    code:          str    # Code d'autorisation reçu de l'IdP
    state:         str    # State (vérifié par le frontend, transmis pour audit)
    code_verifier: str    # Secret PKCE, doit correspondre au code_challenge envoyé
    redirect_uri:  str = ""


@router.post("/callback")
def oidc_callback(body: CallbackRequest):
    """
    Échange le code d'autorisation OIDC contre un JWT repod-rpm.

    Si l'utilisateur n'existe pas et que auto_provision=True, il est créé
    automatiquement avec un mot de passe aléatoire inutilisable (connexion SSO only).
    """
    if not is_enabled():
        raise HTTPException(status_code=400, detail="SSO OIDC non activé")

    redirect_uri = _effective_redirect_uri(body.redirect_uri)

    try:
        user_info = exchange_code_and_get_user(body.code, body.code_verifier, redirect_uri)
    except OidcError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    username = user_info["username"]
    cfg      = get_oidc_config()

    # ── Récupère ou provisionne l'utilisateur ──────────────────────────────────
    user = get_user_any(username)

    if not user:
        if not cfg.get("auto_provision", True):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Utilisateur '{username}' inconnu. "
                    "L'auto-provisioning SSO est désactivé — contactez votre administrateur."
                ),
            )
        # Mot de passe aléatoire fort — inutilisable en login local, SSO only
        create_user(
            username=username,
            password=_secrets.token_urlsafe(32),
            role=user_info["role"],
            full_name=user_info.get("full_name", ""),
            email=user_info.get("email", ""),
            auth_source="oidc",
        )
        user = get_user_any(username)
        audit_log(
            "OIDC_PROVISION", username, "SUCCESS",
            extra={"role": user_info["role"], "iss": user_info.get("iss", "")},
        )

    if not user or not user.get("active"):
        raise HTTPException(status_code=403, detail="Compte désactivé.")

    # ── Émet le JWT repod-rpm ──────────────────────────────────────────────────
    token = create_access_token({
        "sub":  username,
        "role": user["role"],
    })
    audit_log("OIDC_LOGIN", username, "SUCCESS",
              extra={"iss": user_info.get("iss", "")})

    return {"access_token": token, "token_type": "bearer"}


# ── Endpoint : tester la connexion IdP ────────────────────────────────────────

class TestDiscoveryRequest(BaseModel):
    discovery_url: str


@router.post("/test-discovery")
def oidc_test_discovery(
    body: TestDiscoveryRequest,
    _current_user: dict = Depends(get_current_user_full),
):
    """
    Teste l'accessibilité du discovery endpoint et retourne un résumé des
    endpoints détectés. Requiert un JWT repod-rpm valide.
    """
    result = test_discovery(body.discovery_url)
    if not result["ok"]:
        raise HTTPException(status_code=502, detail=result.get("error", "Échec"))
    return result
