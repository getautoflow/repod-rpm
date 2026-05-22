"""
Service SSO OIDC — Authorization Code + PKCE
Compatible : Keycloak, Authentik, Zitadel, Azure AD (Entra ID), Okta, ADFS

Fonctionnement :
  1. build_authorization_url()    → URL IdP avec code_challenge (S256)
  2. exchange_code_and_get_user() → échange code + verifier → claims → user info
     ∟ _fetch_discovery()         → GET /.well-known/openid-configuration (mis en cache 5 min)
     ∟ _post_token_endpoint()     → POST token_endpoint (échange code)
     ∟ _fetch_jwks()              → GET jwks_uri
     ∟ _decode_id_token()         → validation JWT via JWKS

Les fonctions _fetch_discovery, _post_token_endpoint, _fetch_jwks et _decode_id_token
sont exposées séparément pour faciliter le mock dans les tests.
"""

import time
from typing import Optional
from urllib.parse import urlencode

import requests
from jose import jwt as jose_jwt, JWTError

from services.settings import get_settings

# ── Cache discovery (TTL 5 min) ───────────────────────────────────────────────
_discovery_cache: dict = {}   # url → {"doc": dict, "fetched_at": float}
_CACHE_TTL = 300


class OidcError(Exception):
    """Erreur OIDC métier — convertie en HTTPException dans le router."""


# ── Accesseurs mockables ──────────────────────────────────────────────────────

def _fetch_discovery(discovery_url: str) -> dict:
    """GET du document OpenID Connect Discovery (avec cache TTL)."""
    now = time.monotonic()
    cached = _discovery_cache.get(discovery_url)
    if cached and (now - cached["fetched_at"]) < _CACHE_TTL:
        return cached["doc"]
    try:
        r = requests.get(discovery_url, timeout=10, verify=True)
        r.raise_for_status()
        doc = r.json()
    except requests.RequestException as exc:
        raise OidcError(f"Discovery endpoint inaccessible : {exc}") from exc
    _discovery_cache[discovery_url] = {"doc": doc, "fetched_at": now}
    return doc


def _fetch_jwks(jwks_uri: str) -> dict:
    """GET du JWKS (JSON Web Key Set) de l'IdP."""
    try:
        r = requests.get(jwks_uri, timeout=10, verify=True)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as exc:
        raise OidcError(f"Impossible de récupérer les JWKS : {exc}") from exc


def _post_token_endpoint(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    code: str,
    code_verifier: str,
    redirect_uri: str,
) -> dict:
    """POST vers le token endpoint de l'IdP pour échanger le code."""
    try:
        r = requests.post(
            token_endpoint,
            data={
                "grant_type":    "authorization_code",
                "client_id":     client_id,
                "client_secret": client_secret,
                "code":          code,
                "code_verifier": code_verifier,
                "redirect_uri":  redirect_uri,
            },
            timeout=15,
            verify=True,
        )
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as exc:
        body = exc.response.text if exc.response else str(exc)
        raise OidcError(f"Token endpoint a refusé le code : {body}") from exc
    except requests.RequestException as exc:
        raise OidcError(f"Erreur réseau token endpoint : {exc}") from exc


def _decode_id_token(id_token: str, jwks: dict, audience: str, issuer: str) -> dict:
    """Valide et décode l'ID token JWT avec le JWKS de l'IdP."""
    try:
        return jose_jwt.decode(
            id_token,
            jwks,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=audience,
            issuer=issuer,
            options={"verify_at_hash": False},  # at_hash optionnel selon les IdP
        )
    except JWTError as exc:
        raise OidcError(f"ID token invalide ou expiré : {exc}") from exc


# ── API publique ──────────────────────────────────────────────────────────────

def get_oidc_config() -> dict:
    """Retourne la section oidc des settings."""
    return get_settings().get("oidc", {})


def is_enabled() -> bool:
    return bool(get_oidc_config().get("enabled"))


def build_authorization_url(
    code_challenge: str,
    state: str,
    redirect_uri: str,
) -> str:
    """
    Construit l'URL d'autorisation OIDC avec PKCE (code_challenge_method=S256).
    Le code_verifier est généré côté frontend (SPA pattern recommandé par RFC 7636).

    Compatible : Keycloak, Authentik, Zitadel, Azure AD, Okta, ADFS.
    """
    cfg = get_oidc_config()
    if not cfg.get("enabled"):
        raise OidcError("SSO OIDC non activé dans les paramètres")

    discovery_url = cfg.get("discovery_url", "")
    if not discovery_url:
        raise OidcError("discovery_url non configuré")

    doc = _fetch_discovery(discovery_url)
    auth_endpoint = doc.get("authorization_endpoint")
    if not auth_endpoint:
        raise OidcError("authorization_endpoint absent du document discovery")

    params = {
        "response_type":         "code",
        "client_id":             cfg["client_id"],
        "redirect_uri":          redirect_uri,
        "scope":                 cfg.get("scopes", "openid email profile"),
        "state":                 state,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{auth_endpoint}?{urlencode(params)}"


def exchange_code_and_get_user(
    code: str,
    code_verifier: str,
    redirect_uri: str,
) -> dict:
    """
    Échange le code d'autorisation contre un ID token, le valide via JWKS,
    et retourne les informations utilisateur extraites des claims.

    Retourne :
      {"username", "email", "full_name", "role", "sub", "iss"}
    """
    cfg = get_oidc_config()
    if not cfg.get("enabled"):
        raise OidcError("SSO OIDC non activé")

    discovery_url = cfg.get("discovery_url", "")
    doc = _fetch_discovery(discovery_url)

    token_endpoint = doc.get("token_endpoint")
    jwks_uri       = doc.get("jwks_uri")
    issuer         = doc.get("issuer", "")
    client_id      = cfg.get("client_id", "")
    client_secret  = cfg.get("client_secret", "")

    # 1. Échange code → tokens
    tokens = _post_token_endpoint(
        token_endpoint, client_id, client_secret,
        code, code_verifier, redirect_uri,
    )

    id_token = tokens.get("id_token")
    if not id_token:
        raise OidcError("Pas d'ID token dans la réponse de l'IdP")

    # 2. Validation cryptographique via JWKS
    jwks   = _fetch_jwks(jwks_uri)
    claims = _decode_id_token(id_token, jwks, client_id, issuer)

    # 3. Extraction des claims → profil utilisateur
    claim_username = cfg.get("claim_username", "preferred_username")
    claim_email    = cfg.get("claim_email",    "email")
    claim_fullname = cfg.get("claim_fullname", "name")
    claim_role     = cfg.get("claim_role",     "")
    role_map       = cfg.get("role_map",       {})

    username = claims.get(claim_username) or claims.get("sub", "")
    if not username:
        raise OidcError(
            f"Impossible de déterminer le nom d'utilisateur "
            f"(claim '{claim_username}' absent des claims IdP)"
        )

    # 4. Résolution du rôle repod-rpm
    role = cfg.get("default_role", "reader")
    if claim_role and role_map:
        idp_role_value = claims.get(claim_role, "")
        # Le claim peut être une liste (groupes) ou une string
        candidates = idp_role_value if isinstance(idp_role_value, list) else [idp_role_value]
        for candidate in candidates:
            if candidate in role_map:
                role = role_map[candidate]
                break

    return {
        "username":  username,
        "email":     claims.get(claim_email,    ""),
        "full_name": claims.get(claim_fullname, ""),
        "role":      role,
        "sub":       claims.get("sub",  ""),
        "iss":       claims.get("iss",  ""),
    }


def test_discovery(discovery_url: str) -> dict:
    """
    Teste l'accessibilité du discovery endpoint et retourne un résumé.
    Utilisé par le bouton "Tester la connexion" dans les paramètres.
    """
    _discovery_cache.clear()
    try:
        doc = _fetch_discovery(discovery_url)
        return {
            "ok":       True,
            "issuer":   doc.get("issuer", "—"),
            "auth_ep":  doc.get("authorization_endpoint", "—"),
            "token_ep": doc.get("token_endpoint", "—"),
            "jwks_uri": doc.get("jwks_uri", "—"),
        }
    except OidcError as exc:
        return {"ok": False, "error": str(exc)}
