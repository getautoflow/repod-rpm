"""
Module : test_oidc.py
Rôle   : Task 4 [V] — SSO OIDC (Authorization Code + PKCE)
         Vérifie services/oidc_service.py et routers/oidc_router.py

Flow testé :
  1. GET  /api/v1/auth/oidc/public-config   → config publique (pas d'auth)
  2. POST /api/v1/auth/oidc/authorize       → URL d'autorisation IdP + PKCE
  3. POST /api/v1/auth/oidc/callback        → échange code → JWT repod
     · auto-provision si utilisateur inconnu + auto_provision=True
     · 403 si auto_provision=False et utilisateur inconnu

Dépend : pytest, unittest.mock (stdlib)
"""

import os
import sys
import json
import base64
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# ── Isolation des chemins ──────────────────────────────────────────────────────
_backend = Path(__file__).parent.parent
sys.path.insert(0, str(_backend))

import tempfile as _tmp_mod
_TMP = _tmp_mod.mkdtemp(prefix="repod_rpm_oidc_test_")
os.environ["REPOS_PATH"]     = _TMP
os.environ["MANIFESTS_PATH"] = _TMP
os.environ["POOL_PATH"]      = _TMP
os.environ["AUDIT_DIR"]      = os.path.join(_TMP, "audit")
os.environ["AUDIT_LOG_PATH"] = os.path.join(_TMP, "audit.log")
os.environ["SETTINGS_PATH"]  = os.path.join(_TMP, "settings.json")
os.environ["JWT_SECRET_KEY"] = "oidc-test-secret-key-rpm"
os.environ["DB_PATH"]        = os.path.join(_TMP, "users.db")
Path(os.environ["AUDIT_DIR"]).mkdir(parents=True, exist_ok=True)

# ── Fixtures IdP mockées ───────────────────────────────────────────────────────

FAKE_DISCOVERY = {
    "issuer": "https://idp.example.com/realms/test",
    "authorization_endpoint": "https://idp.example.com/realms/test/protocol/openid-connect/auth",
    "token_endpoint": "https://idp.example.com/realms/test/protocol/openid-connect/token",
    "jwks_uri": "https://idp.example.com/realms/test/protocol/openid-connect/certs",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}

FAKE_JWKS = {
    "keys": [{"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
              "n": "test", "e": "AQAB"}]
}

FAKE_CLAIMS = {
    "sub": "user-uuid-1234",
    "preferred_username": "jdupont",
    "email": "jean.dupont@example.com",
    "name": "Jean Dupont",
    "iss": "https://idp.example.com/realms/test",
    "aud": "repod-rpm-client",
    "exp": 9999999999,
    "iat": 1700000000,
}

OIDC_SETTINGS = {
    "enabled": True,
    "provider_name": "Keycloak Test",
    "discovery_url": "https://idp.example.com/realms/test/.well-known/openid-configuration",
    "client_id": "repod-rpm-client",
    "client_secret": "super-secret",
    "scopes": "openid email profile",
    "redirect_uri": "http://localhost:3003/oidc-callback",
    "auto_provision": True,
    "default_role": "reader",
    "claim_username": "preferred_username",
    "claim_email": "email",
    "claim_fullname": "name",
    "claim_role": "",
    "role_map": {},
}


# ══════════════════════════════════════════════════════════════════════════════
# 1. Module services/oidc_service.py
# ══════════════════════════════════════════════════════════════════════════════

class TestOidcServiceModule(unittest.TestCase):
    """services/oidc_service.py doit exister et exporter les symboles attendus."""

    def test_module_exists(self):
        p = Path(__file__).parent.parent / "services" / "oidc_service.py"
        self.assertTrue(p.exists(), "services/oidc_service.py doit être créé (Task 4)")

    def test_oidc_error_importable(self):
        from services.oidc_service import OidcError
        self.assertTrue(issubclass(OidcError, Exception))

    def test_build_authorization_url_importable(self):
        from services.oidc_service import build_authorization_url
        self.assertTrue(callable(build_authorization_url))

    def test_exchange_code_and_get_user_importable(self):
        from services.oidc_service import exchange_code_and_get_user
        self.assertTrue(callable(exchange_code_and_get_user))

    def test_get_oidc_config_importable(self):
        from services.oidc_service import get_oidc_config
        self.assertTrue(callable(get_oidc_config))


class TestBuildAuthorizationUrl(unittest.TestCase):
    """build_authorization_url() construit une URL PKCE valide."""

    def _call(self, code_challenge="abc123", state="state-xyz",
              redirect_uri="http://localhost:3003/oidc-callback"):
        from services.oidc_service import build_authorization_url, _discovery_cache
        _discovery_cache.clear()
        with patch("services.oidc_service.get_oidc_config", return_value=OIDC_SETTINGS), \
             patch("services.oidc_service._fetch_discovery", return_value=FAKE_DISCOVERY):
            return build_authorization_url(code_challenge, state, redirect_uri)

    def test_returns_authorization_endpoint(self):
        url = self._call()
        self.assertIn("https://idp.example.com/realms/test/protocol/openid-connect/auth", url)

    def test_contains_code_challenge(self):
        url = self._call(code_challenge="my_challenge")
        self.assertIn("my_challenge", url)

    def test_contains_s256_method(self):
        url = self._call()
        self.assertIn("S256", url)

    def test_contains_client_id(self):
        url = self._call()
        self.assertIn("repod-rpm-client", url)

    def test_contains_state(self):
        url = self._call(state="random-state-token")
        self.assertIn("random-state-token", url)

    def test_contains_redirect_uri(self):
        url = self._call(redirect_uri="http://localhost:3003/oidc-callback")
        self.assertIn("oidc-callback", url)

    def test_raises_when_disabled(self):
        from services.oidc_service import build_authorization_url, OidcError, _discovery_cache
        _discovery_cache.clear()
        disabled = {**OIDC_SETTINGS, "enabled": False}
        with patch("services.oidc_service.get_oidc_config", return_value=disabled):
            with self.assertRaises(OidcError):
                build_authorization_url("x", "y", "http://cb")


class TestExchangeCodeAndGetUser(unittest.TestCase):
    """exchange_code_and_get_user() valide l'ID token et extrait les claims."""

    def _call(self, claims=None, cfg=None):
        from services.oidc_service import exchange_code_and_get_user, _discovery_cache
        _discovery_cache.clear()
        _claims = claims or FAKE_CLAIMS
        _cfg    = cfg or OIDC_SETTINGS

        fake_tokens = {"id_token": "header.payload.sig", "access_token": "at"}

        with patch("services.oidc_service.get_oidc_config", return_value=_cfg), \
             patch("services.oidc_service._fetch_discovery", return_value=FAKE_DISCOVERY), \
             patch("services.oidc_service._fetch_jwks", return_value=FAKE_JWKS), \
             patch("services.oidc_service._post_token_endpoint", return_value=fake_tokens), \
             patch("services.oidc_service._decode_id_token", return_value=_claims):
            return exchange_code_and_get_user("code-abc", "verifier-xyz",
                                              "http://localhost:3003/oidc-callback")

    def test_returns_username_from_preferred_username(self):
        info = self._call()
        self.assertEqual(info["username"], "jdupont")

    def test_returns_email(self):
        info = self._call()
        self.assertEqual(info["email"], "jean.dupont@example.com")

    def test_returns_full_name(self):
        info = self._call()
        self.assertEqual(info["full_name"], "Jean Dupont")

    def test_returns_default_role_when_no_role_claim(self):
        info = self._call()
        self.assertEqual(info["role"], "reader")

    def test_role_mapped_from_groups_claim(self):
        cfg = {**OIDC_SETTINGS, "claim_role": "groups",
               "role_map": {"admins": "admin", "maintainers": "maintainer"}}
        claims = {**FAKE_CLAIMS, "groups": ["maintainers"]}
        info = self._call(claims=claims, cfg=cfg)
        self.assertEqual(info["role"], "maintainer")

    def test_role_map_first_match_wins(self):
        cfg = {**OIDC_SETTINGS, "claim_role": "groups",
               "role_map": {"admins": "admin", "maintainers": "maintainer"}}
        claims = {**FAKE_CLAIMS, "groups": ["admins", "maintainers"]}
        info = self._call(claims=claims, cfg=cfg)
        self.assertEqual(info["role"], "admin")

    def test_missing_username_raises_oidc_error(self):
        from services.oidc_service import OidcError
        claims = {**FAKE_CLAIMS, "preferred_username": None, "sub": ""}
        with self.assertRaises(OidcError):
            self._call(claims=claims)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Router routers/oidc_router.py — présence des endpoints
# ══════════════════════════════════════════════════════════════════════════════

class TestOidcRouterEndpoints(unittest.TestCase):
    """Les endpoints OIDC doivent être déclarés dans oidc_router.py."""

    def _src(self):
        p = Path(__file__).parent.parent / "routers" / "oidc_router.py"
        return p.read_text(encoding="utf-8") if p.exists() else ""

    def test_router_exists(self):
        p = Path(__file__).parent.parent / "routers" / "oidc_router.py"
        self.assertTrue(p.exists(), "routers/oidc_router.py doit être créé (Task 4)")

    def test_public_config_endpoint(self):
        self.assertIn("/public-config", self._src())

    def test_authorize_endpoint(self):
        self.assertIn("/authorize", self._src())

    def test_callback_endpoint(self):
        self.assertIn("/callback", self._src())

    def test_no_auth_on_public_config(self):
        self.assertIn("public-config", self._src())

    def test_oidc_error_handled(self):
        self.assertIn("OidcError", self._src())


# ══════════════════════════════════════════════════════════════════════════════
# 3. DEFAULT_SETTINGS contient la section oidc
# ══════════════════════════════════════════════════════════════════════════════

class TestOidcDefaultSettings(unittest.TestCase):

    def test_oidc_section_in_defaults(self):
        from services.settings import DEFAULT_SETTINGS
        self.assertIn("oidc", DEFAULT_SETTINGS)

    def test_oidc_enabled_false_by_default(self):
        from services.settings import DEFAULT_SETTINGS
        self.assertFalse(DEFAULT_SETTINGS["oidc"]["enabled"])

    def test_oidc_has_discovery_url(self):
        from services.settings import DEFAULT_SETTINGS
        self.assertIn("discovery_url", DEFAULT_SETTINGS["oidc"])

    def test_oidc_has_client_id(self):
        from services.settings import DEFAULT_SETTINGS
        self.assertIn("client_id", DEFAULT_SETTINGS["oidc"])

    def test_oidc_has_auto_provision(self):
        from services.settings import DEFAULT_SETTINGS
        self.assertIn("auto_provision", DEFAULT_SETTINGS["oidc"])

    def test_oidc_has_claim_mappings(self):
        from services.settings import DEFAULT_SETTINGS
        oidc = DEFAULT_SETTINGS["oidc"]
        for field in ("claim_username", "claim_email", "claim_fullname"):
            self.assertIn(field, oidc)


# ══════════════════════════════════════════════════════════════════════════════
# 4. main.py enregistre le router OIDC
# ══════════════════════════════════════════════════════════════════════════════

class TestOidcRouterRegistered(unittest.TestCase):

    def _main_src(self):
        return (Path(__file__).parent.parent / "main.py").read_text(encoding="utf-8")

    def test_oidc_router_imported_in_main(self):
        self.assertIn("oidc_router", self._main_src())

    def test_oidc_router_included_in_main(self):
        self.assertIn("oidc_router", self._main_src())


# ══════════════════════════════════════════════════════════════════════════════
# 5. Import réel du router
# ══════════════════════════════════════════════════════════════════════════════

class TestOidcRouterImportable(unittest.TestCase):

    def test_router_importable_without_error(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "oidc_router_check",
            Path(__file__).parent.parent / "routers" / "oidc_router.py",
        )
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as exc:
            self.fail(f"routers/oidc_router.py ne s'importe pas : {exc}")

    def test_router_has_correct_routes(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "oidc_router_routes",
            Path(__file__).parent.parent / "routers" / "oidc_router.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        paths = [r.path for r in mod.router.routes]
        for expected in [
            "/auth/oidc/public-config",
            "/auth/oidc/authorize",
            "/auth/oidc/callback",
            "/auth/oidc/test-discovery",
        ]:
            self.assertIn(expected, paths,
                f"Route '{expected}' manquante (routes trouvées: {paths})")

    def test_auth_source_oidc_in_router(self):
        src = (Path(__file__).parent.parent / "routers" / "oidc_router.py").read_text()
        self.assertIn('auth_source="oidc"', src)

    def test_audit_import_correct(self):
        src = (Path(__file__).parent.parent / "routers" / "oidc_router.py").read_text()
        self.assertNotIn("from utils.audit", src)
        self.assertIn("services.audit", src)


# ══════════════════════════════════════════════════════════════════════════════
# 6. Tests HTTP via TestClient
# ══════════════════════════════════════════════════════════════════════════════

class TestOidcHttpEndpoints(unittest.TestCase):

    def _load_module(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "oidc_router_http",
            Path(__file__).parent.parent / "routers" / "oidc_router.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _make_client(self, mod):
        from fastapi import FastAPI
        from starlette.testclient import TestClient
        app = FastAPI()
        app.include_router(mod.router, prefix="/api/v1")
        return TestClient(app, raise_server_exceptions=False)

    def test_public_config_disabled_returns_enabled_false(self):
        mod = self._load_module()
        client = self._make_client(mod)
        with patch.object(mod, 'get_oidc_config', return_value={"enabled": False}):
            resp = client.get("/api/v1/auth/oidc/public-config")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["enabled"])

    def test_public_config_enabled_returns_provider_name(self):
        mod = self._load_module()
        client = self._make_client(mod)
        cfg = {**OIDC_SETTINGS, "provider_name": "Keycloak"}
        with patch.object(mod, 'get_oidc_config', return_value=cfg):
            resp = client.get("/api/v1/auth/oidc/public-config")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["enabled"])
        self.assertEqual(data["provider_name"], "Keycloak")

    def test_authorize_disabled_returns_400(self):
        mod = self._load_module()
        client = self._make_client(mod)
        with patch.object(mod, 'is_enabled', return_value=False):
            resp = client.post("/api/v1/auth/oidc/authorize", json={
                "code_challenge": "abc", "state": "xyz"
            })
        self.assertEqual(resp.status_code, 400)

    def test_authorize_enabled_returns_authorization_url(self):
        mod = self._load_module()
        client = self._make_client(mod)
        fake_url = "https://idp.example.com/auth?response_type=code&..."
        with patch.object(mod, 'is_enabled', return_value=True), \
             patch.object(mod, 'build_authorization_url', return_value=fake_url), \
             patch.object(mod, '_effective_redirect_uri',
                          return_value="http://localhost:3003/oidc-callback"):
            resp = client.post("/api/v1/auth/oidc/authorize", json={
                "code_challenge": "ch4ll3ng3",
                "state": "r4nd0m_st4t3",
                "redirect_uri": "http://localhost:3003/oidc-callback",
            })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("authorization_url", resp.json())

    def test_callback_disabled_returns_400(self):
        mod = self._load_module()
        client = self._make_client(mod)
        with patch.object(mod, 'is_enabled', return_value=False):
            resp = client.post("/api/v1/auth/oidc/callback", json={
                "code": "c", "state": "s", "code_verifier": "v"
            })
        self.assertEqual(resp.status_code, 400)

    def test_callback_valid_code_returns_access_token(self):
        mod = self._load_module()
        client = self._make_client(mod)
        user_info = {
            "username": "jdupont", "email": "j@example.com",
            "full_name": "Jean Dupont", "role": "reader",
            "sub": "uuid-123", "iss": "https://idp.example.com",
        }
        fake_user = {"username": "jdupont", "role": "reader", "active": True}
        with patch.object(mod, 'is_enabled', return_value=True), \
             patch.object(mod, 'get_oidc_config', return_value=OIDC_SETTINGS), \
             patch.object(mod, 'exchange_code_and_get_user', return_value=user_info), \
             patch.object(mod, 'get_user_any', return_value=fake_user), \
             patch.object(mod, 'audit_log'):
            resp = client.post("/api/v1/auth/oidc/callback", json={
                "code": "auth-code-xyz", "state": "state-abc",
                "code_verifier": "verifier-xyz",
                "redirect_uri": "http://localhost:3003/oidc-callback",
            })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")

    def test_callback_auto_provision_creates_user_with_oidc_source(self):
        mod = self._load_module()
        client = self._make_client(mod)
        user_info = {
            "username": "newuser", "email": "new@example.com",
            "full_name": "New User", "role": "reader",
            "sub": "new-uuid", "iss": "https://idp.example.com",
        }
        provisioned_user = {"username": "newuser", "role": "reader", "active": True}
        with patch.object(mod, 'is_enabled', return_value=True), \
             patch.object(mod, 'get_oidc_config',
                          return_value={**OIDC_SETTINGS, "auto_provision": True}), \
             patch.object(mod, 'exchange_code_and_get_user', return_value=user_info), \
             patch.object(mod, 'get_user_any', side_effect=[None, provisioned_user]), \
             patch.object(mod, 'create_user') as mock_create, \
             patch.object(mod, 'audit_log'):
            resp = client.post("/api/v1/auth/oidc/callback", json={
                "code": "code", "state": "state", "code_verifier": "verifier"
            })
        self.assertEqual(resp.status_code, 200)
        create_kwargs = mock_create.call_args.kwargs
        self.assertEqual(create_kwargs.get("auth_source"), "oidc")

    def test_callback_no_auto_provision_returns_403(self):
        mod = self._load_module()
        client = self._make_client(mod)
        user_info = {
            "username": "unknown", "email": "", "full_name": "",
            "role": "reader", "sub": "u", "iss": "https://idp.example.com",
        }
        with patch.object(mod, 'is_enabled', return_value=True), \
             patch.object(mod, 'get_oidc_config',
                          return_value={**OIDC_SETTINGS, "auto_provision": False}), \
             patch.object(mod, 'exchange_code_and_get_user', return_value=user_info), \
             patch.object(mod, 'get_user_any', return_value=None):
            resp = client.post("/api/v1/auth/oidc/callback", json={
                "code": "c", "state": "s", "code_verifier": "v"
            })
        self.assertEqual(resp.status_code, 403)

    def test_callback_inactive_user_returns_403(self):
        mod = self._load_module()
        client = self._make_client(mod)
        user_info = {
            "username": "inactive", "email": "", "full_name": "",
            "role": "reader", "sub": "u", "iss": "https://idp.example.com",
        }
        inactive_user = {"username": "inactive", "role": "reader", "active": False}
        with patch.object(mod, 'is_enabled', return_value=True), \
             patch.object(mod, 'get_oidc_config', return_value=OIDC_SETTINGS), \
             patch.object(mod, 'exchange_code_and_get_user', return_value=user_info), \
             patch.object(mod, 'get_user_any', return_value=inactive_user):
            resp = client.post("/api/v1/auth/oidc/callback", json={
                "code": "c", "state": "s", "code_verifier": "v"
            })
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
