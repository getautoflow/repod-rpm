"""
Module : test_api_integration.py
Rôle   : Tests d'intégration API — endpoints HTTP réels via FastAPI TestClient + httpx.
         Teste le pipeline complet : auth JWT → endpoint → réponse HTTP.

Couverture :
  • Health   GET /health  /health/live  /health/ready
  • Auth     POST /api/v1/auth/token · GET /me · barrières 401/403
  • Packages GET /api/v1/packages/
  • Upload   POST /api/v1/upload/  (validation mockée)
  • Security GET /api/v1/security/vulnerabilities  /packages-posture
  • Dashboard GET /api/v1/dashboard/stats
  • Settings  GET /api/v1/settings/  PATCH /api/v1/settings/
  • Distributions GET /api/v1/distributions/
  • SBOM     GET /api/v1/sbom/export  /sarif
  • Downloads GET /api/v1/downloads/stats
  • Webhooks POST /webhooks/github  /webhooks/kev

Dépend : pytest, httpx, fastapi[testclient]
"""

# ── Env + chemins temporaires AVANT tout import de l'app ─────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_integration_")

os.environ["MANIFEST_DIR"]        = f"{_TMP}/manifests"
os.environ["POOL_DIR"]            = f"{_TMP}/pool"
os.environ["STAGING_INCOMING"]    = f"{_TMP}/staging/incoming"
os.environ["STAGING_QUARANTINE"]  = f"{_TMP}/staging/quarantine"
os.environ["AUDIT_DIR"]           = f"{_TMP}/audit"
os.environ["INDEX_PATH"]          = f"{_TMP}/manifests/index.json"
os.environ["AUTH_DB_PATH"]        = f"{_TMP}/auth/users.db"
os.environ["SETTINGS_PATH"]       = f"{_TMP}/settings.json"
os.environ["SECURITY_CACHE_DIR"]  = f"{_TMP}/security"
os.environ["SECURITY_DIR"]        = f"{_TMP}/security"
os.environ["NGINX_LOGS_DIR"]      = f"{_TMP}/logs"
os.environ["GNUPG_HOME"]          = f"{_TMP}/gnupg"
os.environ["REPO_BASE"]           = _TMP
os.environ["GRYPE_DB_CACHE_DIR"]  = f"{_TMP}/grype-db"
os.environ["INDEX_DIR"]           = f"{_TMP}/package-index"
os.environ["JWT_SECRET_KEY"]      = "test-secret-key-integration-32chars!!"
os.environ["WEBHOOK_SECRET"]      = "repod-test-webhook-secret-integration"
os.environ["ENV"]                 = "test"

# Créer les répertoires nécessaires
from pathlib import Path
for _d in ["manifests", "pool", "staging/incoming", "staging/quarantine",
           "audit", "auth", "security", "logs", "gnupg", "grype-db",
           "package-index"]:
    Path(f"{_TMP}/{_d}").mkdir(parents=True, exist_ok=True)

# ── Imports normaux ───────────────────────────────────────────────────────────
import io
import json
import hmac
import hashlib
import shutil
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

# ── Import de l'app APRÈS la config des env vars ─────────────────────────────
from main import app
from auth.users import hash_password, AUTH_DB_PATH
import sqlite3

# Forcer les chemins module-level qui peuvent avoir été figés avant nos env vars
# (si d'autres tests ont importé ces modules en premier lors de la collecte pytest)
import services.settings as _settings_mod
import services.indexer  as _indexer_mod
import services.audit    as _audit_mod
import services.manifest as _manifest_mod
import services.security_decisions as _sec_dec_mod
import services.cve_enrichment     as _cve_enrich_mod
import services.package_index      as _pkg_idx_mod

_settings_mod.SETTINGS_PATH  = Path(os.environ["SETTINGS_PATH"])
_indexer_mod.INDEX_PATH       = Path(os.environ["INDEX_PATH"])
_audit_mod.AUDIT_DIR          = Path(os.environ["AUDIT_DIR"])
_manifest_mod.MANIFEST_DIR    = Path(os.environ["MANIFEST_DIR"])
_sec_dec_mod.DECISIONS_DIR    = Path(os.environ["SECURITY_CACHE_DIR"]) / "decisions"
_cve_enrich_mod.SECURITY_CACHE_DIR = Path(os.environ["SECURITY_CACHE_DIR"])
_pkg_idx_mod.INDEX_DIR        = Path(os.environ["INDEX_DIR"])

# Recréer les répertoires si nécessaire (les modules les créent à l'import)
for _p in [
    _settings_mod.SETTINGS_PATH.parent,
    _indexer_mod.INDEX_PATH.parent,
    _audit_mod.AUDIT_DIR,
    _manifest_mod.MANIFEST_DIR,
    _sec_dec_mod.DECISIONS_DIR,
    _cve_enrich_mod.SECURITY_CACHE_DIR,
    _pkg_idx_mod.INDEX_DIR,
]:
    _p.mkdir(parents=True, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _init_db_admin(password: str = "Admin123!") -> None:
    """Crée un utilisateur admin dans la DB de test."""
    AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(AUTH_DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'reader',
            full_name TEXT DEFAULT '',
            email TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            created_at TEXT,
            last_login TEXT,
            auth_source TEXT DEFAULT 'local',
            mfa_enabled INTEGER DEFAULT 0,
            totp_secret TEXT,
            totp_pending_secret TEXT
        )
    """)
    conn.execute(
        "INSERT OR REPLACE INTO users (username, hashed_password, role, created_at) "
        "VALUES (?, ?, 'admin', datetime('now'))",
        ("admin", hash_password(password)),
    )
    conn.execute(
        "INSERT OR REPLACE INTO users (username, hashed_password, role, created_at) "
        "VALUES (?, ?, 'reader', datetime('now'))",
        ("reader_user", hash_password("Reader123!")),
    )
    conn.commit()
    conn.close()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    """TestClient FastAPI — une seule instance pour tout le module.

    On mocke auto_init_distributions pour éviter l'appel à createrepo_c
    (non installé hors Docker) lors du démarrage de l'application.
    """
    _init_db_admin()
    with patch("main.auto_init_distributions", return_value=False):
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c


@pytest.fixture(scope="module")
def admin_token(client):
    """JWT admin valide."""
    r = client.post("/api/v1/auth/token",
                    json={"username": "admin", "password": "Admin123!"})
    assert r.status_code == 200, f"Login admin échoué : {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def reader_token(client):
    """JWT reader valide."""
    r = client.post("/api/v1/auth/token",
                    json={"username": "reader_user", "password": "Reader123!"})
    assert r.status_code == 200, f"Login reader échoué : {r.text}"
    return r.json()["access_token"]


def auth(token: str) -> dict:
    """Header Authorization Bearer."""
    return {"Authorization": f"Bearer {token}"}


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Health — aucune auth requise
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealth:

    def test_health_root_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        # L'API retourne "healthy" ou "degraded" (pas "ok")
        assert r.json()["status"] in ("healthy", "degraded")

    def test_health_live_200(self, client):
        r = client.get("/health/live")
        assert r.status_code == 200
        # La liveness probe retourne {"alive": True}
        assert r.json().get("alive") is True

    def test_health_ready_200(self, client):
        r = client.get("/health/ready")
        # 200 si volumes OK, 503 si volumes absents (hors Docker)
        assert r.status_code in (200, 503)
        # Succès → {"ready": True} ; échec → {"detail": "Volumes not ready"}
        body = r.json()
        assert "ready" in body or "detail" in body

    def test_health_returns_json(self, client):
        r = client.get("/health")
        assert r.headers["content-type"].startswith("application/json")

    def test_metrics_endpoint_accessible(self, client):
        r = client.get("/metrics")
        assert r.status_code == 200
        assert "repod" in r.text or "python" in r.text


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Auth — login, me, barrières
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuth:

    def test_login_admin_returns_token(self, client):
        r = client.post("/api/v1/auth/token",
                        json={"username": "admin", "password": "Admin123!"})
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password_401(self, client):
        r = client.post("/api/v1/auth/token",
                        json={"username": "admin", "password": "mauvais"})
        assert r.status_code == 401

    def test_login_unknown_user_401(self, client):
        r = client.post("/api/v1/auth/token",
                        json={"username": "nobody", "password": "x"})
        assert r.status_code == 401

    def test_me_returns_current_user(self, client, admin_token):
        r = client.get("/api/v1/auth/me", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    def test_me_without_token_401(self, client):
        r = client.get("/api/v1/auth/me")
        assert r.status_code == 401

    def test_me_with_invalid_token_401(self, client):
        r = client.get("/api/v1/auth/me",
                       headers={"Authorization": "Bearer token.invalide.xyz"})
        assert r.status_code == 401

    def test_list_users_admin_only(self, client, admin_token, reader_token):
        assert client.get("/api/v1/auth/users",
                          headers=auth(admin_token)).status_code == 200
        assert client.get("/api/v1/auth/users",
                          headers=auth(reader_token)).status_code == 403

    def test_roles_endpoint(self, client, admin_token):
        r = client.get("/api/v1/auth/roles", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        # L'API retourne {"roles": {"admin": {...}, "reader": {...}, ...}}
        roles = data.get("roles", data)
        assert "admin" in roles
        assert "reader" in roles

    def test_create_and_delete_user(self, client, admin_token):
        r = client.post("/api/v1/auth/users",
                        json={"username": "tmp_user", "password": "Tmp123!X",
                              "role": "reader"},
                        headers=auth(admin_token))
        assert r.status_code == 201
        r2 = client.delete("/api/v1/auth/users/tmp_user",
                           headers=auth(admin_token))
        assert r2.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Packages
# ═══════════════════════════════════════════════════════════════════════════════

class TestPackages:

    def test_list_packages_authenticated(self, client, reader_token):
        r = client.get("/api/v1/packages/", headers=auth(reader_token))
        assert r.status_code == 200
        data = r.json()
        assert "packages" in data or isinstance(data, list)

    def test_list_packages_no_auth_401(self, client):
        r = client.get("/api/v1/packages/")
        assert r.status_code == 401

    def test_packages_response_is_json(self, client, reader_token):
        r = client.get("/api/v1/packages/", headers=auth(reader_token))
        assert r.headers["content-type"].startswith("application/json")

    def test_packages_pagination_params(self, client, reader_token):
        r = client.get("/api/v1/packages/?page=1&per_page=10",
                       headers=auth(reader_token))
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Upload
# ═══════════════════════════════════════════════════════════════════════════════

class TestUpload:

    def _fake_rpm_bytes(self) -> bytes:
        """En-tête RPM minimale (magic bytes) — suffit pour déclencher le pipeline."""
        return b"\xed\xab\xee\xdb" + b"\x00" * 96

    def test_upload_no_auth_401(self, client):
        r = client.post("/api/v1/upload/",
                        files={"file": ("test.rpm", self._fake_rpm_bytes(), "application/x-rpm")},
                        data={"distribution": "almalinux8"})
        assert r.status_code == 401

    def test_upload_wrong_extension_400(self, client, admin_token):
        r = client.post("/api/v1/upload/",
                        files={"file": ("test.deb", b"not an rpm", "application/x-deb")},
                        data={"distribution": "almalinux8"},
                        headers=auth(admin_token))
        assert r.status_code == 400
        assert "rpm" in r.json()["detail"].lower()

    def test_upload_invalid_distribution_400(self, client, admin_token):
        r = client.post("/api/v1/upload/",
                        files={"file": ("test.rpm", self._fake_rpm_bytes(),
                                        "application/x-rpm")},
                        data={"distribution": "ubuntu22"},
                        headers=auth(admin_token))
        assert r.status_code == 400
        assert "distribution" in r.json()["detail"].lower() \
               or "invalide" in r.json()["detail"].lower()

    def test_upload_valid_rpm_goes_through_pipeline(self, client, admin_token):
        """Pipeline complet mockée : validation → quarantaine si format invalide."""
        with patch("routers.upload.run_validation_pipeline") as mock_val, \
             patch("routers.upload.asyncio.to_thread", side_effect=lambda f, *a, **kw: f(*a, **kw)):
            result = MagicMock()
            result.passed = False
            result.steps = [{"name": "format", "passed": False,
                             "message": "Format RPM invalide", "detail": ""}]
            result.cve_status = "approved"
            result.cve_results = []
            result.deps = []
            result.to_dict.return_value = {"passed": False, "steps": result.steps}
            mock_val.return_value = result

            r = client.post(
                "/api/v1/upload/",
                files={"file": ("nginx-1.24.0-1.x86_64.rpm",
                                self._fake_rpm_bytes(), "application/x-rpm")},
                data={"distribution": "almalinux8"},
                headers=auth(admin_token),
            )
        assert r.status_code == 200
        assert r.json()["status"] == "rejected"

    def test_upload_reader_forbidden(self, client, reader_token):
        """Un reader ne peut pas uploader (rôle uploader/admin requis)."""
        r = client.post("/api/v1/upload/",
                        files={"file": ("test.rpm", self._fake_rpm_bytes(),
                                        "application/x-rpm")},
                        data={"distribution": "almalinux8"},
                        headers=auth(reader_token))
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Security
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurity:

    def test_vulnerabilities_authenticated(self, client, reader_token):
        r = client.get("/api/v1/security/vulnerabilities",
                       headers=auth(reader_token))
        assert r.status_code == 200
        data = r.json()
        assert "vulnerabilities" in data or "items" in data or "summary" in data

    def test_vulnerabilities_no_auth_401(self, client):
        r = client.get("/api/v1/security/vulnerabilities")
        assert r.status_code == 401

    def test_vulnerabilities_severity_filter(self, client, reader_token):
        r = client.get("/api/v1/security/vulnerabilities?severity=Critical",
                       headers=auth(reader_token))
        assert r.status_code == 200

    def test_packages_posture_authenticated(self, client, reader_token):
        r = client.get("/api/v1/security/packages-posture",
                       headers=auth(reader_token))
        assert r.status_code == 200

    def test_clamav_status_authenticated(self, client, reader_token):
        r = client.get("/api/v1/security/clamav/status",
                       headers=auth(reader_token))
        assert r.status_code == 200
        data = r.json()
        assert "available" in data
        assert "daemon_running" in data

    def test_security_report_authenticated(self, client, reader_token):
        r = client.get("/api/v1/security/report",
                       headers=auth(reader_token))
        assert r.status_code == 200

    def test_review_queue_authenticated(self, client, reader_token):
        r = client.get("/api/v1/security/review-queue",
                       headers=auth(reader_token))
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Dashboard
# ═══════════════════════════════════════════════════════════════════════════════

class TestDashboard:

    def test_stats_authenticated(self, client, reader_token):
        r = client.get("/api/v1/dashboard/stats", headers=auth(reader_token))
        assert r.status_code == 200
        data = r.json()
        assert "packages" in data
        assert "activity" in data
        assert "clamav" in data

    def test_stats_no_auth_401(self, client):
        r = client.get("/api/v1/dashboard/stats")
        assert r.status_code == 401

    def test_stats_packages_structure(self, client, reader_token):
        r = client.get("/api/v1/dashboard/stats", headers=auth(reader_token))
        pkgs = r.json()["packages"]
        assert "total" in pkgs
        assert "imports_today" in pkgs

    def test_history_endpoint(self, client, reader_token):
        r = client.get("/api/v1/dashboard/history?days=7",
                       headers=auth(reader_token))
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list) or "days" in data or "history" in data


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Settings
# ═══════════════════════════════════════════════════════════════════════════════

class TestSettings:

    def test_get_settings_admin(self, client, admin_token):
        r = client.get("/api/v1/settings/", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert "sync" in data
        assert "email" in data
        assert "cve_policy" in data

    def test_get_settings_reader_forbidden(self, client, reader_token):
        """Les settings sont réservés aux admins — un reader reçoit 403."""
        r = client.get("/api/v1/settings/", headers=auth(reader_token))
        assert r.status_code == 403

    def test_get_settings_no_auth_401(self, client):
        r = client.get("/api/v1/settings/")
        assert r.status_code == 401

    def test_patch_settings_admin(self, client, admin_token):
        r = client.patch("/api/v1/settings/",
                         json={"sync": {"hour": 4, "minute": 30}},
                         headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert data["sync"]["hour"] == 4
        assert data["sync"]["minute"] == 30

    def test_patch_settings_reader_forbidden(self, client, reader_token):
        r = client.patch("/api/v1/settings/",
                         json={"sync": {"hour": 5}},
                         headers=auth(reader_token))
        assert r.status_code == 403

    def test_settings_deep_merge_preserves_other_keys(self, client, admin_token):
        """PATCH partiel ne doit pas effacer les autres sections."""
        before = client.get("/api/v1/settings/",
                            headers=auth(admin_token)).json()
        client.patch("/api/v1/settings/",
                     json={"sync": {"hour": 3}},
                     headers=auth(admin_token))
        after = client.get("/api/v1/settings/",
                           headers=auth(admin_token)).json()
        assert "email" in after
        assert "cve_policy" in after
        assert after["email"] == before["email"]


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Distributions
# ═══════════════════════════════════════════════════════════════════════════════

class TestDistributions:

    def test_list_distributions_authenticated(self, client, reader_token):
        r = client.get("/api/v1/distributions/", headers=auth(reader_token))
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list) or "distributions" in data

    def test_list_distributions_no_auth_401(self, client):
        r = client.get("/api/v1/distributions/")
        assert r.status_code == 401

    def test_known_distributions_present(self, client, reader_token):
        r = client.get("/api/v1/distributions/", headers=auth(reader_token))
        body = r.json()
        names = [d["codename"] if isinstance(d, dict) else d
                 for d in (body if isinstance(body, list)
                           else body.get("distributions", []))]
        # Au moins une distribution RPM connue doit être présente
        known = {"almalinux8", "rocky9", "centos-stream9", "almalinux9"}
        assert known & set(names), f"Aucune distribution connue dans {names}"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. SBOM
# ═══════════════════════════════════════════════════════════════════════════════

class TestSbom:

    def test_sbom_export_authenticated(self, client, reader_token):
        r = client.get("/api/v1/sbom/export", headers=auth(reader_token))
        assert r.status_code == 200

    def test_sbom_export_no_auth_401(self, client):
        r = client.get("/api/v1/sbom/export")
        assert r.status_code == 401

    def test_sbom_sarif_authenticated(self, client, reader_token):
        r = client.get("/api/v1/sbom/sarif", headers=auth(reader_token))
        assert r.status_code == 200
        data = r.json()
        # SARIF 2.1.0 minimal
        assert "version" in data or "$schema" in data or "runs" in data

    def test_sbom_preview_authenticated(self, client, reader_token):
        r = client.get("/api/v1/sbom/preview", headers=auth(reader_token))
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Downloads stats
# ═══════════════════════════════════════════════════════════════════════════════

class TestDownloads:

    def test_downloads_stats_authenticated(self, client, reader_token):
        r = client.get("/api/v1/downloads/stats", headers=auth(reader_token))
        assert r.status_code == 200

    def test_downloads_stats_no_auth_401(self, client):
        r = client.get("/api/v1/downloads/stats")
        assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════════
# 11. Webhooks (HMAC — pas de JWT)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhooks:

    def _sign(self, body: bytes, secret: str) -> str:
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return f"sha256={sig}"

    def test_github_webhook_no_signature_400(self, client):
        r = client.post("/webhooks/github",
                        content=b'{"action":"published"}',
                        headers={"Content-Type": "application/json"})
        # 400 sans signature ; 401 si secret configuré et header manquant
        assert r.status_code in (400, 401, 422)

    def test_github_webhook_wrong_signature_401(self, client):
        body = b'{"action":"published","advisory":{}}'
        r = client.post("/webhooks/github",
                        content=body,
                        headers={
                            "Content-Type": "application/json",
                            "X-Hub-Signature-256": "sha256=aaaa",
                        })
        assert r.status_code in (401, 403)

    def test_kev_webhook_no_signature_400(self, client):
        r = client.post("/webhooks/kev",
                        content=b'{"vulnerabilities":[]}',
                        headers={"Content-Type": "application/json"})
        # 400 sans signature ; 401 si secret configuré et header manquant
        assert r.status_code in (400, 401, 422)

    def test_github_webhook_valid_signature_accepted(self, client):
        """Payload valide avec signature correcte → 200 ou 202."""
        secret = os.getenv("WEBHOOK_SECRET", "repod-test-webhook-secret-integration")
        body = json.dumps({
            "action": "published",
            "advisory": {
                "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Test advisory",
                "severity": "high",
                "cve_id": "CVE-2024-9999",
                "vulnerable_versions": ["< 1.0.0"],
            }
        }).encode()
        r = client.post("/webhooks/github",
                        content=body,
                        headers={
                            "Content-Type": "application/json",
                            "X-Hub-Signature-256": self._sign(body, secret),
                        })
        assert r.status_code in (200, 202)


# ═══════════════════════════════════════════════════════════════════════════════
# 12. Barrières de sécurité globales
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityBarriers:

    @pytest.mark.parametrize("path", [
        "/api/v1/packages/",
        "/api/v1/dashboard/stats",
        "/api/v1/settings/",
        "/api/v1/security/vulnerabilities",
        "/api/v1/sbom/export",
        "/api/v1/downloads/stats",
        "/api/v1/distributions/",
    ])
    def test_endpoint_requires_auth(self, client, path):
        """Tous les endpoints protégés retournent 401 sans token."""
        r = client.get(path)
        assert r.status_code == 401, (
            f"{path} devrait retourner 401 sans authentification, "
            f"mais retourne {r.status_code}"
        )

    @pytest.mark.parametrize("path,method", [
        ("/api/v1/settings/", "patch"),
        ("/api/v1/auth/users", "get"),
    ])
    def test_admin_endpoint_rejects_reader(self, client, reader_token, path, method):
        """Les endpoints admin retournent 403 pour un reader."""
        r = getattr(client, method)(path, headers=auth(reader_token))
        assert r.status_code == 403, (
            f"{method.upper()} {path} devrait retourner 403 pour un reader, "
            f"mais retourne {r.status_code}"
        )

    def test_expired_or_garbage_token_401(self, client):
        garbage = "eyJhbGciOiJIUzI1NiJ9.garbage.garbage"
        r = client.get("/api/v1/packages/",
                       headers={"Authorization": f"Bearer {garbage}"})
        assert r.status_code == 401

    def test_no_bearer_prefix_401(self, client):
        r = client.get("/api/v1/packages/",
                       headers={"Authorization": "Basic YWRtaW46YWRtaW4="})
        assert r.status_code == 401
