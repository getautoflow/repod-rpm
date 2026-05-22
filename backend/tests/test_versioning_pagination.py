"""
Module : test_versioning_pagination.py
Rôle   : Tests versioning /api/v1/ + Pagination pour repod-rpm.
         Vérifie que :
           - Tous les routers métier sont enregistrés sous /api/v1
           - health_router reste sans préfixe (endpoint infra)
           - services/pagination.py existe et fonctionne correctement
           - GET /artifacts/    → format paginé {items, total, page, per_page, pages}
           - GET /security/review-queue → format paginé
           - GET /security/vulnerabilities → format paginé
           - GET /artifacts/audit/logs   → format paginé

Adapté depuis repod-apt/tests/test_versioning_pagination.py → RPM (règle R5).
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_rpm_pagv1_test_")
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR",     _TMP)
os.environ.setdefault("AUTH_DB_PATH", f"{_TMP}/users.db")

# ── Imports normaux ────────────────────────────────────────────────────────────
import math
from pathlib import Path

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# Versioning — tous les routers métier sous /api/v1
# ═══════════════════════════════════════════════════════════════════════════════

class TestApiV1PrefixInMain:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "main.py"
        assert p.exists()
        return p.read_text()

    def test_api_v1_prefix_constant_defined(self):
        """
        ❌ ROUGE avant fix : aucun /api/v1 dans main.py
        ✅ VERT après fix  : API_V1 = "/api/v1" présent
        """
        src = self._src()
        assert "/api/v1" in src, (
            "main.py doit définir le préfixe /api/v1 pour les routers versionnés"
        )

    def test_packages_router_registered_with_api_v1(self):
        """packages_router inclus avec prefix /api/v1."""
        src = self._src()
        lines = src.splitlines()
        pkg_lines = [l for l in lines if "packages_router" in l and "include_router" in l]
        assert any("api/v1" in l or "API_V1" in l for l in pkg_lines), (
            f"packages_router doit être inclus avec le préfixe /api/v1 : {pkg_lines}"
        )

    def test_security_router_registered_with_api_v1(self):
        """security_router inclus avec prefix /api/v1."""
        src = self._src()
        lines = src.splitlines()
        lines_ = [l for l in lines if "security_router" in l and "include_router" in l]
        assert any("api/v1" in l or "API_V1" in l for l in lines_), (
            f"security_router doit être inclus avec /api/v1 : {lines_}"
        )

    def test_auth_router_registered_with_api_v1(self):
        """auth_router inclus avec prefix /api/v1."""
        src = self._src()
        lines = src.splitlines()
        lines_ = [l for l in lines if "auth_router" in l and "include_router" in l]
        assert any("api/v1" in l or "API_V1" in l for l in lines_), (
            f"auth_router doit être inclus avec /api/v1 : {lines_}"
        )

    def test_health_router_not_versioned(self):
        """
        health_router doit rester sans préfixe /api/v1 — endpoint infra
        consulté par Docker healthcheck, load balancers, Kubernetes probes.
        """
        src = self._src()
        lines = src.splitlines()
        health_lines = [l for l in lines if "health_router" in l and "include_router" in l]
        assert health_lines, "health_router doit être enregistré dans main.py"
        versioned = [l for l in health_lines if "api/v1" in l or "API_V1" in l]
        assert not versioned, (
            f"health_router ne doit PAS être versionné (endpoint infra) : {versioned}"
        )

    def test_dashboard_router_registered_with_api_v1(self):
        """dashboard_router inclus avec prefix /api/v1."""
        src = self._src()
        lines = src.splitlines()
        lines_ = [l for l in lines if "dashboard_router" in l and "include_router" in l]
        assert any("api/v1" in l or "API_V1" in l for l in lines_), (
            f"dashboard_router doit être inclus avec /api/v1 : {lines_}"
        )

    def test_sbom_router_registered_with_api_v1(self):
        """sbom_router inclus avec prefix /api/v1."""
        src = self._src()
        lines = src.splitlines()
        lines_ = [l for l in lines if "sbom_router" in l and "include_router" in l]
        assert any("api/v1" in l or "API_V1" in l for l in lines_), (
            f"sbom_router doit être inclus avec /api/v1 : {lines_}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# services/pagination.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestPaginationModule:

    def test_module_exists(self):
        """
        ❌ ROUGE avant fix : services/pagination.py n'existe pas
        ✅ VERT après fix  : module présent
        """
        p = Path(__file__).parent.parent / "services" / "pagination.py"
        assert p.exists(), "services/pagination.py doit être créé"

    def test_paginate_importable(self):
        from services.pagination import paginate
        assert callable(paginate)

    def test_paginate_full_page(self):
        from services.pagination import paginate
        items = list(range(10))
        result = paginate(items, page=1, per_page=5)
        assert result["items"] == [0, 1, 2, 3, 4]
        assert result["total"] == 10
        assert result["page"] == 1
        assert result["per_page"] == 5
        assert result["pages"] == 2

    def test_paginate_second_page(self):
        from services.pagination import paginate
        result = paginate(list(range(10)), page=2, per_page=5)
        assert result["items"] == [5, 6, 7, 8, 9]
        assert result["page"] == 2

    def test_paginate_last_page_partial(self):
        from services.pagination import paginate
        result = paginate(list(range(7)), page=2, per_page=5)
        assert result["items"] == [5, 6]
        assert result["total"] == 7
        assert result["pages"] == 2

    def test_paginate_empty_list(self):
        from services.pagination import paginate
        result = paginate([], page=1, per_page=50)
        assert result == {"items": [], "total": 0, "page": 1, "per_page": 50, "pages": 0}

    def test_paginate_page_beyond_range(self):
        from services.pagination import paginate
        result = paginate(list(range(3)), page=99, per_page=10)
        assert result["items"] == []
        assert result["total"] == 3
        assert result["page"] == 99

    def test_paginate_default_values(self):
        from services.pagination import paginate
        result = paginate(list(range(5)))
        assert result["page"] == 1
        assert result["per_page"] == 50

    def test_paginate_output_keys(self):
        from services.pagination import paginate
        result = paginate([1, 2, 3], page=1, per_page=10)
        for key in ("items", "total", "page", "per_page", "pages"):
            assert key in result, f"Clé manquante : {key!r}"

    def test_paginate_pages_ceil(self):
        from services.pagination import paginate
        result = paginate(list(range(11)), page=1, per_page=5)
        assert result["pages"] == 3


# ═══════════════════════════════════════════════════════════════════════════════
# GET /artifacts/ — format paginé
# ═══════════════════════════════════════════════════════════════════════════════

class TestArtifactsEndpointPaginated:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "routers" / "artifacts.py"
        assert p.exists()
        return p.read_text()

    def test_page_param_in_artifacts_route(self):
        """
        ❌ ROUGE avant fix : GET /artifacts/ n'a pas de param page/per_page
        ✅ VERT après fix  : Query param page et per_page présents
        """
        src = self._src()
        idx = src.find("def list_artifacts")
        assert idx >= 0, "list_artifacts() introuvable dans artifacts.py"
        snippet = src[idx:idx + 500]
        assert "page" in snippet, "list_artifacts doit avoir un paramètre 'page'"
        assert "per_page" in snippet, "list_artifacts doit avoir un paramètre 'per_page'"

    def test_paginate_called_in_artifacts_route(self):
        """paginate() est appelé dans list_artifacts()."""
        src = self._src()
        idx = src.find("def list_artifacts")
        next_def = src.find("\ndef ", idx + 1)
        body = src[idx:next_def] if next_def > 0 else src[idx:]
        assert "paginate(" in body, (
            "list_artifacts doit appeler paginate() (services.pagination)"
        )

    def test_artifacts_route_returns_paginate_result(self):
        """list_artifacts() retourne directement le résultat de paginate()."""
        src = self._src()
        idx = src.find("def list_artifacts")
        next_def = src.find("\ndef ", idx + 1)
        body = src[idx:next_def] if next_def > 0 else src[idx:]
        assert "return paginate(" in body, (
            "list_artifacts doit retourner paginate(...) directement"
        )

    def test_search_param_in_artifacts_route(self):
        """list_artifacts doit accepter un paramètre 'search' pour filtrer par nom."""
        src = self._src()
        idx = src.find("def list_artifacts")
        snippet = src[idx:idx + 600]
        assert "search" in snippet, (
            "list_artifacts doit accepter un paramètre 'search'"
        )

    def test_distribution_param_in_artifacts_route(self):
        """list_artifacts doit accepter un paramètre 'distribution' pour filtrer par distrib."""
        src = self._src()
        idx = src.find("def list_artifacts")
        snippet = src[idx:idx + 600]
        assert "distribution" in snippet, (
            "list_artifacts doit accepter un paramètre 'distribution'"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /security/review-queue — format paginé
# ═══════════════════════════════════════════════════════════════════════════════

class TestReviewQueuePaginated:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "routers" / "security_router.py"
        assert p.exists()
        return p.read_text()

    def test_page_param_in_review_queue_route(self):
        """
        ❌ ROUGE avant fix : get_review_queue() sans page/per_page
        ✅ VERT après fix  : params présents
        """
        src = self._src()
        idx = src.find("def get_review_queue")
        assert idx >= 0
        snippet = src[idx:idx + 400]
        assert "page" in snippet, "get_review_queue doit avoir un paramètre 'page'"

    def test_per_page_param_in_review_queue(self):
        src = self._src()
        idx = src.find("def get_review_queue")
        snippet = src[idx:idx + 400]
        assert "per_page" in snippet, "get_review_queue doit avoir un paramètre 'per_page'"

    def test_paginate_called_in_review_queue(self):
        src = self._src()
        idx = src.find("def get_review_queue")
        next_def = src.find("\ndef ", idx + 1)
        body = src[idx:next_def] if next_def > 0 else src[idx:]
        assert "paginate(" in body, (
            "get_review_queue doit appeler paginate() sur la liste packages"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /security/vulnerabilities — format paginé
# ═══════════════════════════════════════════════════════════════════════════════

class TestVulnerabilitiesPaginated:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "routers" / "security_router.py"
        assert p.exists()
        return p.read_text()

    def test_page_param_in_vulnerabilities_route(self):
        src = self._src()
        idx = src.find("def get_vulnerabilities")
        assert idx >= 0
        snippet = src[idx:idx + 400]
        assert "page" in snippet, "get_vulnerabilities doit avoir un paramètre 'page'"

    def test_paginate_called_in_vulnerabilities(self):
        src = self._src()
        idx = src.find("def get_vulnerabilities")
        next_def = src.find("\ndef ", idx + 1)
        body = src[idx:next_def] if next_def > 0 else src[idx:]
        assert "paginate(" in body, (
            "get_vulnerabilities doit appeler paginate() sur la liste CVE"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /artifacts/audit/logs — format paginé
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditLogsPaginated:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "routers" / "artifacts.py"
        assert p.exists()
        return p.read_text()

    def test_page_param_in_audit_logs_route(self):
        """
        ❌ ROUGE avant fix : get_audit_logs() utilise limit=, pas page/per_page
        ✅ VERT après fix  : paramètres page et per_page présents
        """
        src = self._src()
        idx = src.find("def get_audit_logs")
        assert idx >= 0
        snippet = src[idx:idx + 400]
        assert "page" in snippet, "get_audit_logs doit avoir un paramètre 'page'"
        assert "per_page" in snippet, "get_audit_logs doit avoir un paramètre 'per_page'"

    def test_paginate_called_in_audit_logs(self):
        src = self._src()
        idx = src.find("def get_audit_logs")
        next_def = src.find("\ndef ", idx + 1)
        body = src[idx:next_def] if next_def > 0 else src[idx:]
        assert "paginate(" in body, (
            "get_audit_logs doit appeler paginate() sur les logs"
        )

    def test_no_plain_limit_in_audit_logs(self):
        """
        L'ancien paramètre limit= seul est remplacé par page/per_page.
        La logique de limite doit passer par per_page.
        """
        src = self._src()
        idx = src.find("def get_audit_logs")
        next_def = src.find("\ndef ", idx + 1)
        body = src[idx:next_def] if next_def > 0 else src[idx:]
        # paginate() doit être présent (le test précédent le vérifie déjà)
        # per_page doit aussi être présent
        assert "per_page" in body, (
            "get_audit_logs : per_page doit remplacer limit= comme paramètre de taille de page"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Frontend — fichiers générés (inspection source)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFrontendPaginatorComponent:

    @staticmethod
    def _paginator_src() -> str:
        p = Path(__file__).parent.parent.parent / "frontend" / "src" / "components" / "Paginator.js"
        assert p.exists(), (
            "frontend/src/components/Paginator.js doit être créé"
        )
        return p.read_text()

    def test_paginator_file_exists(self):
        """
        ❌ ROUGE avant fix : Paginator.js absent
        ✅ VERT après fix  : composant présent
        """
        self._paginator_src()  # lève AssertionError si absent

    def test_paginator_exports_default_function(self):
        """Paginator.js exporte une fonction par défaut."""
        src = self._paginator_src()
        assert "export default function Paginator" in src, (
            "Paginator.js doit exporter 'export default function Paginator'"
        )

    def test_paginator_accepts_page_prop(self):
        """Paginator reçoit la prop 'page'."""
        src = self._paginator_src()
        assert "page" in src

    def test_paginator_accepts_onpagechange_prop(self):
        """Paginator reçoit la prop 'onPageChange'."""
        src = self._paginator_src()
        assert "onPageChange" in src

    def test_paginator_has_prev_next_buttons(self):
        """Paginator a des boutons Précédent et Suivant."""
        src = self._paginator_src()
        assert "réc" in src.lower() or "prev" in src.lower(), (
            "Paginator doit avoir un bouton Précédent"
        )
        assert "uiv" in src.lower() or "next" in src.lower(), (
            "Paginator doit avoir un bouton Suivant"
        )


class TestFrontendApiPagination:
    """Vérifie que api.js passe bien page/per_page aux endpoints paginés."""

    @staticmethod
    def _api_src() -> str:
        p = Path(__file__).parent.parent.parent / "frontend" / "src" / "api.js"
        assert p.exists()
        return p.read_text()

    def test_listartifacts_accepts_page_param(self):
        """
        ❌ ROUGE avant fix : listArtifacts() sans params de pagination
        ✅ VERT après fix  : listArtifacts(page, perPage, ...) présent
        """
        src = self._api_src()
        idx = src.find("listArtifacts")
        assert idx >= 0
        snippet = src[idx:idx + 300]
        assert "page" in snippet, (
            "listArtifacts dans api.js doit accepter un paramètre 'page'"
        )

    def test_getreviewqueue_accepts_page_param(self):
        """getReviewQueue() doit passer page/per_page."""
        src = self._api_src()
        idx = src.find("getReviewQueue")
        assert idx >= 0
        snippet = src[idx:idx + 200]
        assert "page" in snippet, (
            "getReviewQueue dans api.js doit accepter un paramètre 'page'"
        )

    def test_getauditlogs_accepts_page_param(self):
        """getAuditLogs() doit passer page/per_page."""
        src = self._api_src()
        idx = src.find("getAuditLogs")
        assert idx >= 0
        snippet = src[idx:idx + 300]
        assert "page" in snippet, (
            "getAuditLogs dans api.js doit accepter un paramètre 'page'"
        )

    def test_api_uses_api_v1_prefix(self):
        """
        api.js doit utiliser /api/v1 comme préfixe pour les appels API.
        ❌ ROUGE avant fix : baseURL sans /api/v1
        ✅ VERT après fix  : /api/v1 présent dans la configuration axios
        """
        src = self._api_src()
        assert "api/v1" in src, (
            "api.js doit utiliser le préfixe /api/v1 (baseURL ou constante API_V1)"
        )


class TestFrontendPackageListPagination:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent.parent / "frontend" / "src" / "components" / "PackageList.js"
        assert p.exists()
        return p.read_text()

    def test_paginator_imported_in_packagelist(self):
        """
        ❌ ROUGE avant fix : Paginator non importé
        ✅ VERT après fix  : import Paginator présent
        """
        src = self._src()
        assert "Paginator" in src, (
            "PackageList.js doit importer le composant Paginator"
        )

    def test_page_state_in_packagelist(self):
        """PackageList maintient un état 'page'."""
        src = self._src()
        assert "useState" in src
        assert "page" in src.lower(), (
            "PackageList.js doit avoir un état 'page' pour la pagination"
        )

    def test_paginator_rendered_in_packagelist(self):
        """PackageList rend le composant <Paginator ...>."""
        src = self._src()
        assert "<Paginator" in src, (
            "PackageList.js doit rendre le composant <Paginator>"
        )


class TestFrontendAuditPagePagination:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent.parent / "frontend" / "src" / "pages" / "AuditPage.js"
        assert p.exists()
        return p.read_text()

    def test_paginator_imported_in_auditpage(self):
        src = self._src()
        assert "Paginator" in src, "AuditPage.js doit importer Paginator"

    def test_page_state_in_auditpage(self):
        src = self._src()
        assert "page" in src.lower(), "AuditPage.js doit avoir un état 'page'"

    def test_paginator_rendered_in_auditpage(self):
        src = self._src()
        assert "<Paginator" in src, "AuditPage.js doit rendre <Paginator>"


class TestFrontendSecurityPagePagination:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent.parent / "frontend" / "src" / "pages" / "SecurityPage.js"
        assert p.exists()
        return p.read_text()

    def test_paginator_imported_in_securitypage(self):
        src = self._src()
        assert "Paginator" in src, "SecurityPage.js doit importer Paginator"

    def test_paginator_rendered_in_review_queue(self):
        src = self._src()
        assert "<Paginator" in src, "SecurityPage.js doit rendre <Paginator>"

    def test_pkgpage_state_in_cveposture(self):
        """CvePostureSection doit avoir un état pkgPage pour la pagination client-side."""
        src = self._src()
        assert "pkgPage" in src, (
            "SecurityPage.js CvePostureSection doit avoir l'état 'pkgPage'"
        )
