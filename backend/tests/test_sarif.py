"""
Module : test_sarif.py
Rôle   : [G] Export SARIF 2.1.0 (GitHub Code Scanning / SonarQube) — repod-rpm
         Vérifie la structure du document SARIF, le mapping CVE → rules/results,
         les niveaux de sévérité, les filtres et les cas limites.

Spécification SARIF 2.1.0 :
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Mapping sévérité → level SARIF :
  Critical / High  → "error"
  Medium           → "warning"
  Low / Negligible → "note"
  Inconnu          → "none"

Adapté depuis repod-apt/tests/test_sarif.py → RPM (règle R5) :
  amd64 → x86_64 | .deb → .rpm | jammy → almalinux8 | focal → rocky9
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_sarif_test_")
os.environ["MANIFEST_DIR"] = _TMP
os.environ.setdefault("POOL_DIR", _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
from pathlib import Path
from unittest.mock import patch

import pytest

import services.manifest as _manifest_mod
_manifest_mod.MANIFEST_DIR = Path(_TMP)


# ── Données de test ───────────────────────────────────────────────────────────

def _manifest(
    name="nginx", version="1.24.0", arch="x86_64", distribution="almalinux8",
    cve_results=None,
):
    return {
        "name": name, "version": version, "arch": arch,
        "distribution": distribution,
        "filename": f"{name}-{version}.{arch}.rpm",
        "description": f"Package {name}", "section": "web",
        "status": "validated",
        "integrity": {"sha256": "abc123", "sha512": "def456"},
        "source": {"imported_at": "2025-01-01T00:00:00+00:00", "import_method": "upload"},
        "cve_results": cve_results or [],
    }


def _cve(
    cve_id="CVE-2024-1234", severity="High", cvss=7.5,
    description="Test vulnerability", fix_state="fixed",
    fix_versions=None, in_kev=False,
    package_name=None, package_version=None,
):
    return {
        "id": cve_id, "severity": severity, "cvss": cvss,
        "description": description, "fix_state": fix_state,
        "fix_versions": fix_versions or ["1.24.1"],
        "in_kev": in_kev,
        "package_name": package_name,
        "package_version": package_version,
        "urls": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Source inspection — services/sarif.py existe
# ═══════════════════════════════════════════════════════════════════════════════

class TestSarifModuleExists:

    def test_sarif_module_exists(self):
        """
        ❌ ROUGE avant fix : services/sarif.py n'existe pas
        ✅ VERT après fix  : module présent
        """
        p = Path(__file__).parent.parent / "services" / "sarif.py"
        assert p.exists(), "services/sarif.py doit être créé ([G] Export SARIF)"

    def test_generate_sarif_importable(self):
        """generate_sarif() doit être importable depuis services.sarif."""
        from services.sarif import generate_sarif
        assert callable(generate_sarif)

    def test_sarif_endpoint_in_sbom_router(self):
        """Le router sbom doit exposer un endpoint SARIF."""
        src = (Path(__file__).parent.parent / "routers" / "sbom_router.py").read_text()
        assert "sarif" in src.lower(), (
            "sbom_router.py doit exposer un endpoint SARIF (GET /sbom/sarif)"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Structure SARIF 2.1.0 — champs obligatoires
# ═══════════════════════════════════════════════════════════════════════════════

class TestSarifStructure:

    def _gen(self, manifests):
        with patch("services.sarif.list_manifests", return_value=manifests):
            from services.sarif import generate_sarif
            return generate_sarif()

    def test_version_is_2_1_0(self):
        """
        ❌ ROUGE avant fix : champ version absent ou incorrect
        ✅ VERT après fix  : version = "2.1.0" (obligatoire SARIF)
        """
        doc = self._gen([])
        assert doc.get("version") == "2.1.0", (
            f"SARIF doit avoir version='2.1.0', obtenu : {doc.get('version')!r}"
        )

    def test_schema_url_present(self):
        """Le champ $schema doit pointer vers le schéma SARIF 2.1.0."""
        doc = self._gen([])
        schema = doc.get("$schema", "")
        assert "sarif" in schema.lower() and "2.1" in schema, (
            f"$schema doit référencer SARIF 2.1.0, obtenu : {schema!r}"
        )

    def test_runs_is_list(self):
        """runs doit être une liste (même si vide)."""
        doc = self._gen([])
        assert isinstance(doc.get("runs"), list)

    def test_runs_has_exactly_one_run(self):
        """Un seul run par export (un outil = repod)."""
        doc = self._gen([_manifest()])
        assert len(doc["runs"]) == 1

    def test_run_has_tool(self):
        """Chaque run contient un outil (tool.driver)."""
        doc = self._gen([])
        run = doc["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]

    def test_tool_driver_has_name(self):
        """tool.driver.name = 'repod'."""
        doc = self._gen([])
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver.get("name") == "repod"

    def test_tool_driver_has_version(self):
        """tool.driver.version est présent et non vide."""
        doc = self._gen([])
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver.get("version") not in (None, "")

    def test_run_has_results_list(self):
        """results est une liste (peut être vide)."""
        doc = self._gen([])
        run = doc["runs"][0]
        assert isinstance(run.get("results"), list)

    def test_run_has_rules_in_driver(self):
        """tool.driver.rules est une liste."""
        doc = self._gen([])
        rules = doc["runs"][0]["tool"]["driver"].get("rules", [])
        assert isinstance(rules, list)


# ═══════════════════════════════════════════════════════════════════════════════
# Sans CVE — document vide mais valide
# ═══════════════════════════════════════════════════════════════════════════════

class TestSarifNoCve:

    def _gen(self, manifests):
        with patch("services.sarif.list_manifests", return_value=manifests):
            from services.sarif import generate_sarif
            return generate_sarif()

    def test_empty_manifests_empty_results(self):
        """0 paquet → results=[], rules=[]."""
        doc = self._gen([])
        run = doc["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []

    def test_manifest_without_cve_produces_no_results(self):
        """Paquet RPM sans CVE → results=[]."""
        doc = self._gen([_manifest(cve_results=[])])
        assert doc["runs"][0]["results"] == []

    def test_manifest_without_cve_produces_no_rules(self):
        """Paquet RPM sans CVE → rules=[]."""
        doc = self._gen([_manifest(cve_results=[])])
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# Règles SARIF (rules) — une par CVE unique
# ═══════════════════════════════════════════════════════════════════════════════

class TestSarifRules:

    def _gen(self, manifests):
        with patch("services.sarif.list_manifests", return_value=manifests):
            from services.sarif import generate_sarif
            return generate_sarif()

    def test_one_cve_one_rule(self):
        """1 CVE → 1 rule dans tool.driver.rules."""
        cve = _cve("CVE-2024-1234")
        doc = self._gen([_manifest(cve_results=[cve])])
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "CVE-2024-1234"

    def test_same_cve_two_packages_one_rule(self):
        """
        La même CVE sur 2 paquets RPM → 1 seule rule (dédupliquée)
        mais 2 results.
        """
        cve = _cve("CVE-2024-SHARED")
        m1 = _manifest("nginx", "1.24.0", cve_results=[cve])
        m2 = _manifest("curl",  "7.88.0", cve_results=[cve])
        doc = self._gen([m1, m2])
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert rule_ids.count("CVE-2024-SHARED") == 1, (
            "La même CVE ne doit apparaître qu'une seule fois dans rules"
        )

    def test_rule_has_short_description(self):
        """Chaque rule a shortDescription.text."""
        doc = self._gen([_manifest(cve_results=[_cve()])])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "shortDescription" in rule
        assert "text" in rule["shortDescription"]
        assert rule["shortDescription"]["text"]

    def test_rule_has_full_description_with_cve_details(self):
        """fullDescription.text contient la description de la CVE."""
        desc = "Critical buffer overflow in libssl"
        cve = _cve(description=desc)
        doc = self._gen([_manifest(cve_results=[cve])])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        full = rule.get("fullDescription", {}).get("text", "")
        assert desc in full or len(full) > 0

    def test_rule_default_configuration_level_error_for_high(self):
        """High severity → defaultConfiguration.level = 'error'."""
        cve = _cve(severity="High")
        doc = self._gen([_manifest(cve_results=[cve])])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        level = rule.get("defaultConfiguration", {}).get("level")
        assert level == "error", f"High → 'error', obtenu : {level!r}"

    def test_rule_level_error_for_critical(self):
        """Critical → level 'error'."""
        cve = _cve(severity="Critical")
        doc = self._gen([_manifest(cve_results=[cve])])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_rule_level_warning_for_medium(self):
        """Medium → level 'warning'."""
        cve = _cve(severity="Medium")
        doc = self._gen([_manifest(cve_results=[cve])])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "warning"

    def test_rule_level_note_for_low(self):
        """Low → level 'note'."""
        cve = _cve(severity="Low")
        doc = self._gen([_manifest(cve_results=[cve])])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "note"

    def test_rule_level_note_for_negligible(self):
        """Negligible → level 'note'."""
        cve = _cve(severity="Negligible")
        doc = self._gen([_manifest(cve_results=[cve])])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "note"

    def test_rule_has_help_with_fix_info(self):
        """help.text contient l'info de correction."""
        cve = _cve(fix_state="fixed", fix_versions=["1.24.1"])
        doc = self._gen([_manifest(cve_results=[cve])])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        help_text = rule.get("help", {}).get("text", "")
        assert len(help_text) > 0

    def test_rule_properties_has_severity(self):
        """rule.properties contient severity."""
        cve = _cve(severity="High")
        doc = self._gen([_manifest(cve_results=[cve])])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        props = rule.get("properties", {})
        assert "severity" in props


# ═══════════════════════════════════════════════════════════════════════════════
# Résultats SARIF (results) — un par (CVE × paquet)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSarifResults:

    def _gen(self, manifests):
        with patch("services.sarif.list_manifests", return_value=manifests):
            from services.sarif import generate_sarif
            return generate_sarif()

    def test_one_cve_one_result(self):
        """1 CVE sur 1 paquet RPM → 1 result."""
        doc = self._gen([_manifest(cve_results=[_cve()])])
        assert len(doc["runs"][0]["results"]) == 1

    def test_two_cves_two_results(self):
        """2 CVE différentes sur le même paquet → 2 results."""
        cves = [_cve("CVE-2024-001"), _cve("CVE-2024-002")]
        doc = self._gen([_manifest(cve_results=cves)])
        assert len(doc["runs"][0]["results"]) == 2

    def test_same_cve_two_packages_two_results(self):
        """La même CVE sur 2 paquets RPM → 2 results."""
        cve = _cve("CVE-2024-SHARED")
        m1 = _manifest("nginx", "1.24.0", cve_results=[cve])
        m2 = _manifest("curl",  "7.88.0", cve_results=[cve])
        doc = self._gen([m1, m2])
        assert len(doc["runs"][0]["results"]) == 2

    def test_result_has_rule_id(self):
        """Chaque result référence son ruleId."""
        doc = self._gen([_manifest(cve_results=[_cve("CVE-2024-1234")])])
        result = doc["runs"][0]["results"][0]
        assert result.get("ruleId") == "CVE-2024-1234"

    def test_result_level_matches_rule(self):
        """Le level du result correspond à la sévérité."""
        doc = self._gen([_manifest(cve_results=[_cve(severity="High")])])
        result = doc["runs"][0]["results"][0]
        assert result.get("level") == "error"

    def test_result_has_message(self):
        """Chaque result a message.text non vide."""
        doc = self._gen([_manifest(cve_results=[_cve()])])
        result = doc["runs"][0]["results"][0]
        msg = result.get("message", {}).get("text", "")
        assert len(msg) > 0

    def test_result_message_contains_package_name(self):
        """Le message inclut le nom du paquet RPM affecté."""
        doc = self._gen([_manifest(name="openssl", cve_results=[_cve()])])
        result = doc["runs"][0]["results"][0]
        assert "openssl" in result["message"]["text"]

    def test_result_message_contains_cve_id(self):
        """Le message inclut l'ID de la CVE."""
        doc = self._gen([_manifest(cve_results=[_cve("CVE-2024-9999")])])
        result = doc["runs"][0]["results"][0]
        assert "CVE-2024-9999" in result["message"]["text"]

    def test_result_has_locations(self):
        """Chaque result a une liste locations non vide."""
        doc = self._gen([_manifest(cve_results=[_cve()])])
        result = doc["runs"][0]["results"][0]
        assert isinstance(result.get("locations"), list)
        assert len(result["locations"]) >= 1

    def test_result_location_has_artifact_uri(self):
        """La location inclut un URI vers le fichier .rpm."""
        doc = self._gen([_manifest(name="nginx", version="1.24.0", cve_results=[_cve()])])
        result = doc["runs"][0]["results"][0]
        loc = result["locations"][0]
        uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
        assert "nginx" in uri or ".rpm" in uri

    def test_result_rule_index_matches_rules_position(self):
        """ruleIndex pointe vers la bonne position dans rules[]."""
        cves = [_cve("CVE-A"), _cve("CVE-B")]
        doc = self._gen([_manifest(cve_results=cves)])
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        for result in doc["runs"][0]["results"]:
            idx = result.get("ruleIndex", -1)
            assert 0 <= idx < len(rules)
            assert rules[idx]["id"] == result["ruleId"]

    def test_kev_flag_in_result_properties(self):
        """CVE marquée in_kev=True → kev:true dans result.properties."""
        cve = _cve(in_kev=True)
        doc = self._gen([_manifest(cve_results=[cve])])
        result = doc["runs"][0]["results"][0]
        props = result.get("properties", {})
        assert props.get("kev") is True


# ═══════════════════════════════════════════════════════════════════════════════
# Filtres — distribution RPM et nom de paquet
# ═══════════════════════════════════════════════════════════════════════════════

class TestSarifFilters:

    def test_distribution_filter(self):
        """Seuls les paquets de la distribution RPM demandée sont inclus."""
        m_alma = _manifest("nginx", "1.24.0", distribution="almalinux8",
                           cve_results=[_cve("CVE-ALMA")])
        m_rocky = _manifest("curl", "7.88.0", distribution="rocky9",
                            cve_results=[_cve("CVE-ROCKY")])
        with patch("services.sarif.list_manifests", return_value=[m_alma, m_rocky]):
            from services.sarif import generate_sarif
            doc = generate_sarif(distribution="almalinux8")
        results = doc["runs"][0]["results"]
        rule_ids = {r["ruleId"] for r in results}
        assert "CVE-ALMA" in rule_ids
        assert "CVE-ROCKY" not in rule_ids

    def test_name_version_filter_single_package(self):
        """Avec name+version → seul ce paquet RPM est inclus (via load_manifest)."""
        m = _manifest("vim", "9.0", cve_results=[_cve("CVE-VIM")])
        with patch("services.sarif.load_manifest", return_value=m):
            from services.sarif import generate_sarif
            doc = generate_sarif(name="vim", version="9.0")
        results = doc["runs"][0]["results"]
        assert any(r["ruleId"] == "CVE-VIM" for r in results)

    def test_missing_package_returns_empty_results(self):
        """Paquet RPM introuvable → results=[]."""
        with patch("services.sarif.load_manifest", return_value=None):
            from services.sarif import generate_sarif
            doc = generate_sarif(name="nonexistent", version="0.0.0")
        assert doc["runs"][0]["results"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# Endpoint router — source inspection
# ═══════════════════════════════════════════════════════════════════════════════

class TestSarifRouterEndpoints:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "routers" / "sbom_router.py"
        return p.read_text()

    def test_sarif_global_endpoint(self):
        """
        ❌ ROUGE avant fix : GET /sbom/sarif absent
        ✅ VERT après fix  : endpoint présent dans sbom_router.py
        """
        assert "/sarif" in self._src(), (
            "sbom_router.py doit exposer GET /sbom/sarif"
        )

    def test_sarif_content_type_header(self):
        """Le router doit retourner application/sarif+json."""
        src = self._src()
        assert "sarif" in src.lower()

    def test_sarif_filename_in_response(self):
        """L'en-tête Content-Disposition doit contenir .sarif.json."""
        src = self._src()
        assert ".sarif" in src or "sarif" in src

    def test_sarif_arch_default_x86_64(self):
        """
        ❌ ROUGE avant fix : arch par défaut = 'amd64' (héritage APT)
        ✅ VERT après fix  : arch par défaut = 'x86_64' (RPM)
        """
        src = self._src()
        # Le router SARIF doit utiliser x86_64 comme arch par défaut (pas amd64)
        assert "x86_64" in src, (
            "sbom_router.py doit utiliser x86_64 comme architecture par défaut (RPM)"
        )

    def test_sarif_per_package_endpoint(self):
        """GET /sbom/{name}/{version}/sarif doit exister."""
        src = self._src()
        assert "{name}/{version}" in src and "sarif" in src, (
            "sbom_router.py doit exposer GET /sbom/{name}/{version}/sarif"
        )
