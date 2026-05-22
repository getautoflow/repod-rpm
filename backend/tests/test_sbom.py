"""
Module : test_sbom.py
Rôle   : Tests de génération SBOM CycloneDX + SPDX pour paquets RPM.
         Vérifie en particulier que :
           - le type purl est bien pkg:rpm/ (pas pkg:deb/)
           - aucune mention Debian/Ubuntu/APT n'apparaît dans les sorties
           - les champs obligatoires CycloneDX 1.5 et SPDX 2.3 sont présents
           - les cas limites fonctionnent (0 paquet, CVE, deps, filtre distrib)

Adapté depuis repod-apt/tests/test_sbom.py → RPM (règle R5).
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_rpm_sbom_test_")
os.environ["MANIFEST_DIR"] = _TMP
os.environ.setdefault("POOL_DIR", _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
import re
from pathlib import Path
from unittest.mock import patch

import pytest

import services.manifest as _manifest_mod
_manifest_mod.MANIFEST_DIR = Path(_TMP)

from services.sbom import generate_cyclonedx, generate_spdx, generate_sbom, _purl, _spdx_id


# ── Données de test RPM ───────────────────────────────────────────────────────

def _manifest(
    name="nginx",
    version="1.24.0-1.el9",
    arch="x86_64",
    distribution="almalinux8",
    cve_results=None,
    dependencies=None,
):
    """Crée un manifest RPM minimal pour les tests."""
    return {
        "name": name,
        "version": version,
        "arch": arch,
        "distribution": distribution,
        "description": f"Test RPM package {name}",
        "section": "Applications/Internet",
        "maintainer": "test@test.local",
        "status": "validated",
        "integrity": {"sha256": "abc123rpm", "sha512": "def456rpm"},
        "source": {
            "imported_at": "2025-01-01T00:00:00+00:00",
            "import_method": "upload",
        },
        "cve_results": cve_results or [],
        "dependencies": dependencies or [],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TESTS CRITIQUES — FORMAT PURL RPM
# Ces tests DOIVENT échouer avant le fix, passer après.
# ═══════════════════════════════════════════════════════════════════════════════

class TestPurlRpm:
    """Vérifie que le type purl est pkg:rpm/ et non pkg:deb/."""

    def test_purl_uses_rpm_scheme(self):
        """_purl() doit retourner pkg:rpm/, jamais pkg:deb/."""
        purl = _purl("nginx", "1.24.0-1.el9", "x86_64", "almalinux8")
        assert purl.startswith("pkg:rpm/"), (
            f"PURL incorrect : attendu pkg:rpm/..., obtenu {purl!r}"
        )
        assert "pkg:deb/" not in purl, f"pkg:deb/ présent dans le purl RPM : {purl!r}"

    def test_purl_full_format(self):
        """_purl() produit l'URL complète attendue pour un paquet RPM."""
        purl = _purl("curl", "7.76.1-26.el9_3.2", "x86_64", "almalinux8")
        assert purl == "pkg:rpm/almalinux8/curl@7.76.1-26.el9_3.2?arch=x86_64"

    def test_purl_fedora(self):
        """_purl() fonctionne avec une distribution Fedora."""
        purl = _purl("bash", "5.1.8-6.el9", "x86_64", "fedora")
        assert purl == "pkg:rpm/fedora/bash@5.1.8-6.el9?arch=x86_64"

    def test_purl_noarch(self):
        """_purl() accepte l'arch 'noarch' (paquets RPM non spécifiques à une arch)."""
        purl = _purl("python3-requests", "2.28.0-1.el9", "noarch", "almalinux8")
        assert "noarch" in purl
        assert purl.startswith("pkg:rpm/")

    def test_no_deb_in_cyclonedx_components(self):
        """Aucun composant CycloneDX ne doit avoir pkg:deb/ dans son purl."""
        with patch("services.sbom.list_manifests", return_value=[_manifest()]):
            doc = generate_cyclonedx()
        for comp in doc["components"]:
            assert "pkg:deb/" not in comp.get("purl", ""), (
                f"pkg:deb/ trouvé dans le purl du composant : {comp['purl']!r}"
            )
            assert "pkg:rpm/" in comp.get("purl", ""), (
                f"pkg:rpm/ absent du purl du composant : {comp['purl']!r}"
            )

    def test_no_deb_in_spdx_download_location(self):
        """SPDX downloadLocation ne doit pas contenir pkg:deb/."""
        with patch("services.sbom.list_manifests", return_value=[_manifest()]):
            doc = generate_spdx()
        for pkg in doc["packages"]:
            loc = pkg.get("downloadLocation", "")
            if loc not in ("NOASSERTION",):
                assert "pkg:deb/" not in loc, (
                    f"pkg:deb/ trouvé dans downloadLocation SPDX : {loc!r}"
                )

    def test_no_deb_in_dep_external_refs(self):
        """Les dépendances en externalReferences ne doivent pas utiliser pkg:deb/."""
        deps = [{"name": "openssl", "version_constraint": ">=1.1"}]
        with patch("services.sbom.list_manifests", return_value=[_manifest(dependencies=deps)]):
            doc = generate_cyclonedx()
        for comp in doc["components"]:
            for ref in comp.get("externalReferences", []):
                url = ref.get("url", "")
                assert "pkg:deb/" not in url, (
                    f"pkg:deb/ trouvé dans externalReference : {url!r}"
                )


# ═══════════════════════════════════════════════════════════════════════════════
# TESTS ANTI-RÉGRESSION — Aucune mention APT/Debian/Ubuntu dans les sorties
# ═══════════════════════════════════════════════════════════════════════════════

class TestNoAptReferences:
    """Vérifie l'absence de toute mention APT / Debian / Ubuntu dans les SBOM."""

    def _collect_strings(self, obj, path="") -> list[str]:
        """Collecte récursivement toutes les chaînes d'un dict/list."""
        found = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                found.extend(self._collect_strings(v, f"{path}.{k}"))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                found.extend(self._collect_strings(v, f"{path}[{i}]"))
        elif isinstance(obj, str):
            found.append((path, obj))
        return found

    def _bad_strings(self, doc: dict) -> list[tuple[str, str]]:
        """Retourne les couples (chemin, valeur) contenant APT/Debian/Ubuntu."""
        bad_keywords = ("apt repository", "debian", "ubuntu", "pkg:deb/")
        return [
            (path, val)
            for path, val in self._collect_strings(doc)
            if any(kw in val.lower() for kw in bad_keywords)
        ]

    def test_cyclonedx_no_apt_references(self):
        """generate_cyclonedx() ne doit contenir aucune mention APT/Debian/Ubuntu."""
        with patch("services.sbom.list_manifests", return_value=[_manifest()]):
            doc = generate_cyclonedx()
        bad = self._bad_strings(doc)
        assert not bad, (
            "Références APT/Debian/Ubuntu trouvées dans CycloneDX :\n"
            + "\n".join(f"  {p} = {v!r}" for p, v in bad)
        )

    def test_spdx_no_apt_references(self):
        """generate_spdx() ne doit contenir aucune mention APT/Debian/Ubuntu."""
        with patch("services.sbom.list_manifests", return_value=[_manifest()]):
            doc = generate_spdx()
        bad = self._bad_strings(doc)
        assert not bad, (
            "Références APT/Debian/Ubuntu trouvées dans SPDX :\n"
            + "\n".join(f"  {p} = {v!r}" for p, v in bad)
        )

    def test_cyclonedx_metadata_mentions_rpm(self):
        """Le nom de l'outil et du repo dans metadata doit mentionner RPM."""
        with patch("services.sbom.list_manifests", return_value=[]):
            doc = generate_cyclonedx()
        tool_name = doc["metadata"]["tools"][0]["name"]
        component_name = doc["metadata"]["component"]["name"]
        assert "rpm" in tool_name.lower() or "repod" in tool_name.lower(), (
            f"Le nom de l'outil ne mentionne pas RPM : {tool_name!r}"
        )
        assert "apt" not in component_name.lower(), (
            f"Le composant metadata mentionne encore APT : {component_name!r}"
        )

    def test_spdx_creators_no_apt(self):
        """Les créateurs SPDX ne doivent pas mentionner APT."""
        with patch("services.sbom.list_manifests", return_value=[]):
            doc = generate_spdx()
        creators = doc["creationInfo"]["creators"]
        for c in creators:
            assert "apt" not in c.lower(), (
                f"Créateur SPDX mentionne APT : {c!r}"
            )

    def test_spdx_root_package_name_no_apt(self):
        """Le paquet racine SPDX ne doit pas s'appeler 'APT Repository'."""
        with patch("services.sbom.list_manifests", return_value=[]):
            doc = generate_spdx()
        repo_pkg = next(p for p in doc["packages"] if p["SPDXID"] == "SPDXRef-REPO")
        assert "apt" not in repo_pkg["name"].lower(), (
            f"Nom racine SPDX contient APT : {repo_pkg['name']!r}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Utilitaires internes
# ═══════════════════════════════════════════════════════════════════════════════

class TestHelpers:

    def test_spdx_id_sanitizes_special_chars(self):
        """_spdx_id() remplace les caractères non autorisés par '-'."""
        sid = _spdx_id("python3-requests", "2.28.0-1.el9", "x86_64")
        assert re.match(r"^SPDXRef-[A-Za-z0-9.\-]+$", sid), (
            f"SPDX ID invalide : {sid}"
        )

    def test_spdx_id_epoch_in_version(self):
        """_spdx_id() gère les epochs RPM (ex: 2:7.76.1-26.el9)."""
        sid = _spdx_id("curl", "2:7.76.1-26.el9", "x86_64")
        assert re.match(r"^SPDXRef-[A-Za-z0-9.\-]+$", sid)


# ═══════════════════════════════════════════════════════════════════════════════
# generate_cyclonedx() — Structure et cas limites
# ═══════════════════════════════════════════════════════════════════════════════

class TestCycloneDXStructure:

    def _gen(self, manifests):
        with patch("services.sbom.list_manifests", return_value=manifests):
            return generate_cyclonedx()

    def test_returns_dict(self):
        assert isinstance(self._gen([_manifest()]), dict)

    def test_bom_format_and_spec_version(self):
        doc = self._gen([_manifest()])
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"

    def test_serial_number_is_urn_uuid(self):
        doc = self._gen([_manifest()])
        assert doc["serialNumber"].startswith("urn:uuid:")

    def test_metadata_present(self):
        doc = self._gen([_manifest()])
        meta = doc["metadata"]
        assert "timestamp" in meta
        assert len(meta.get("tools", [])) >= 1

    def test_empty_manifests_produces_empty_components(self):
        doc = self._gen([])
        assert doc["components"] == []

    def test_one_manifest_one_component(self):
        doc = self._gen([_manifest("nginx", "1.24.0-1.el9")])
        assert len(doc["components"]) == 1
        comp = doc["components"][0]
        assert comp["name"] == "nginx"
        assert comp["version"] == "1.24.0-1.el9"

    def test_component_has_rpm_purl(self):
        """Le purl du composant utilise pkg:rpm/."""
        doc = self._gen([_manifest("curl", "7.76.1-26.el9", distribution="almalinux8")])
        comp = doc["components"][0]
        assert comp["purl"] == "pkg:rpm/almalinux8/curl@7.76.1-26.el9?arch=x86_64"

    def test_component_has_sha256_hash(self):
        doc = self._gen([_manifest()])
        hashes = {h["alg"]: h["content"] for h in doc["components"][0]["hashes"]}
        assert "SHA-256" in hashes
        assert hashes["SHA-256"] == "abc123rpm"

    def test_multiple_manifests_multiple_components(self):
        manifests = [_manifest(f"pkg{i}", f"{i}.0-1.el9") for i in range(5)]
        doc = self._gen(manifests)
        assert len(doc["components"]) == 5

    def test_cve_results_become_vulnerabilities(self):
        cve = {
            "id": "CVE-2024-1234",
            "severity": "High",
            "description": "Test vuln",
            "cvss_score": 7.5,
        }
        doc = self._gen([_manifest(cve_results=[cve])])
        assert "vulnerabilities" in doc
        assert doc["vulnerabilities"][0]["id"] == "CVE-2024-1234"

    def test_no_cve_no_vulnerabilities_key(self):
        doc = self._gen([_manifest(cve_results=[])])
        assert "vulnerabilities" not in doc

    def test_distribution_filter(self):
        manifests = [
            _manifest("nginx", "1.24.0-1.el9", distribution="almalinux8"),
            _manifest("curl",  "7.76.1-1.el9",  distribution="rocky8"),
        ]
        with patch("services.sbom.list_manifests", return_value=manifests):
            doc = generate_cyclonedx(distribution="almalinux8")
        assert len(doc["components"]) == 1
        assert doc["components"][0]["name"] == "nginx"

    def test_single_package_by_name_version(self):
        m = _manifest("vim", "9.0.0-1.el9")
        with patch("services.sbom.load_manifest", return_value=m):
            doc = generate_cyclonedx(name="vim", version="9.0.0-1.el9")
        assert len(doc["components"]) == 1
        assert doc["components"][0]["name"] == "vim"

    def test_missing_package_returns_empty_components(self):
        with patch("services.sbom.load_manifest", return_value=None):
            doc = generate_cyclonedx(name="nonexistent", version="0.0.0")
        assert doc["components"] == []

    def test_dep_external_refs_use_rpm_purl(self):
        """Les références de dépendances utilisent pkg:rpm/."""
        deps = [{"name": "openssl", "version_constraint": ">=1.1"}]
        doc = self._gen([_manifest(dependencies=deps)])
        comp = doc["components"][0]
        refs = comp.get("externalReferences", [])
        assert refs, "Aucune externalReference générée pour les dépendances"
        for ref in refs:
            assert "pkg:rpm/" in ref["url"], (
                f"externalReference n'utilise pas pkg:rpm/ : {ref['url']!r}"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# generate_spdx() — Structure et cas limites
# ═══════════════════════════════════════════════════════════════════════════════

class TestSpdxStructure:

    def _gen(self, manifests):
        with patch("services.sbom.list_manifests", return_value=manifests):
            return generate_spdx()

    def test_returns_dict(self):
        assert isinstance(self._gen([_manifest()]), dict)

    def test_spdx_version(self):
        assert self._gen([_manifest()])["spdxVersion"] == "SPDX-2.3"

    def test_data_license(self):
        assert self._gen([_manifest()])["dataLicense"] == "CC0-1.0"

    def test_document_namespace_unique(self):
        with patch("services.sbom.list_manifests", return_value=[]):
            doc1, doc2 = generate_spdx(), generate_spdx()
        assert doc1["documentNamespace"] != doc2["documentNamespace"]

    def test_root_repo_package_present(self):
        doc = self._gen([])
        spdx_ids = [p["SPDXID"] for p in doc["packages"]]
        assert "SPDXRef-REPO" in spdx_ids

    def test_one_manifest_two_packages(self):
        doc = self._gen([_manifest()])
        assert len(doc["packages"]) == 2

    def test_package_has_required_spdx_fields(self):
        doc = self._gen([_manifest("curl", "7.76.1-26.el9")])
        pkg = next(p for p in doc["packages"] if "curl" in p.get("name", "").lower())
        for field in ("SPDXID", "name", "versionInfo", "downloadLocation",
                      "licenseConcluded", "licenseDeclared"):
            assert field in pkg, f"Champ SPDX manquant : {field!r}"

    def test_relationships_describes(self):
        doc = self._gen([_manifest()])
        rels = doc.get("relationships", [])
        assert any(
            r["spdxElementId"] == "SPDXRef-DOCUMENT"
            and r["relationshipType"] == "DESCRIBES"
            and r["relatedSpdxElement"] == "SPDXRef-REPO"
            for r in rels
        ), "Relation DESCRIBES manquante"

    def test_empty_manifests_only_repo_package(self):
        doc = self._gen([])
        assert len(doc["packages"]) == 1
        assert doc["packages"][0]["SPDXID"] == "SPDXRef-REPO"

    def test_download_location_uses_rpm_purl(self):
        """downloadLocation utilise pkg:rpm/ pour les paquets RPM."""
        doc = self._gen([_manifest("bash", "5.1.8-6.el9", distribution="almalinux8")])
        pkgs = [p for p in doc["packages"] if p["SPDXID"] != "SPDXRef-REPO"]
        assert pkgs, "Aucun paquet trouvé (hors SPDXRef-REPO)"
        for pkg in pkgs:
            loc = pkg["downloadLocation"]
            assert loc.startswith("pkg:rpm/"), (
                f"downloadLocation SPDX n'utilise pas pkg:rpm/ : {loc!r}"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# generate_sbom() — Point d'entrée unifié
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateSbom:

    def test_cyclonedx_dispatch(self):
        with patch("services.sbom.list_manifests", return_value=[]):
            doc = generate_sbom("cyclonedx")
        assert doc["bomFormat"] == "CycloneDX"

    def test_spdx_dispatch(self):
        with patch("services.sbom.list_manifests", return_value=[]):
            doc = generate_sbom("spdx")
        assert doc["spdxVersion"] == "SPDX-2.3"
