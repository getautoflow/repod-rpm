"""
Génération de SBOM (Software Bill of Materials).

Formats supportés :
  - CycloneDX JSON v1.5  (standard OWASP, le plus répandu)
  - SPDX JSON v2.3       (standard ISO/IEC 5962)

Source : manifests JSON dans /repos/manifests/.
"""

import re
import uuid
from datetime import datetime, timezone
from typing import Literal

from services.manifest import list_manifests, load_manifest

SbomFormat = Literal["cyclonedx", "spdx"]


# ─── Utilitaires ──────────────────────────────────────────────────────────────

def _purl(name: str, version: str, arch: str, distribution: str) -> str:
    """Package URL (purl) spec pour les paquets Debian/Ubuntu."""
    distro = distribution or "linux"
    return f"pkg:deb/{distro}/{name}@{version}?arch={arch}"


def _spdx_id(name: str, version: str, arch: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9.\-]", "-", f"{name}-{version}-{arch}")
    return f"SPDXRef-{safe}"


def _filter_manifests(distribution: str | None = None, name: str | None = None) -> list[dict]:
    manifests = list_manifests()
    if distribution:
        manifests = [m for m in manifests if m.get("distribution") == distribution]
    if name:
        manifests = [m for m in manifests if m.get("name") == name]
    return manifests


# ─── CycloneDX JSON v1.5 ──────────────────────────────────────────────────────

def generate_cyclonedx(
    distribution: str | None = None,
    name: str | None = None,
    version: str | None = None,
    arch: str = "amd64",
) -> dict:
    """
    Génère un SBOM au format CycloneDX JSON v1.5.
    Si name+version sont fournis → SBOM d'un seul paquet.
    Sinon → SBOM de tous les paquets (filtré par distribution).
    """
    if name and version:
        manifests = []
        m = load_manifest(name, version, arch)
        if m:
            manifests = [m]
    else:
        manifests = _filter_manifests(distribution)

    components = []
    vulnerabilities = []

    for m in manifests:
        pkg_name    = m.get("name", "unknown")
        pkg_version = m.get("version", "unknown")
        pkg_arch    = m.get("arch", "amd64")
        pkg_distrib = m.get("distribution", distribution or "unknown")

        hashes = []
        integrity = m.get("integrity", {})
        if integrity.get("sha256"):
            hashes.append({"alg": "SHA-256", "content": integrity["sha256"]})
        if integrity.get("sha512"):
            hashes.append({"alg": "SHA-512", "content": integrity["sha512"]})

        # Dépendances → externalReferences internes
        ext_refs = []
        for dep in m.get("dependencies", []):
            dep_name = dep.get("name", "")
            if dep_name:
                ext_refs.append({
                    "type": "distribution",
                    "url":  f"pkg:deb/{pkg_distrib}/{dep_name}",
                    "comment": dep.get("version_constraint", ""),
                })

        component = {
            "type":        "library",
            "bom-ref":     _purl(pkg_name, pkg_version, pkg_arch, pkg_distrib),
            "name":        pkg_name,
            "version":     pkg_version,
            "purl":        _purl(pkg_name, pkg_version, pkg_arch, pkg_distrib),
            "description": (m.get("description") or "")[:256],
            "hashes":      hashes,
            "properties": [
                {"name": "arch",         "value": pkg_arch},
                {"name": "distribution", "value": pkg_distrib},
                {"name": "section",      "value": m.get("section", "")},
                {"name": "maintainer",   "value": (m.get("maintainer") or "")[:128]},
                {"name": "import_method","value": m.get("source", {}).get("import_method", "")},
                {"name": "imported_at",  "value": m.get("source", {}).get("imported_at", "")},
                {"name": "status",       "value": m.get("status", "")},
            ],
        }
        if ext_refs:
            component["externalReferences"] = ext_refs
        components.append(component)

        # CVE → vulnérabilités CycloneDX
        for cve in m.get("cve_results", []):
            cve_id = cve.get("cve_id") or cve.get("id", "")
            if not cve_id:
                continue
            vuln = {
                "id":     cve_id,
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
                "ratings": [{
                    "severity": (cve.get("severity") or "unknown").lower(),
                    "score":    cve.get("cvss_score"),
                    "method":   "CVSSv3",
                }],
                "description": (cve.get("description") or "")[:512],
                "affects": [{
                    "ref": _purl(pkg_name, pkg_version, pkg_arch, pkg_distrib),
                }],
            }
            if cve.get("fix_version"):
                vuln["recommendation"] = f"Mettre à jour vers {cve['fix_version']}"
            vulnerabilities.append(vuln)

    doc = {
        "bomFormat":    "CycloneDX",
        "specVersion":  "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version":      1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{
                "vendor":  "repod",
                "name":    "repod APT Repository Manager",
                "version": "2.0.0",
            }],
            "component": {
                "type":    "platform",
                "name":    f"APT Repository{f' — {distribution}' if distribution else ''}",
                "version": "1.0",
            },
        },
        "components": components,
    }
    if vulnerabilities:
        doc["vulnerabilities"] = vulnerabilities

    return doc


# ─── SPDX JSON v2.3 ───────────────────────────────────────────────────────────

def generate_spdx(
    distribution: str | None = None,
    name: str | None = None,
    version: str | None = None,
    arch: str = "amd64",
) -> dict:
    """
    Génère un SBOM au format SPDX JSON v2.3 (ISO/IEC 5962:2021).
    """
    if name and version:
        manifests = []
        m = load_manifest(name, version, arch)
        if m:
            manifests = [m]
    else:
        manifests = _filter_manifests(distribution)

    doc_name  = f"repod-sbom{f'-{distribution}' if distribution else ''}"
    namespace = f"https://repod.local/sbom/{doc_name}-{uuid.uuid4()}"
    now       = datetime.now(timezone.utc).isoformat()

    packages     = []
    relationships = [{
        "spdxElementId":      "SPDXRef-DOCUMENT",
        "relationshipType":   "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-REPO",
    }]

    # Package racine = le dépôt APT
    packages.append({
        "SPDXID":           "SPDXRef-REPO",
        "name":             f"APT Repository{f' ({distribution})' if distribution else ''}",
        "versionInfo":      "1.0",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed":    False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared":  "NOASSERTION",
        "copyrightText":    "NOASSERTION",
    })

    for m in manifests:
        pkg_name    = m.get("name", "unknown")
        pkg_version = m.get("version", "unknown")
        pkg_arch    = m.get("arch", "amd64")
        pkg_distrib = m.get("distribution", distribution or "unknown")
        spdx_id     = _spdx_id(pkg_name, pkg_version, pkg_arch)

        checksum = []
        integrity = m.get("integrity", {})
        if integrity.get("sha256"):
            checksum.append({"algorithm": "SHA256", "checksumValue": integrity["sha256"]})
        if integrity.get("sha512"):
            checksum.append({"algorithm": "SHA512", "checksumValue": integrity["sha512"]})

        pkg = {
            "SPDXID":           spdx_id,
            "name":             pkg_name,
            "versionInfo":      pkg_version,
            "downloadLocation": f"pkg:deb/{pkg_distrib}/{pkg_name}@{pkg_version}?arch={pkg_arch}",
            "filesAnalyzed":    False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared":  "NOASSERTION",
            "copyrightText":    "NOASSERTION",
            "supplier":         f"Organization: {(m.get('maintainer') or 'NOASSERTION')[:128]}",
            "comment":          (m.get("description") or "")[:256],
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType":     "purl",
                    "referenceLocator":  _purl(pkg_name, pkg_version, pkg_arch, pkg_distrib),
                }
            ],
            "annotations": [
                {
                    "annotationType": "REVIEW",
                    "annotator":      "Tool: repod",
                    "annotationDate": m.get("source", {}).get("imported_at", now),
                    "comment":        f"arch={pkg_arch} section={m.get('section','')} status={m.get('status','')}",
                }
            ],
        }
        if checksum:
            pkg["checksums"] = checksum

        packages.append(pkg)

        # Relation : REPO CONTAINS pkg
        relationships.append({
            "spdxElementId":      "SPDXRef-REPO",
            "relationshipType":   "CONTAINS",
            "relatedSpdxElement": spdx_id,
        })

        # Dépendances → DEPENDS_ON
        for dep in m.get("dependencies", []):
            dep_name = dep.get("name", "")
            if not dep_name:
                continue
            # On référence le dep par nom seulement (version inconnue)
            dep_spdx = _spdx_id(dep_name, "unknown", pkg_arch)
            relationships.append({
                "spdxElementId":      spdx_id,
                "relationshipType":   "DEPENDS_ON",
                "relatedSpdxElement": dep_spdx,
                "comment":            dep.get("version_constraint", ""),
            })

    return {
        "spdxVersion":      "SPDX-2.3",
        "dataLicense":      "CC0-1.0",
        "SPDXID":           "SPDXRef-DOCUMENT",
        "name":             doc_name,
        "documentNamespace": namespace,
        "creationInfo": {
            "created":  now,
            "creators": ["Tool: repod-2.0.0", "Organization: repod APT Repository Manager"],
            "comment":  "Generated by repod",
        },
        "packages":       packages,
        "relationships":  relationships,
    }


# ─── Point d'entrée unifié ────────────────────────────────────────────────────

def generate_sbom(
    fmt: SbomFormat,
    distribution: str | None = None,
    name: str | None = None,
    version: str | None = None,
    arch: str = "amd64",
) -> dict:
    if fmt == "spdx":
        return generate_spdx(distribution=distribution, name=name, version=version, arch=arch)
    return generate_cyclonedx(distribution=distribution, name=name, version=version, arch=arch)
