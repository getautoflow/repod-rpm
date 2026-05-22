"""
services/sarif.py — [G] Export SARIF 2.1.0 (GitHub Code Scanning / SonarQube)

Génère un document SARIF 2.1.0 depuis les manifests CVE du dépôt RPM.

Mapping sévérité → level :
  Critical / High  → "error"
  Medium           → "warning"
  Low / Negligible → "note"
  Inconnu          → "none"

Référence : https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

from services.manifest import list_manifests, load_manifest

# ── Constantes SARIF ──────────────────────────────────────────────────────────

_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_DRIVER_NAME    = "repod"
_DRIVER_VERSION = "1.0.0"

_LEVEL_MAP: dict[str, str] = {
    "critical":   "error",
    "high":       "error",
    "medium":     "warning",
    "low":        "note",
    "negligible": "note",
}


# ── Helpers privés ────────────────────────────────────────────────────────────

def _severity_to_level(severity: str) -> str:
    """Convertit une sévérité Grype en level SARIF."""
    return _LEVEL_MAP.get((severity or "").lower(), "none")


def _build_rule(cve: dict) -> dict:
    """Construit un objet rule SARIF depuis une entrée CVE."""
    cve_id       = cve.get("id", "UNKNOWN")
    severity     = cve.get("severity", "Unknown")
    description  = cve.get("description", cve_id)
    fix_state    = cve.get("fix_state", "")
    fix_versions = cve.get("fix_versions") or []
    urls         = cve.get("urls") or []

    # help.text — info de correction lisible
    if fix_state == "fixed" and fix_versions:
        help_text = f"Fix disponible en version {', '.join(str(v) for v in fix_versions)}."
    else:
        help_text = f"État du correctif : {fix_state or 'inconnu'}."
    if urls:
        help_text += f" Référence : {urls[0]}"

    return {
        "id": cve_id,
        "shortDescription": {"text": f"{cve_id} — {severity}"},
        "fullDescription":  {"text": description},
        "defaultConfiguration": {"level": _severity_to_level(severity)},
        "help": {"text": help_text},
        "properties": {"severity": severity},
    }


def _build_result(cve: dict, manifest: dict, rule_index: int) -> dict:
    """Construit un objet result SARIF pour une paire (CVE × paquet RPM)."""
    cve_id   = cve.get("id", "UNKNOWN")
    severity = cve.get("severity", "Unknown")
    pkg_name = manifest.get("name", "unknown")
    pkg_ver  = manifest.get("version", "unknown")
    arch     = manifest.get("arch", "x86_64")
    filename = manifest.get("filename", f"{pkg_name}-{pkg_ver}.{arch}.rpm")
    in_kev   = bool(cve.get("in_kev", False))

    message = (
        f"La vulnérabilité {cve_id} ({severity}) affecte le paquet RPM "
        f"{pkg_name} version {pkg_ver}."
    )

    result: dict = {
        "ruleId":    cve_id,
        "ruleIndex": rule_index,
        "level":     _severity_to_level(severity),
        "message":   {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": filename},
                }
            }
        ],
    }

    if in_kev:
        result["properties"] = {"kev": True}

    return result


# ── API publique ──────────────────────────────────────────────────────────────

def generate_sarif(
    distribution: str | None = None,
    name: str | None = None,
    version: str | None = None,
    arch: str = "x86_64",
) -> dict:
    """
    Génère un document SARIF 2.1.0 depuis les manifests CVE RPM.

    Filtres (optionnels, mutuellement prioritaires) :
      name + version → exporte un seul paquet (via load_manifest)
      distribution   → filtre par distribution RPM (via list_manifests)
      arch           → architecture cible (défaut : x86_64)

    Règles de construction :
      • Une rule par CVE unique (dédupliquée sur l'ensemble des paquets).
      • Un result par couple (CVE × paquet).
      • Le ruleIndex pointe vers la position de la rule dans driver.rules.
    """
    # ── 1. Récupération des manifests ─────────────────────────────────────────
    if name and version:
        m = load_manifest(name, version, arch)
        manifests: list[dict] = [m] if m is not None else []
    else:
        manifests = list_manifests()
        if distribution:
            manifests = [
                m for m in manifests
                if m.get("distribution") == distribution
            ]

    # ── 2. Règles — dédupliquées par CVE ID ──────────────────────────────────
    seen: dict[str, int] = {}   # cve_id → index dans rules[]
    rules: list[dict] = []

    for manifest in manifests:
        for cve in manifest.get("cve_results") or []:
            cve_id = cve.get("id")
            if not cve_id:
                continue
            if cve_id not in seen:
                seen[cve_id] = len(rules)
                rules.append(_build_rule(cve))

    # ── 3. Résultats — un par (CVE × paquet RPM) ─────────────────────────────
    results: list[dict] = []

    for manifest in manifests:
        for cve in manifest.get("cve_results") or []:
            cve_id = cve.get("id")
            if not cve_id or cve_id not in seen:
                continue
            results.append(_build_result(cve, manifest, seen[cve_id]))

    # ── 4. Document SARIF 2.1.0 ──────────────────────────────────────────────
    return {
        "$schema": _SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":    _DRIVER_NAME,
                        "version": _DRIVER_VERSION,
                        "rules":   rules,
                    }
                },
                "results": results,
            }
        ],
    }
