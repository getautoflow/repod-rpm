"""
Génération et lecture des manifests d'artefacts RPM.
Chaque artefact .rpm a un manifest JSON associé stocké dans /repos/manifests/.
"""
import json
import hashlib
import subprocess
import os
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))
MANIFEST_DIR.mkdir(parents=True, exist_ok=True)


def compute_sha256(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_sha512(file_path: str) -> str:
    h = hashlib.sha512()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_rpm_fields(rpm_path: str) -> dict:
    """Extrait les métadonnées d'un .rpm via rpm -qp --queryformat."""
    queryformat = (
        "NAME=%{NAME}\\n"
        "VERSION=%{VERSION}\\n"
        "RELEASE=%{RELEASE}\\n"
        "ARCH=%{ARCH}\\n"
        "SUMMARY=%{SUMMARY}\\n"
        "DESCRIPTION=%{DESCRIPTION}\\n"
        "GROUP=%{GROUP}\\n"
        "SIZE=%{SIZE}\\n"
        "LICENSE=%{LICENSE}\\n"
        "VENDOR=%{VENDOR}\\n"
        "URL=%{URL}\\n"
        "EPOCH=%{EPOCH}\\n"
        "BUILDHOST=%{BUILDHOST}\\n"
        "SOURCERPM=%{SOURCERPM}\\n"
        "PACKAGER=%{PACKAGER}\\n"
    )
    result = subprocess.run(
        ["rpm", "-qp", "--queryformat", queryformat,
         "--nosignature", "--noplugins", rpm_path],
        capture_output=True, text=True,
    )
    fields: dict = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            val = value.strip()
            if val and val != "(none)":
                fields[key.strip().lower()] = val
    return fields


def parse_rpm_requires(rpm_path: str) -> list[str]:
    """Retourne la liste brute des Requires d'un .rpm."""
    result = subprocess.run(
        ["rpm", "-qp", "--requires", "--nosignature", "--noplugins", rpm_path],
        capture_output=True, text=True,
    )
    reqs = []
    for line in result.stdout.splitlines():
        line = line.strip()
        # Filtrer les dépendances internes (rpmlib, config, etc.)
        if line and not line.startswith("rpmlib(") and not line.startswith("/"):
            reqs.append(line)
    return reqs


def parse_dependencies(requires_list: list[str]) -> list[dict]:
    """Convertit la liste de Requires en liste structurée."""
    deps = []
    for req in requires_list:
        req = req.strip()
        if not req:
            continue
        # Gérer les contraintes de version : "curl >= 7.0"
        parts = req.split()
        name = parts[0]
        version_constraint = None
        if len(parts) >= 3:
            version_constraint = f"{parts[1]} {parts[2]}"
        entry: dict = {"name": name}
        if version_constraint:
            entry["version_constraint"] = version_constraint
        deps.append(entry)
    return deps


def get_full_version(fields: dict) -> str:
    """Construit la version complète epoch:version-release."""
    epoch = fields.get("epoch", "")
    version = fields.get("version", "unknown")
    release = fields.get("release", "")
    full = f"{version}-{release}" if release else version
    if epoch and epoch not in ("0", "(none)"):
        full = f"{epoch}:{full}"
    return full


def generate_manifest(
    rpm_path: str,
    imported_by: str = "system",
    import_method: str = "upload",
    validated_deps: list[dict] | None = None,
    import_group: str | None = None,
    validation_steps: list[dict] | None = None,
    cve_results: list[dict] | None = None,
    distribution: str = "almalinux8",
) -> dict:
    """Génère un manifest complet pour un .rpm."""
    fields = parse_rpm_fields(rpm_path)
    file_size = os.path.getsize(rpm_path)

    if validated_deps is not None:
        deps = validated_deps
    else:
        requires_raw = parse_rpm_requires(rpm_path)
        deps = parse_dependencies(requires_raw)

    full_version = get_full_version(fields)

    manifest = {
        "name": fields.get("name", Path(rpm_path).stem),
        "version": full_version,
        "arch": fields.get("arch", "x86_64"),
        "section": fields.get("group", "Unspecified"),
        "description": fields.get("summary", fields.get("description", "")),
        "maintainer": fields.get("packager", fields.get("vendor", "")),
        "license": fields.get("license", ""),
        "url": fields.get("url", ""),
        "source_rpm": fields.get("sourcerpm", ""),
        "installed_size_kb": int(fields.get("size", 0) or 0) // 1024,
        "file_size_bytes": file_size,
        "filename": Path(rpm_path).name,
        "type": "rpm",
        "distribution": distribution,
        "source": {
            "imported_by": imported_by,
            "imported_at": datetime.now(timezone.utc).isoformat(),
            "import_method": import_method,
            "import_group": import_group,
        },
        "integrity": {
            "sha256": compute_sha256(rpm_path),
            "sha512": compute_sha512(rpm_path),
            "gpg_signed": False,
        },
        "dependencies": deps,
        "status": "validated",
        "tags": [],
        "validation_steps": validation_steps or [],
        "cve_results": cve_results or [],
    }
    return manifest


def save_manifest(manifest: dict) -> str:
    """Sauvegarde un manifest et retourne son chemin."""
    name = manifest["name"]
    version = manifest["version"].replace(":", "_").replace("/", "_").replace(" ", "_")
    arch = manifest["arch"]
    filename = f"{name}_{version}_{arch}.manifest.json"
    path = MANIFEST_DIR / filename
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    return str(path)


def load_manifest(name: str, version: str, arch: str = "x86_64") -> dict | None:
    version_safe = version.replace(":", "_").replace("/", "_").replace(" ", "_")
    filename = f"{name}_{version_safe}_{arch}.manifest.json"
    path = MANIFEST_DIR / filename
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def list_manifests() -> list[dict]:
    """Retourne tous les manifests disponibles."""
    manifests = []
    for path in sorted(MANIFEST_DIR.glob("*.manifest.json")):
        try:
            with open(path) as f:
                manifests.append(json.load(f))
        except Exception:
            continue
    return manifests
