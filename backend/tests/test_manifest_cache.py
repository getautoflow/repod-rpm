"""
Module : test_manifest_cache.py
Rôle   : Cache in-memory pour list_manifests()
         Vérifie que les appels répétés ne déclenchent pas N lectures disque
         et que le cache est invalidé correctement à chaque save_manifest().

Adapté depuis repod-apt → RPM (règle R5) :
  amd64 → x86_64 | .deb → .rpm | jammy → almalinux8

Dépend : pytest, unittest.mock, services.manifest
"""

# ── Chemins temp avant tout import ────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_manifest_cache_")
os.environ["MANIFEST_DIR"] = _TMP
os.environ.setdefault("POOL_DIR", _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
import json
from pathlib import Path
from threading import Thread
from unittest.mock import patch

import pytest

import services.manifest as _manifest_mod
from services.manifest import (
    list_manifests,
    save_manifest,
    invalidate_manifest_cache,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

_MANIFEST_DIR = Path(_TMP)
_manifest_mod.MANIFEST_DIR = _MANIFEST_DIR


def _write_manifest_file(name: str, version: str, arch: str = "x86_64") -> Path:
    """Crée un fichier *.manifest.json minimal RPM dans le répertoire de test."""
    data = {
        "name": name,
        "version": version,
        "arch": arch,
        "section": "Applications/Internet",
        "description": f"Test RPM package {name}",
        "maintainer": "vendor@example.com",
        "license": "MIT",
        "installed_size_kb": 100,
        "file_size_bytes": 1024,
        "filename": f"{name}-{version}.{arch}.rpm",
        "type": "rpm",
        "distribution": "almalinux8",
        "source": {
            "imported_by": "test",
            "imported_at": "2025-01-01T00:00:00+00:00",
            "import_method": "upload",
            "import_group": None,
        },
        "integrity": {"sha256": "abc123", "sha512": "def456", "gpg_signed": False},
        "dependencies": [],
        "status": "validated",
        "tags": [],
        "validation_steps": [],
        "cve_results": [],
    }
    safe_ver = version.replace(":", "_").replace("/", "_")
    path = _MANIFEST_DIR / f"{name}_{safe_ver}_{arch}.manifest.json"
    path.write_text(json.dumps(data))
    return path


@pytest.fixture(autouse=True)
def clean_state():
    """Réinitialise le répertoire et le cache avant/après chaque test."""
    _manifest_mod.MANIFEST_DIR = _MANIFEST_DIR
    for f in _MANIFEST_DIR.glob("*.manifest.json"):
        f.unlink(missing_ok=True)
    invalidate_manifest_cache()
    yield
    for f in _MANIFEST_DIR.glob("*.manifest.json"):
        f.unlink(missing_ok=True)
    invalidate_manifest_cache()


# ═══════════════════════════════════════════════════════════════════════════════
# Comportement de base du cache
# ═══════════════════════════════════════════════════════════════════════════════

class TestListManifestsCache:

    def test_cold_cache_returns_manifests_from_disk(self):
        """Premier appel → lit le disque et retourne les manifests."""
        _write_manifest_file("nginx", "1.24.0")
        _write_manifest_file("curl",  "7.88.0")

        result = list_manifests()
        names = {m["name"] for m in result}
        assert "nginx" in names
        assert "curl" in names
        assert len(result) == 2

    def test_second_call_uses_cache_not_disk(self):
        """
        ❌ ROUGE avant fix : chaque appel relit le disque (N × open())
        ✅ VERT après fix  : le cache répond sans accès disque supplémentaire
        """
        _write_manifest_file("nginx", "1.24.0")

        list_manifests()  # remplit le cache

        with patch("builtins.open") as mock_open:
            result = list_manifests()

        mock_open.assert_not_called()
        assert len(result) == 1
        assert result[0]["name"] == "nginx"

    def test_multiple_calls_hit_disk_only_once(self):
        """N appels successifs → json.load() appelé 1 seule fois."""
        _write_manifest_file("vim", "9.0")
        invalidate_manifest_cache()

        import services.manifest as _mod

        with patch.object(_mod.json, "load", wraps=_mod.json.load) as mock_load:
            for _ in range(5):
                list_manifests()

        assert mock_load.call_count == 1, (
            f"json.load() appelé {mock_load.call_count} fois — le cache ne fonctionne pas"
        )

    def test_cache_returns_consistent_data_across_calls(self):
        """Les données retournées sont identiques entre deux appels successifs."""
        _write_manifest_file("openssl", "3.0.2")

        first  = list_manifests()
        second = list_manifests()

        assert first == second

    def test_empty_dir_returns_empty_list_and_caches(self):
        """Répertoire vide → liste vide, mise en cache effective."""
        result1 = list_manifests()
        result2 = list_manifests()
        assert result1 == []
        assert result2 == []

    def test_cache_returns_copy_not_reference(self):
        """Muter le résultat de list_manifests() ne doit pas corrompre le cache."""
        _write_manifest_file("libssl", "3.0.0")

        first_result = list_manifests()
        first_result.clear()  # mutation intentionnelle

        second_result = list_manifests()
        assert len(second_result) == 1  # le cache est intact


# ═══════════════════════════════════════════════════════════════════════════════
# Invalidation du cache
# ═══════════════════════════════════════════════════════════════════════════════

class TestCacheInvalidation:

    def test_invalidate_manifest_cache_forces_disk_read(self):
        """invalidate_manifest_cache() → le prochain appel relit le disque."""
        _write_manifest_file("nginx", "1.24.0")
        list_manifests()  # remplit le cache

        _write_manifest_file("curl", "7.88.0")
        invalidate_manifest_cache()
        result = list_manifests()

        names = {m["name"] for m in result}
        assert "nginx" in names
        assert "curl" in names

    def test_save_manifest_invalidates_cache(self):
        """save_manifest() invalide le cache → le prochain list_manifests() voit le nouveau fichier."""
        _write_manifest_file("nginx", "1.24.0")
        before = list_manifests()
        assert len(before) == 1

        new_manifest = {
            "name": "curl", "version": "7.88.0", "arch": "x86_64",
            "section": "Applications/Internet", "description": "curl",
            "maintainer": "vendor@example.com", "license": "MIT",
            "installed_size_kb": 50, "file_size_bytes": 512,
            "filename": "curl-7.88.0.x86_64.rpm",
            "type": "rpm", "distribution": "almalinux8",
            "source": {
                "imported_by": "test", "imported_at": "2025-01-01T00:00:00+00:00",
                "import_method": "upload", "import_group": None,
            },
            "integrity": {"sha256": "xyz", "sha512": "uvw", "gpg_signed": False},
            "dependencies": [], "status": "validated", "tags": [],
            "validation_steps": [], "cve_results": [],
        }
        save_manifest(new_manifest)

        after = list_manifests()
        names = {m["name"] for m in after}
        assert "nginx" in names
        assert "curl" in names
        assert len(after) == 2

    def test_cache_expires_after_ttl(self):
        """Après expiration du TTL, le prochain appel relit le disque."""
        _write_manifest_file("nginx", "1.24.0")

        clock = [0.0]

        def fake_monotonic():
            return clock[0]

        with patch("services.manifest.time") as mock_time:
            mock_time.monotonic.side_effect = fake_monotonic

            list_manifests()  # t=0, cache rempli

            clock[0] = 5.0   # dans le TTL
            with patch("builtins.open") as mock_open:
                list_manifests()
            mock_open.assert_not_called()

            clock[0] = 35.0  # TTL expiré
            _write_manifest_file("curl", "7.88.0")
            result = list_manifests()

        names = {m["name"] for m in result}
        assert "curl" in names

    def test_explicit_invalidation_then_empty_dir(self):
        """Invalidation explicite sur répertoire vide → [] et cache rechargé."""
        _write_manifest_file("nginx", "1.24.0")
        list_manifests()

        for f in _MANIFEST_DIR.glob("*.manifest.json"):
            f.unlink()

        invalidate_manifest_cache()
        result = list_manifests()
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
# Thread safety
# ═══════════════════════════════════════════════════════════════════════════════

class TestCacheThreadSafety:

    def test_concurrent_reads_return_consistent_data(self):
        """
        Plusieurs threads appelant list_manifests() simultanément
        doivent tous recevoir les mêmes données sans corruption.
        """
        _write_manifest_file("nginx",   "1.24.0")
        _write_manifest_file("curl",    "7.88.0")
        _write_manifest_file("openssl", "3.0.2")

        results: list[list] = []

        def read():
            results.append(list_manifests())

        threads = [Thread(target=read) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(len(r) == 3 for r in results)
        ref_names = {m["name"] for m in results[0]}
        assert all({m["name"] for m in r} == ref_names for r in results)
