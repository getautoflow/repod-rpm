"""
Index local de métadonnées RPM.

Architecture RPM vs Debian :
  - Debian : Packages.gz par dist/component/arch
  - RPM    : repomd.xml → primary.xml.gz + updateinfo.xml.gz par dépôt

Chaque dépôt RPM est un « repo » indépendant (BaseOS, AppStream, EPEL…).
On télécharge primary.xml.gz pour indexer les paquets disponibles.
On télécharge updateinfo.xml.gz pour indexer les avis de sécurité (CVE/ALSA/RHSA).
"""
import gzip
import os
import sqlite3
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

INDEX_DIR = Path(os.getenv("INDEX_DIR", "/repos/package-index"))
INDEX_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = INDEX_DIR / "packages.db"

_lock = Lock()

# ─── Sources RPM publiques ────────────────────────────────────────────────────
#
# Chaque entrée représente un dépôt RPM indépendant.
# La clé "component" décrit le rôle (baseos, appstream, extras, updates…).
# La clé "security" = True si le repo contient updateinfo.xml.gz avec des CVE.
#
# URLs validées le 2026-05-17.
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_SOURCES = [
    # ── AlmaLinux 8 ────────────────────────────────────────────────────────────
    {
        "id": "almalinux8-baseos",
        "label": "AlmaLinux 8 — BaseOS",
        "repomd_url": "https://repo.almalinux.org/almalinux/8/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux8",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,  # contient updateinfo.xml.gz avec avis ALSA
    },
    {
        "id": "almalinux8-appstream",
        "label": "AlmaLinux 8 — AppStream",
        "repomd_url": "https://repo.almalinux.org/almalinux/8/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux8",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
    },
    {
        "id": "almalinux8-extras",
        "label": "AlmaLinux 8 — Extras",
        "repomd_url": "https://repo.almalinux.org/almalinux/8/extras/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux8",
        "arch": "x86_64",
        "component": "extras",
        "security": False,
    },
    # ── AlmaLinux 9 ────────────────────────────────────────────────────────────
    {
        "id": "almalinux9-baseos",
        "label": "AlmaLinux 9 — BaseOS",
        "repomd_url": "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux8",  # mapped to almalinux8 distro for now
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
    },
    {
        "id": "almalinux9-appstream",
        "label": "AlmaLinux 9 — AppStream",
        "repomd_url": "https://repo.almalinux.org/almalinux/9/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux8",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
    },
    # ── Rocky Linux 8 ──────────────────────────────────────────────────────────
    {
        "id": "rocky8-baseos",
        "label": "Rocky Linux 8 — BaseOS",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "rocky8",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,  # contient updateinfo.xml.gz avec avis RLSA
    },
    {
        "id": "rocky8-appstream",
        "label": "Rocky Linux 8 — AppStream",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "rocky8",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
    },
    # ── Rocky Linux 9 ──────────────────────────────────────────────────────────
    {
        "id": "rocky9-baseos",
        "label": "Rocky Linux 9 — BaseOS",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "rocky8",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
    },
    {
        "id": "rocky9-appstream",
        "label": "Rocky Linux 9 — AppStream",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "rocky8",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
    },
    # ── CentOS Stream 9 ────────────────────────────────────────────────────────
    # CentOS Stream n'a PAS de updateinfo.xml.gz car c'est un rolling release.
    {
        "id": "centos-stream9-baseos",
        "label": "CentOS Stream 9 — BaseOS",
        "repomd_url": "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "centos-stream9",
        "arch": "x86_64",
        "component": "baseos",
        "security": False,
    },
    {
        "id": "centos-stream9-appstream",
        "label": "CentOS Stream 9 — AppStream",
        "repomd_url": "https://mirror.stream.centos.org/9-stream/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "centos-stream9",
        "arch": "x86_64",
        "component": "appstream",
        "security": False,
    },
    # ── Oracle Linux 8 ─────────────────────────────────────────────────────────
    {
        "id": "oraclelinux8-baseos",
        "label": "Oracle Linux 8 — BaseOS",
        "repomd_url": "https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/repodata/repomd.xml",
        "distro": "oraclelinux8",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
    },
    {
        "id": "oraclelinux8-appstream",
        "label": "Oracle Linux 8 — AppStream",
        "repomd_url": "https://yum.oracle.com/repo/OracleLinux/OL8/appstream/x86_64/repodata/repomd.xml",
        "distro": "oraclelinux8",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
    },
    # ── Oracle Linux 9 ─────────────────────────────────────────────────────────
    {
        "id": "oraclelinux9-baseos",
        "label": "Oracle Linux 9 — BaseOS",
        "repomd_url": "https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64/repodata/repomd.xml",
        "distro": "oraclelinux8",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
    },
    # ── Fedora 42 ──────────────────────────────────────────────────────────────
    # Fedora utilise dl.fedoraproject.org (CDN direct, pas de metalink).
    # Fedora 42 = version stable courante en mai 2026.
    {
        "id": "fedora42",
        "label": "Fedora 42 — Everything",
        "repomd_url": "https://dl.fedoraproject.org/pub/fedora/linux/releases/42/Everything/x86_64/os/repodata/repomd.xml",
        "distro": "fedora",
        "arch": "x86_64",
        "component": "everything",
        "security": False,
    },
    {
        "id": "fedora42-updates",
        "label": "Fedora 42 — Updates",
        "repomd_url": "https://dl.fedoraproject.org/pub/fedora/linux/updates/42/Everything/x86_64/repodata/repomd.xml",
        "distro": "fedora",
        "arch": "x86_64",
        "component": "updates",
        "security": True,  # updates contient des avis de sécurité
    },
    # ── EPEL (Extra Packages for Enterprise Linux) ─────────────────────────────
    # EPEL est incontournable en environnement entreprise RHEL/CentOS.
    {
        "id": "epel8",
        "label": "EPEL 8 — Extra Packages",
        "repomd_url": "https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/repodata/repomd.xml",
        "distro": "almalinux8",
        "arch": "x86_64",
        "component": "epel",
        "security": False,
    },
    {
        "id": "epel9",
        "label": "EPEL 9 — Extra Packages",
        "repomd_url": "https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/repodata/repomd.xml",
        "distro": "rocky8",
        "arch": "x86_64",
        "component": "epel",
        "security": False,
    },
    # ── openSUSE Leap 15.6 ─────────────────────────────────────────────────────
    # openSUSE sépare OSS (paquets libres) des updates dans deux dépôts distincts.
    {
        "id": "opensuse-leap-15.6-oss",
        "label": "openSUSE Leap 15.6 — OSS",
        "repomd_url": "https://download.opensuse.org/distribution/leap/15.6/repo/oss/repodata/repomd.xml",
        "distro": "opensuse-leap-15.6",
        "arch": "x86_64",
        "component": "oss",
        "security": False,
    },
    {
        "id": "opensuse-leap-15.6-updates",
        "label": "openSUSE Leap 15.6 — Updates",
        "repomd_url": "https://download.opensuse.org/update/leap/15.6/oss/repodata/repomd.xml",
        "distro": "opensuse-leap-15.6",
        "arch": "x86_64",
        "component": "updates",
        "security": True,  # les updates openSUSE contiennent des avis SUSE Security Advisory
    },
    # ── openSUSE Tumbleweed ─────────────────────────────────────────────────────
    # Tumbleweed = rolling release, pas de notion "updates" distincte.
    {
        "id": "opensuse-tumbleweed-oss",
        "label": "openSUSE Tumbleweed — OSS",
        "repomd_url": "https://download.opensuse.org/tumbleweed/repo/oss/repodata/repomd.xml",
        "distro": "opensuse-tumbleweed",
        "arch": "x86_64",
        "component": "oss",
        "security": True,
    },
]


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crée le schéma SQLite si nécessaire."""
    with _get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS packages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id   TEXT NOT NULL,
                name        TEXT NOT NULL,
                version     TEXT NOT NULL,
                arch        TEXT,
                summary     TEXT,
                description TEXT,
                group_name  TEXT,
                size        INTEGER,
                license     TEXT,
                url         TEXT,
                rpm_url     TEXT,
                sha256      TEXT,
                requires    TEXT,
                provides    TEXT,
                synced_at   TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_pkg_source_name_ver
                ON packages(source_id, name, version);
            CREATE INDEX IF NOT EXISTS idx_pkg_name ON packages(name);

            CREATE TABLE IF NOT EXISTS sync_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id   TEXT NOT NULL,
                status      TEXT NOT NULL,
                pkg_count   INTEGER,
                error       TEXT,
                synced_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS import_groups (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL UNIQUE,
                package_count INTEGER DEFAULT 0,
                total_size_bytes INTEGER DEFAULT 0,
                distribution TEXT,
                imported_by TEXT,
                imported_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS import_group_files (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                group_name  TEXT NOT NULL,
                filename    TEXT NOT NULL,
                size_bytes  INTEGER DEFAULT 0,
                FOREIGN KEY (group_name) REFERENCES import_groups(name) ON DELETE CASCADE
            );
        """)
        # Migration : ajout de la colonne provides si absente (bases existantes)
        try:
            conn.execute("ALTER TABLE packages ADD COLUMN provides TEXT")
        except Exception:
            pass  # colonne déjà présente


# ─── Parsing repomd.xml ───────────────────────────────────────────────────────

def _fetch_metadata_url(repomd_url: str, metadata_type: str = "primary") -> str | None:
    """
    Télécharge repomd.xml et extrait l'URL d'un fichier de métadonnées.

    Dans l'écosystème RPM, repomd.xml est le point d'entrée du dépôt.
    Il liste tous les fichiers de métadonnées :
      - primary.xml.gz      : liste des paquets (nom, version, URL de téléchargement)
      - filelists.xml.gz    : liste des fichiers fournis par chaque paquet
      - other.xml.gz        : changelogs
      - updateinfo.xml.gz   : avis de sécurité (RHSA/ALSA/RLSA/SUSE-SU)
      - comps.xml           : groupes de paquets (équivalent RPM des tasksel Debian)
    """
    try:
        req = urllib.request.Request(repomd_url, headers={"User-Agent": "RPM-Repo-Manager/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            repomd_data = resp.read()
    except Exception:
        return None

    try:
        tree = ET.fromstring(repomd_data)
        ns = {"r": "http://linux.duke.edu/metadata/repo"}
        for data in tree.findall("r:data", ns):
            if data.get("type") == metadata_type:
                loc = data.find("r:location", ns)
                if loc is not None:
                    href = loc.get("href", "")
                    base = repomd_url.rsplit("/repodata/", 1)[0]
                    # href est relatif à la racine du dépôt (ex: "repodata/abc123-primary.xml.gz")
                    return f"{base}/{href}"
    except Exception:
        pass
    return None


def _fetch_primary_xml_url(repomd_url: str) -> str | None:
    return _fetch_metadata_url(repomd_url, "primary")


def _fetch_updateinfo_xml_url(repomd_url: str) -> str | None:
    return _fetch_metadata_url(repomd_url, "updateinfo")


# ─── Parsing primary.xml.gz ───────────────────────────────────────────────────

def _parse_package_elem(pkg, ns_common: str, ns_rpm: str) -> dict | None:
    """Extrait les métadonnées d'un élément <package> primary.xml."""
    ns = {"p": ns_common, "rpm": ns_rpm}
    name_el    = pkg.find("p:name", ns)
    version_el = pkg.find("p:version", ns)
    if name_el is None or version_el is None:
        return None

    arch_el     = pkg.find("p:arch", ns)
    summary_el  = pkg.find("p:summary", ns)
    desc_el     = pkg.find("p:description", ns)
    url_el      = pkg.find("p:url", ns)
    location_el = pkg.find("p:location", ns)
    size_el     = pkg.find("p:size", ns)
    checksum_el = pkg.find("p:checksum", ns)
    group_el    = pkg.find(f"p:format/p:group", ns)

    ver   = version_el.get("ver", "")
    rel   = version_el.get("rel", "")
    epoch = version_el.get("epoch", "0")
    version = f"{ver}-{rel}" if rel else ver
    if epoch and epoch != "0":
        version = f"{epoch}:{version}"

    rpm_url = location_el.get("href", "") if location_el is not None else ""

    sha256 = ""
    if checksum_el is not None and checksum_el.get("type", "") in ("sha256", "sha"):
        sha256 = checksum_el.text or ""

    installed_size = 0
    if size_el is not None:
        try:
            installed_size = int(size_el.get("installed", 0))
        except (ValueError, TypeError):
            pass

    requires_els = pkg.findall(f"p:format/rpm:requires/rpm:entry", ns)
    requires = ",".join(
        el.get("name", "")
        for el in requires_els
        if el.get("name")
        and not el.get("name", "").startswith("rpmlib(")
        and not el.get("name", "").startswith("/")
    )

    provides_els = pkg.findall(f"p:format/rpm:provides/rpm:entry", ns)
    provides = ",".join(
        el.get("name", "")
        for el in provides_els
        if el.get("name")
    )

    return {
        "name":        name_el.text or "",
        "version":     version,
        "arch":        arch_el.text if arch_el is not None else "x86_64",
        "summary":     summary_el.text if summary_el is not None else "",
        "description": desc_el.text if desc_el is not None else "",
        "group_name":  group_el.text if group_el is not None else "",
        "size":        installed_size,
        "url":         url_el.text if url_el is not None else "",
        "rpm_url":     rpm_url,
        "sha256":      sha256,
        "requires":    requires,
        "provides":    provides,
    }


def _stream_parse_primary_xml(xml_bytes: bytes, source_id: str, batch_size: int = 200) -> int:
    """
    Parse primary.xml en streaming avec iterparse + insertion SQLite par lots.

    Utilise iterparse + elem.clear() pour éviter de charger tout le DOM en mémoire.
    Les grands primary.xml (AlmaLinux 8 BaseOS ≈ 50 MB, 1800+ paquets) causaient
    un OOM avec ET.fromstring() qui construisait un arbre de ~1.5 GB.

    Retourne le nombre de paquets insérés, ou -1 en cas d'erreur.
    """
    import io

    ns_common = "http://linux.duke.edu/metadata/common"
    ns_rpm    = "http://linux.duke.edu/metadata/rpm"
    pkg_tag   = f"{{{ns_common}}}package"

    now = datetime.now(timezone.utc).isoformat()
    total = 0
    batch: list[tuple] = []
    first_batch = True

    def _flush(conn, clear_table: bool = False):
        nonlocal total, batch, first_batch
        if clear_table:
            conn.execute("DELETE FROM packages WHERE source_id = ?", (source_id,))
        if batch:
            conn.executemany(
                """INSERT OR REPLACE INTO packages
                   (source_id, name, version, arch, summary, description, group_name,
                    size, url, rpm_url, sha256, requires, provides, synced_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                batch,
            )
            total += len(batch)
            batch = []

    try:
        stream = io.BytesIO(xml_bytes)
        context = ET.iterparse(stream, events=("start", "end"))
        root = None
        with _lock:
            with _get_db() as conn:
                for event, elem in context:
                    if event == "start" and root is None:
                        root = elem
                        continue
                    if event != "end" or elem.tag != pkg_tag:
                        continue
                    try:
                        pkg = _parse_package_elem(elem, ns_common, ns_rpm)
                        if pkg:
                            batch.append((
                                source_id, pkg["name"], pkg["version"], pkg["arch"],
                                pkg["summary"], pkg["description"], pkg["group_name"],
                                pkg["size"], pkg["url"], pkg["rpm_url"],
                                pkg["sha256"], pkg["requires"], pkg.get("provides", ""), now,
                            ))
                    except Exception:
                        pass

                    if root is not None:
                        root.clear()

                    if len(batch) >= batch_size:
                        _flush(conn, clear_table=first_batch)
                        first_batch = False

                if batch or first_batch:
                    _flush(conn, clear_table=first_batch)

    except Exception:
        return -1

    return total


def _open_streaming_decompressor(response, url: str):
    """
    Retourne un objet fichier décompressant à la volée depuis une réponse HTTP
    en streaming. Ne charge jamais le contenu entier en mémoire.

    Formats supportés : .gz, .xz, .bz2, .zst (Fedora 38+, openSUSE…)
    """
    if url.endswith(".gz"):
        import gzip as _gzip
        return _gzip.GzipFile(fileobj=response)
    if url.endswith(".xz"):
        import lzma as _lzma
        # lzma.open() n'accepte pas directement un socket urllib ; on passe par un wrapper
        class _LzmaStream:
            def __init__(self, src):
                self._dec = _lzma.LZMADecompressor()
                self._src = src
                self._buf = b""
            def read(self, n=-1):
                while len(self._buf) < (n if n > 0 else 1):
                    chunk = self._src.read(65536)
                    if not chunk:
                        break
                    self._buf += self._dec.decompress(chunk)
                if n < 0:
                    out, self._buf = self._buf, b""
                else:
                    out, self._buf = self._buf[:n], self._buf[n:]
                return out
        return _LzmaStream(response)
    if url.endswith(".bz2"):
        import bz2 as _bz2
        class _Bz2Stream:
            def __init__(self, src):
                self._dec = _bz2.BZ2Decompressor()
                self._src = src
                self._buf = b""
            def read(self, n=-1):
                while len(self._buf) < (n if n > 0 else 1):
                    chunk = self._src.read(65536)
                    if not chunk:
                        break
                    self._buf += self._dec.decompress(chunk)
                if n < 0:
                    out, self._buf = self._buf, b""
                else:
                    out, self._buf = self._buf[:n], self._buf[n:]
                return out
        return _Bz2Stream(response)
    if url.endswith(".zst"):
        try:
            import zstandard as _zstd
            dctx = _zstd.ZstdDecompressor()
            return dctx.stream_reader(response)
        except ImportError:
            pass
    # Pas de compression reconnue → retour brut
    return response


def _stream_download_and_parse(url: str, source_id: str,
                               batch_size: int = 200, timeout: int = 300) -> int:
    """
    Pipeline 100 % streaming : télécharge, décompresse et parse primary.xml
    sans jamais charger le contenu entier en mémoire.

    Retourne le nombre de paquets insérés, ou -1 en cas d'erreur.
    Supporte les très grands primary.xml (Oracle Linux 8 ≈ 600 MB XML).
    """
    ns_common = "http://linux.duke.edu/metadata/common"
    ns_rpm    = "http://linux.duke.edu/metadata/rpm"
    pkg_tag   = f"{{{ns_common}}}package"
    now       = datetime.now(timezone.utc).isoformat()
    total     = 0
    batch: list[tuple] = []
    first_batch = True

    def _flush(conn, clear_table: bool = False):
        nonlocal total, batch, first_batch
        if clear_table:
            conn.execute("DELETE FROM packages WHERE source_id = ?", (source_id,))
        if batch:
            conn.executemany(
                """INSERT OR REPLACE INTO packages
                   (source_id, name, version, arch, summary, description, group_name,
                    size, url, rpm_url, sha256, requires, provides, synced_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                batch,
            )
            total += len(batch)
            batch = []

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RPM-Repo-Manager/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as raw_resp:
            xml_stream = _open_streaming_decompressor(raw_resp, url)
            # events=("start", "end") : on capture "start" uniquement pour récupérer
            # la référence à l'élément racine afin de libérer la mémoire après chaque
            # paquet (root.clear() supprime les enfants déjà traités du DOM).
            # IMPORTANT : ne PAS appeler elem.clear() sur les éléments enfants d'un
            # <package> — cela efface leur .text avant que le parent soit traité,
            # ce qui produit des noms/versions vides dans la base.
            context = ET.iterparse(xml_stream, events=("start", "end"))
            root = None
            with _lock:
                with _get_db() as conn:
                    for event, elem in context:
                        if event == "start" and root is None:
                            root = elem  # premier élément = <metadata>
                            continue
                        if event != "end" or elem.tag != pkg_tag:
                            continue
                        try:
                            pkg = _parse_package_elem(elem, ns_common, ns_rpm)
                            if pkg:
                                batch.append((
                                    source_id, pkg["name"], pkg["version"], pkg["arch"],
                                    pkg["summary"], pkg["description"], pkg["group_name"],
                                    pkg["size"], pkg["url"], pkg["rpm_url"],
                                    pkg["sha256"], pkg["requires"], pkg.get("provides", ""), now,
                                ))
                        except Exception:
                            pass

                        # Libérer la mémoire : supprimer le paquet traité du DOM racine
                        if root is not None:
                            root.clear()

                        if len(batch) >= batch_size:
                            _flush(conn, clear_table=first_batch)
                            first_batch = False

                    if batch or first_batch:
                        _flush(conn, clear_table=first_batch)

    except Exception:
        return -1

    return total


# ─── Synchronisation d'une source ────────────────────────────────────────────

def sync_source(source: dict) -> dict:
    """
    Synchronise une source RPM dans l'index SQLite.

    Processus :
      1. Télécharger repomd.xml → URL de primary.xml
      2. Télécharger en streaming + décompresser à la volée (gzip/xz/bz2/zst)
      3. Parser avec iterparse directement depuis le flux → 0 byte chargé en RAM
         → supporte les grands primary.xml (Oracle Linux 8 BaseOS ≈ 600 MB XML)
    """
    init_db()
    source_id  = source["id"]
    repomd_url = source.get("repomd_url", "")

    primary_url = _fetch_primary_xml_url(repomd_url)
    if not primary_url:
        err = f"Impossible de localiser primary.xml dans repomd.xml ({repomd_url})"
        _log_sync(source_id, "error", 0, err)
        return {"source_id": source_id, "status": "error", "error": err}

    pkg_count = _stream_download_and_parse(primary_url, source_id)

    if pkg_count < 0:
        err = f"Téléchargement ou parsing de primary.xml échoué ({primary_url})"
        _log_sync(source_id, "error", 0, err)
        return {"source_id": source_id, "status": "error", "error": err}

    if pkg_count == 0:
        err = "Aucun paquet parsé depuis primary.xml"
        _log_sync(source_id, "error", 0, err)
        return {"source_id": source_id, "status": "error", "error": err}

    _log_sync(source_id, "ok", pkg_count, None)

    return {
        "source_id": source_id,
        "status":    "ok",
        "pkg_count": pkg_count,
        "label":     source.get("label", source_id),
    }


def _log_sync(source_id: str, status: str, pkg_count: int, error: str | None,
              conn=None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    if conn:
        conn.execute(
            "INSERT INTO sync_log (source_id, status, pkg_count, error, synced_at) VALUES (?, ?, ?, ?, ?)",
            (source_id, status, pkg_count, error, now),
        )
    else:
        with _get_db() as c:
            c.execute(
                "INSERT INTO sync_log (source_id, status, pkg_count, error, synced_at) VALUES (?, ?, ?, ?, ?)",
                (source_id, status, pkg_count, error, now),
            )


# ─── Recherche dans l'index ───────────────────────────────────────────────────

def get_package_info(name: str) -> dict | None:
    """Cherche un paquet par nom exact dans l'index local."""
    init_db()
    with _get_db() as conn:
        row = conn.execute(
            "SELECT * FROM packages WHERE name = ? ORDER BY synced_at DESC LIMIT 1",
            (name,),
        ).fetchone()
    return dict(row) if row else None


def resolve_provide_to_package(provide: str) -> dict | None:
    """
    Résout une capability RPM (provide) vers le paquet qui la fournit.
    Ex: 'libc.so.6(GLIBC_2.34)(64bit)' → {name: 'glibc', ...}

    Cherche d'abord par nom exact, puis dans la colonne provides.
    """
    init_db()
    # 1. Nom exact
    pkg = get_package_info(provide)
    if pkg:
        return pkg
    # 2. Recherche dans les provides
    with _get_db() as conn:
        row = conn.execute(
            """SELECT * FROM packages
               WHERE provides LIKE ?
               ORDER BY synced_at DESC LIMIT 1""",
            (f"%{provide}%",),
        ).fetchone()
    return dict(row) if row else None


def search_packages(query: str, limit: int = 50, source_id: str | None = None) -> list[dict]:
    """Recherche des paquets par nom ou résumé dans l'index local."""
    init_db()
    with _get_db() as conn:
        if source_id:
            rows = conn.execute(
                """SELECT * FROM packages
                   WHERE source_id = ? AND (name LIKE ? OR summary LIKE ?)
                   ORDER BY name LIMIT ?""",
                (source_id, f"%{query}%", f"%{query}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM packages
                   WHERE name LIKE ? OR summary LIKE ?
                   ORDER BY name LIMIT ?""",
                (f"%{query}%", f"%{query}%", limit),
            ).fetchall()
    return [dict(r) for r in rows]


# ─── Statistiques de synchronisation ─────────────────────────────────────────

def get_sync_stats() -> list[dict]:
    """
    Retourne l'état de synchronisation de chaque source.
    'never' si jamais synchronisée, 'ok'/'error' sinon.
    """
    init_db()
    result = []
    with _get_db() as conn:
        for source in DEFAULT_SOURCES:
            sid = source["id"]
            row = conn.execute(
                """SELECT pkg_count, synced_at, status, error
                   FROM sync_log WHERE source_id = ?
                   ORDER BY id DESC LIMIT 1""",
                (sid,),
            ).fetchone()
            result.append({
                "id":        sid,
                "label":     source.get("label", sid),
                "distro":    source.get("distro", ""),
                "arch":      source.get("arch", "x86_64"),
                "component": source.get("component", ""),
                "security":  source.get("security", False),
                "pkg_count": row["pkg_count"] if row else 0,
                "last_sync": row["synced_at"] if row else None,
                "status":    row["status"] if row else "never",
                "error":     row["error"] if row else None,
            })
    return result


# ─── Groupes d'import ────────────────────────────────────────────────────────

def record_import_group(
    name: str,
    files: list[dict],
    distribution: str,
    imported_by: str,
) -> None:
    """
    Enregistre un groupe d'import (ensemble de .rpm téléchargés ensemble).
    files = [{"filename": "nginx-1.24.rpm", "size_bytes": 1234567}, …]
    """
    init_db()
    total_size = sum(f.get("size_bytes", 0) for f in files)
    now = datetime.now(timezone.utc).isoformat()
    with _get_db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO import_groups
               (name, package_count, total_size_bytes, distribution, imported_by, imported_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, len(files), total_size, distribution, imported_by, now),
        )
        conn.execute("DELETE FROM import_group_files WHERE group_name = ?", (name,))
        conn.executemany(
            "INSERT INTO import_group_files (group_name, filename, size_bytes) VALUES (?, ?, ?)",
            [(name, f["filename"], f.get("size_bytes", 0)) for f in files],
        )


def get_import_groups() -> list[dict]:
    """Retourne tous les groupes d'import avec leurs fichiers."""
    init_db()
    with _get_db() as conn:
        groups = conn.execute(
            "SELECT * FROM import_groups ORDER BY imported_at DESC"
        ).fetchall()
        result = []
        for g in groups:
            files = conn.execute(
                "SELECT filename, size_bytes FROM import_group_files WHERE group_name = ?",
                (g["name"],),
            ).fetchall()
            result.append({
                **dict(g),
                "packages": [dict(f) for f in files],
            })
    return result


def delete_import_group(name: str) -> bool:
    """Supprime un groupe d'import (cascade sur les fichiers)."""
    init_db()
    with _get_db() as conn:
        conn.execute("DELETE FROM import_group_files WHERE group_name = ?", (name,))
        conn.execute("DELETE FROM import_groups WHERE name = ?", (name,))
    return True
