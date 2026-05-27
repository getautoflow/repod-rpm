#!/bin/bash
set -e

CLAMAV_DB_DIR="${CLAMAV_DB_DIR:-/var/lib/clamav}"
ENV="${ENV:-development}"

# ─── ClamAV ──────────────────────────────────────────────────────────────────

echo "[entrypoint] Initialisation ClamAV..."

chown -R clamav:clamav "$CLAMAV_DB_DIR" 2>/dev/null || true
chmod -R g+w "$CLAMAV_DB_DIR" 2>/dev/null || true
usermod -aG clamav appuser 2>/dev/null || true
mkdir -p /var/log/clamav && chown clamav:clamav /var/log/clamav && chmod g+w /var/log/clamav 2>/dev/null || true

if [ ! -f "$CLAMAV_DB_DIR/main.cvd" ] && [ ! -f "$CLAMAV_DB_DIR/main.cld" ]; then
    echo "[entrypoint] Base ClamAV absente — téléchargement initial..."
    freshclam --datadir="$CLAMAV_DB_DIR" 2>&1 | tail -5 || echo "[entrypoint] Avertissement: freshclam initial échoué (mode offline ?)"
else
    echo "[entrypoint] Base ClamAV trouvée dans le volume."
fi

freshclam --daemon \
    --datadir="$CLAMAV_DB_DIR" \
    --log=/var/log/freshclam.log \
    --checks=2 \
    2>/dev/null || echo "[entrypoint] freshclam daemon non disponible"

echo "[entrypoint] Démarrage clamd daemon..."
mkdir -p /var/run/clamav
chown clamav:clamav /var/run/clamav
clamd 2>/dev/null &
for i in $(seq 1 30); do
    if [ -S /var/run/clamav/clamd.ctl ]; then
        echo "[entrypoint] clamd prêt."
        chmod 666 /var/run/clamav/clamd.ctl 2>/dev/null || true
        break
    fi
    sleep 1
done
if [ ! -S /var/run/clamav/clamd.ctl ]; then
    echo "[entrypoint] Avertissement: clamd socket non disponible — fallback clamscan."
fi

# ─── Permissions volumes ──────────────────────────────────────────────────────

echo "[entrypoint] Correction des permissions sur les volumes..."

for DIR in \
    /repos/audit \
    /repos/auth \
    /repos/grype-db \
    /repos/imports \
    /repos/manifests \
    /repos/package-index \
    /repos/pool \
    /repos/staging \
    /repos/security \
    /repos/logs; do
    if [ -d "$DIR" ]; then
        chown -R appuser:appuser "$DIR" 2>/dev/null || true
    fi
done

# Répertoires distributions RPM — créer si absents PUIS corriger ownership
# (Docker crée les bind-mounts manquants en root:root, appuser ne peut pas écrire)
for DISTRO in almalinux8 almalinux9 rocky8 rocky9 centos-stream9 oraclelinux8 fedora \
              opensuse-leap-15.5 opensuse-leap-15.6 opensuse-leap opensuse-tumbleweed; do
    DPATH="/repos/${DISTRO}"
    for ARCH in x86_64 aarch64 noarch; do
        mkdir -p "${DPATH}/${ARCH}/repodata" 2>/dev/null || true
    done
    chown -R appuser:appuser "${DPATH}" 2>/dev/null || true
done

GNUPG_DIR="${GNUPG_HOME:-/repos/gnupg}"
if [ -d "$GNUPG_DIR" ]; then
    chown -R appuser:appuser "$GNUPG_DIR" 2>/dev/null || true
    chmod 700 "$GNUPG_DIR" 2>/dev/null || true
elif [ -n "$GNUPG_DIR" ]; then
    mkdir -p "$GNUPG_DIR" && chown appuser:appuser "$GNUPG_DIR" && chmod 700 "$GNUPG_DIR" || true
fi

AUTH_DB="${AUTH_DB_PATH:-/repos/auth/users.db}"
if [ -f "$AUTH_DB" ]; then
    chown appuser:appuser "$AUTH_DB" 2>/dev/null || chmod 666 "$AUTH_DB" 2>/dev/null || true
fi

# Correction explicite des permissions sur la base SQLite des packages-index
# (peut se retrouver owned by root si docker exec a été utilisé pour des tests)
PKG_DB="${INDEX_DIR:-/repos/package-index}/packages.db"
if [ -f "$PKG_DB" ]; then
    chown appuser:appuser "$PKG_DB" 2>/dev/null || chmod 666 "$PKG_DB" 2>/dev/null || true
fi

SETTINGS_FILE="${SETTINGS_PATH:-/repos/settings.json}"
SETTINGS_DIR="$(dirname "$SETTINGS_FILE")"
chown appuser:appuser "$SETTINGS_DIR" 2>/dev/null || true
if [ -f "$SETTINGS_FILE" ]; then
    chown appuser:appuser "$SETTINGS_FILE" 2>/dev/null || true
fi

# ─── Démarrage uvicorn ────────────────────────────────────────────────────────

TRUSTED_PROXIES="${TRUSTED_PROXIES:-127.0.0.1}"

if [ "$ENV" = "production" ]; then
    echo "[entrypoint] Mode PRODUCTION"
    exec gosu appuser python -m uvicorn main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --proxy-headers \
        --forwarded-allow-ips="${TRUSTED_PROXIES}" \
        --workers 2
else
    echo "[entrypoint] Mode DÉVELOPPEMENT — rechargement automatique activé"
    exec gosu appuser python -m uvicorn main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --proxy-headers \
        --forwarded-allow-ips="*" \
        --reload
fi
