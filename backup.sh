#!/bin/bash
# =============================================================================
# backup.sh — Sauvegarde de production RPM Repo Manager
# =============================================================================
# Usage :
#   ./backup.sh                    → backup dans ./backups/ (défaut)
#   BACKUP_DIR=/mnt/nas ./backup.sh → backup vers un NAS
#   ./backup.sh --dry-run           → liste ce qui serait sauvegardé
# =============================================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-$(pwd)/backups}"
REPOS_DIR="${REPOS_DIR:-$(pwd)/repos}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="repod_rpm_backup_${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"
DRY_RUN=false
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

for arg in "$@"; do
    case $arg in
        --dry-run) DRY_RUN=true ;;
        *) echo "Usage: $0 [--dry-run]"; exit 1 ;;
    esac
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

log()  { echo -e "${GREEN}[backup]${NC} $*"; }
warn() { echo -e "${YELLOW}[backup]${NC} $*"; }
fail() { echo -e "${RED}[backup]${NC} $*" >&2; exit 1; }

[ -d "$REPOS_DIR" ] || fail "Répertoire repos introuvable : $REPOS_DIR"

if $DRY_RUN; then
    warn "Mode DRY-RUN — aucune écriture"
    log "Répertoires qui seraient sauvegardés :"
    for d in auth audit security settings.json gnupg manifests; do
        path="$REPOS_DIR/$d"
        [ -e "$path" ] && log "  + $path" || warn "  - $path (absent)"
    done
    exit 0
fi

mkdir -p "$BACKUP_PATH"
log "Début de la sauvegarde → ${BACKUP_PATH}"

if [ -f "$REPOS_DIR/auth/users.db" ]; then
    if command -v sqlite3 &>/dev/null; then
        sqlite3 "$REPOS_DIR/auth/users.db" ".backup '$BACKUP_PATH/users.db'"
        log "users.db sauvegardée (sqlite3 .backup)"
    else
        cp "$REPOS_DIR/auth/users.db" "$BACKUP_PATH/users.db"
        warn "sqlite3 absent — copie directe"
    fi
else
    warn "users.db introuvable — ignorée"
fi

for f in settings.json; do
    [ -f "$REPOS_DIR/$f" ] && cp "$REPOS_DIR/$f" "$BACKUP_PATH/$f" && log "$f sauvegardé"
done

if [ -d "$REPOS_DIR/audit" ]; then
    mkdir -p "$BACKUP_PATH/audit"
    cp -r "$REPOS_DIR/audit/." "$BACKUP_PATH/audit/"
    AUDIT_COUNT=$(find "$BACKUP_PATH/audit" -name "*.jsonl" | wc -l)
    log "Audit logs sauvegardés ($AUDIT_COUNT fichiers)"
fi

if [ -d "$REPOS_DIR/security" ]; then
    mkdir -p "$BACKUP_PATH/security"
    cp -r "$REPOS_DIR/security/." "$BACKUP_PATH/security/"
    log "Répertoire security sauvegardé"
fi

if [ -d "$REPOS_DIR/manifests" ]; then
    mkdir -p "$BACKUP_PATH/manifests"
    cp -r "$REPOS_DIR/manifests/." "$BACKUP_PATH/manifests/"
    MANIFEST_COUNT=$(find "$BACKUP_PATH/manifests" -name "*.json" | wc -l)
    log "Manifestes sauvegardés ($MANIFEST_COUNT fichiers)"
fi

if [ -d "$REPOS_DIR/gnupg" ]; then
    mkdir -p "$BACKUP_PATH/gnupg"
    cp -rp "$REPOS_DIR/gnupg/." "$BACKUP_PATH/gnupg/" 2>/dev/null || true
    chmod 700 "$BACKUP_PATH/gnupg"
    log "Trousseau GPG sauvegardé"
fi

ARCHIVE="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
tar -czf "$ARCHIVE" -C "$BACKUP_DIR" "$BACKUP_NAME"
rm -rf "$BACKUP_PATH"
ARCHIVE_SIZE=$(du -sh "$ARCHIVE" | cut -f1)
log "Archive créée : ${ARCHIVE} (${ARCHIVE_SIZE})"

if [ "$RETENTION_DAYS" -gt 0 ]; then
    DELETED=$(find "$BACKUP_DIR" -name "repod_rpm_backup_*.tar.gz" \
        -mtime "+${RETENTION_DAYS}" -print -delete | wc -l)
    [ "$DELETED" -gt 0 ] && log "Rétention : $DELETED ancien(s) backup(s) supprimé(s) (>${RETENTION_DAYS}j)"
fi

echo ""
log "Sauvegarde terminée avec succès"
log "  Archive : $ARCHIVE ($ARCHIVE_SIZE)"
log "  Rétention : ${RETENTION_DAYS} jours"
