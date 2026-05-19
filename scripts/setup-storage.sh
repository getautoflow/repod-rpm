#!/usr/bin/env bash
# =============================================================================
# setup-storage.sh — Initialisation du stockage LVM pour RPM Repo Manager
# =============================================================================
#
# Usage :
#   sudo ./setup-storage.sh /dev/sdb [/dev/sdc ...]
#
# Ce script est IDEMPOTENT : si le VG/LV existe déjà, il est ignoré.
# À lancer UNE FOIS sur un nouveau serveur avant le premier `docker compose up`.
#
# Prérequis :
#   - lvm2 installé  (dnf install lvm2 / apt install lvm2)
#   - xfsprogs       (dnf install xfsprogs / apt install xfsprogs)
#   - Disques cibles vides (vérifier avec `lsblk` avant)
#
# Exemple :
#   sudo ./setup-storage.sh /dev/sdb /dev/sdc
# =============================================================================

set -euo pipefail

# ─── Couleurs ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }

# =============================================================================
# CONFIGURATION — adapter selon le serveur
# =============================================================================

VG_NAME="vg_repo"
MOUNT_BASE="/repo"

# Tailles des volumes logiques (modifier selon la capacité disque disponible)
declare -A LV_SIZES=(
    # ── Distributions RPM ────────────────────────────────────────────
    ["lv_almalinux8"]="20G"
    ["lv_almalinux9"]="20G"
    ["lv_rocky8"]="20G"
    ["lv_rocky9"]="20G"
    ["lv_centos_stream9"]="15G"
    ["lv_oraclelinux8"]="15G"
    ["lv_fedora"]="20G"
    ["lv_opensuse_leap"]="15G"
    ["lv_opensuse_tw"]="15G"
    # ── Infrastructure ───────────────────────────────────────────────
    ["lv_pool"]="50G"       # pool d'upload des RPMs
    ["lv_grype_db"]="15G"   # base de données CVE Grype
    ["lv_data"]="15G"       # manifestes, index, auth, staging, audit, security
    ["lv_logs"]="5G"        # logs nginx + backend
    ["lv_clamav"]="5G"      # base antivirus ClamAV
)

# Points de montage correspondant à chaque LV
declare -A LV_MOUNTS=(
    ["lv_almalinux8"]="${MOUNT_BASE}/almalinux8"
    ["lv_almalinux9"]="${MOUNT_BASE}/almalinux9"
    ["lv_rocky8"]="${MOUNT_BASE}/rocky8"
    ["lv_rocky9"]="${MOUNT_BASE}/rocky9"
    ["lv_centos_stream9"]="${MOUNT_BASE}/centos-stream9"
    ["lv_oraclelinux8"]="${MOUNT_BASE}/oraclelinux8"
    ["lv_fedora"]="${MOUNT_BASE}/fedora"
    ["lv_opensuse_leap"]="${MOUNT_BASE}/opensuse-leap"
    ["lv_opensuse_tw"]="${MOUNT_BASE}/opensuse-tumbleweed"
    ["lv_pool"]="${MOUNT_BASE}/pool"
    ["lv_grype_db"]="${MOUNT_BASE}/grype-db"
    ["lv_data"]="${MOUNT_BASE}/data"
    ["lv_logs"]="${MOUNT_BASE}/logs"
    ["lv_clamav"]="${MOUNT_BASE}/clamav-db"
)

# =============================================================================
# VÉRIFICATIONS PRÉLIMINAIRES
# =============================================================================

section "Vérifications préliminaires"

[[ $EUID -ne 0 ]] && error "Ce script doit être exécuté en root (sudo)."
[[ $# -eq 0 ]]    && error "Usage : $0 /dev/sdX [/dev/sdY ...]"

# Vérifier les outils
for cmd in pvcreate vgcreate lvcreate mkfs.xfs; do
    command -v "$cmd" &>/dev/null || error "'$cmd' introuvable. Installer lvm2 et xfsprogs."
done
ok "Outils LVM et XFS disponibles."

# Vérifier les disques passés en paramètre
DISKS=("$@")
for disk in "${DISKS[@]}"; do
    [[ -b "$disk" ]] || error "Périphérique introuvable ou non-bloc : $disk"
    # Avertir si le disque a déjà des partitions montées
    if mount | grep -q "^${disk}"; then
        error "$disk est actuellement monté. Abandon."
    fi
    ok "Disque $disk disponible."
done

# Calculer l'espace total requis
TOTAL_GB=0
for size in "${LV_SIZES[@]}"; do
    num="${size%G}"
    TOTAL_GB=$((TOTAL_GB + num))
done
info "Espace total requis pour les LV : ${TOTAL_GB} Go (+ overhead LVM ~1 Go)."
warn "Assurez-vous que vos disques totalisent au moins $((TOTAL_GB + 5)) Go."

echo ""
read -rp "$(echo -e "${YELLOW}Continuer avec les disques : ${DISKS[*]} ? [oui/NON] : ${RESET}")" confirm
[[ "$confirm" == "oui" ]] || { info "Abandon."; exit 0; }

# =============================================================================
# CRÉATION DU VOLUME GROUP
# =============================================================================

section "Volume Group : $VG_NAME"

if vgs "$VG_NAME" &>/dev/null; then
    warn "Le VG '$VG_NAME' existe déjà — étape ignorée."
else
    # Créer les Physical Volumes
    for disk in "${DISKS[@]}"; do
        if pvs "$disk" &>/dev/null; then
            warn "PV $disk existe déjà."
        else
            pvcreate -y "$disk"
            ok "PV créé : $disk"
        fi
    done

    # Créer le Volume Group
    vgcreate "$VG_NAME" "${DISKS[@]}"
    ok "VG créé : $VG_NAME (disques : ${DISKS[*]})"
fi

vgs "$VG_NAME"

# =============================================================================
# CRÉATION DES VOLUMES LOGIQUES
# =============================================================================

section "Volumes Logiques"

CREATED=0
SKIPPED=0

for lv_name in "${!LV_SIZES[@]}"; do
    size="${LV_SIZES[$lv_name]}"
    lv_path="/dev/${VG_NAME}/${lv_name}"

    if lvs "${VG_NAME}/${lv_name}" &>/dev/null; then
        warn "LV '$lv_name' existe déjà — ignoré."
        ((SKIPPED++)) || true
        continue
    fi

    lvcreate -y -L "$size" -n "$lv_name" "$VG_NAME"
    ok "LV créé : $lv_name (${size})"
    ((CREATED++)) || true
done

info "$CREATED LV créés, $SKIPPED ignorés (existants)."
lvs "$VG_NAME"

# =============================================================================
# FORMATAGE XFS
# =============================================================================

section "Formatage XFS"

for lv_name in "${!LV_SIZES[@]}"; do
    lv_path="/dev/${VG_NAME}/${lv_name}"

    # Vérifier si le FS est déjà formaté
    if blkid "$lv_path" | grep -q 'TYPE="xfs"'; then
        warn "$lv_name déjà formaté en XFS — ignoré."
        continue
    fi

    mkfs.xfs -L "$lv_name" -f "$lv_path" > /dev/null
    ok "XFS formaté : $lv_name"
done

# =============================================================================
# CRÉATION DES POINTS DE MONTAGE ET MONTAGE
# =============================================================================

section "Points de montage"

for lv_name in "${!LV_MOUNTS[@]}"; do
    mount_point="${LV_MOUNTS[$lv_name]}"
    lv_path="/dev/${VG_NAME}/${lv_name}"

    # Créer le répertoire
    mkdir -p "$mount_point"

    # Monter si pas déjà monté
    if mountpoint -q "$mount_point"; then
        warn "$mount_point déjà monté — ignoré."
    else
        mount "$lv_path" "$mount_point"
        ok "Monté : $lv_path → $mount_point"
    fi

    # Permissions pour Docker (les containers tournent en non-root)
    chmod 755 "$mount_point"
done

# Sous-répertoires dans lv_data (structure attendue par le backend)
DATA_SUBDIRS=(manifests staging/incoming staging/quarantine audit auth security package-index imports gnupg)
for subdir in "${DATA_SUBDIRS[@]}"; do
    mkdir -p "${MOUNT_BASE}/data/${subdir}"
done
ok "Sous-répertoires créés dans lv_data."

# =============================================================================
# MISE À JOUR DE /etc/fstab
# =============================================================================

section "/etc/fstab"

# Sauvegarder le fstab
cp /etc/fstab /etc/fstab.bak.$(date +%Y%m%d_%H%M%S)
ok "Sauvegarde : /etc/fstab.bak.*"

# Supprimer les anciennes entrées vg_repo si elles existent
sed -i "/\/dev\/${VG_NAME}\//d" /etc/fstab

# Ajouter les nouvelles entrées
{
    echo ""
    echo "# ── RPM Repo Manager — LVM (généré par setup-storage.sh le $(date +%Y-%m-%d)) ──"
    for lv_name in "${!LV_MOUNTS[@]}"; do
        printf "/dev/${VG_NAME}/%-22s %-35s xfs  defaults,noatime  0 2\n" \
               "${lv_name}" "${LV_MOUNTS[$lv_name]}"
    done
} >> /etc/fstab

ok "/etc/fstab mis à jour."
systemctl daemon-reload

# =============================================================================
# VÉRIFICATION FINALE
# =============================================================================

section "Vérification finale"

echo ""
printf "%-30s %6s %6s %6s %4s  %s\n" "FILESYSTEM" "TAILLE" "UTIL." "LIBRE" "%" "POINT DE MONTAGE"
printf "%-30s %6s %6s %6s %4s  %s\n" "──────────────────────────────" "──────" "──────" "──────" "────" "────────────────"
df -h --output=source,size,used,avail,pcent,target | grep "${VG_NAME}" | \
    while read -r src size used avail pct mnt; do
        printf "%-30s %6s %6s %6s %4s  %s\n" "$src" "$size" "$used" "$avail" "$pct" "$mnt"
    done

echo ""
VG_FREE=$(vgs --noheadings --units g -o vfree "$VG_NAME" | tr -d ' ')
ok "Espace libre dans le VG : ${VG_FREE}"
echo ""
echo -e "${GREEN}${BOLD}✓ Stockage initialisé avec succès.${RESET}"
echo -e "  Prochaine étape : ${BOLD}sudo docker compose -f docker-compose.prod.yml up -d${RESET}"
echo ""
