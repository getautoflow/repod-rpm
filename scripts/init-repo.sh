#!/bin/bash

set -e
set -u

REPO_DIR="${REPO_BASE:-/usr/share/nginx/html/repos}"
GPG_HOME="${GNUPG_HOME:-/repos/gnupg}"
REPO_DATA_DIR="${REPO_DATA_DIR:-/repos}"

DISTRIBUTIONS=(
    "almalinux8"
    "rocky8"
    "centos-stream9"
    "oraclelinux8"
    "fedora"
    "opensuse-leap-15.5"
    "opensuse-leap-15.6"
    "opensuse-leap"
    "opensuse-tumbleweed"
)
ARCHITECTURES=("x86_64" "aarch64" "noarch")

echo "Initialisation du dépôt RPM..."

if ! command -v gpg >/dev/null 2>&1; then
    echo "ERREUR: gpg n'est pas installé." >&2
    exit 1
fi

if ! command -v createrepo_c >/dev/null 2>&1; then
    echo "ERREUR: createrepo_c n'est pas installé." >&2
    exit 1
fi

mkdir -p "${GPG_HOME}"
chmod 700 "${GPG_HOME}"

export GNUPGHOME="${GPG_HOME}"

if ! gpg --list-keys 2>/dev/null | grep -q "DepotRPM"; then
    echo "Génération d'une nouvelle clé GPG..."
    gpg --batch --generate-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: DepotRPM
Name-Email: depot@local
Expire-Date: 0
%no-protection
%commit
EOF
    echo "Clé GPG générée."
else
    echo "Clé GPG existante détectée."
fi

GPG_KEY_ID=$(gpg --list-keys --with-colons 2>/dev/null | awk -F: '/^pub:/ {print $5}' | head -1)

if [[ -z "$GPG_KEY_ID" ]]; then
    echo "ERREUR: Impossible de récupérer l'ID de la clé GPG !" >&2
    exit 1
fi

echo "Clé GPG : $GPG_KEY_ID"

# Exporter la clé publique au format ASCII armored (pour les clients)
gpg --yes --armor --export "$GPG_KEY_ID" > "${REPO_DIR}/RPM-GPG-KEY-DepotRPM"
chmod 644 "${REPO_DIR}/RPM-GPG-KEY-DepotRPM"

# Exporter aussi en binaire pour compatibilité
gpg --yes --output "${REPO_DIR}/depot.gpg" --export "$GPG_KEY_ID"
chmod 644 "${REPO_DIR}/depot.gpg"

echo "Clé publique exportée."

# Créer et initialiser chaque distribution/architecture
for DISTRIB in "${DISTRIBUTIONS[@]}"; do
    for ARCH in "${ARCHITECTURES[@]}"; do
        DISTRIB_DIR="${REPO_DIR}/${DISTRIB}/${ARCH}"
        mkdir -p "${DISTRIB_DIR}"
        chmod 755 "${DISTRIB_DIR}"

        if [ ! -f "${DISTRIB_DIR}/repodata/repomd.xml" ]; then
            echo "Initialisation de ${DISTRIB}/${ARCH}..."
            createrepo_c --quiet "${DISTRIB_DIR}"

            # Signer le repomd.xml initial
            REPOMD="${DISTRIB_DIR}/repodata/repomd.xml"
            if [ -f "$REPOMD" ]; then
                gpg --batch --yes --detach-sign --armor \
                    --output "${REPOMD}.asc" "${REPOMD}"
            fi
        else
            echo "Dépôt ${DISTRIB}/${ARCH} déjà initialisé."
        fi
    done

    # Créer le fichier .repo pour DNF/Zypper
    REPO_FILE="${REPO_DIR}/${DISTRIB}.repo"
    cat > "${REPO_FILE}" <<REPOEOF
[depot-rpm-${DISTRIB}]
name=Depot RPM Privé - ${DISTRIB}
baseurl=http://localhost/repos/${DISTRIB}/\$basearch/
enabled=1
gpgcheck=1
gpgkey=http://localhost/repos/RPM-GPG-KEY-DepotRPM
REPOEOF
    chmod 644 "${REPO_FILE}"
done

echo "Dépôt RPM prêt."
