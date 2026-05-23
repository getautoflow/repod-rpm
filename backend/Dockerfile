# ── Stage 1 : builder (dépendances Python) ───────────────────────────────────
FROM python:3.10 AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --target=/dependencies -r requirements.txt

# ── Stage 2 : runtime slim ───────────────────────────────────────────────────
FROM python:3.10-slim

# Outils RPM + sécurité
# Acquire::Check-Valid-Until "false" évite l'erreur "not valid yet" si
# l'horloge système de l'hôte est légèrement en avance sur les miroirs Debian.
RUN echo 'Acquire::Check-Valid-Until "false";' \
        > /etc/apt/apt.conf.d/99no-check-valid-until \
    && apt-get update && apt-get install -y --no-install-recommends \
    # Manipulation RPM
    rpm \
    createrepo-c \
    # GPG pour signature repomd.xml
    gnupg \
    gpg-agent \
    # ClamAV antivirus
    clamav \
    clamav-daemon \
    # SSH client (import distant)
    openssh-client \
    # Utilitaires
    curl \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Grype pour scan CVE (supporte RPM nativement)
RUN GRYPE_VERSION=$(curl -s https://api.github.com/repos/anchore/grype/releases/latest \
        | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && curl -sSfL "https://raw.githubusercontent.com/anchore/grype/main/install.sh" \
        | sh -s -- -b /usr/local/bin \
    || echo "Grype non disponible — scan CVE désactivé"

# Copie des dépendances Python depuis le builder
COPY --from=builder /dependencies /usr/lib/python3/dist-packages/

# Application
WORKDIR /app
COPY . .
ENV PYTHONPATH="/usr/lib/python3/dist-packages:/app"

# Utilisateur non-root
RUN groupadd -g 1000 appuser && useradd -u 1000 -g appuser -m appuser

# Répertoires de travail (les volumes seront montés dessus)
RUN mkdir -p /repos/pool /repos/manifests /repos/staging/incoming \
             /repos/staging/quarantine /repos/audit /repos/auth \
             /repos/gnupg /repos/grype-db /repos/package-index \
             /repos/imports /repos/security /repos/logs \
    && chown -R appuser:appuser /repos

# Copie du script d'entrée
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

ENTRYPOINT ["/entrypoint.sh"]
