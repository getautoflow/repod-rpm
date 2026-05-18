# RPM Repo Manager

Gestionnaire de dépôts RPM privé — version Enterprise.
Equivalent du projet **Repod-deb** mais pour les distributions RPM/DNF/Zypper.

## Distributions supportées

| Distribution | Codename | Package Manager | Compatibilité |
|---|---|---|---|
| AlmaLinux 8 | `almalinux8` | dnf | RHEL 8 compatible |
| Rocky Linux 8 | `rocky8` | dnf | RHEL 8 compatible |
| CentOS Stream 9 | `centos-stream9` | dnf | RHEL 9 upstream |
| Oracle Linux 8 | `oraclelinux8` | dnf | RHEL 8 compatible |
| Fedora | `fedora` | dnf | Rolling release |
| openSUSE Leap 15.5 | `opensuse-leap-15.5` | zypper | SUSE compatible |
| openSUSE Leap 15.6 | `opensuse-leap-15.6` | zypper | SUSE compatible |
| openSUSE Leap | `opensuse-leap` | zypper | Dernière Leap stable |
| openSUSE Tumbleweed | `opensuse-tumbleweed` | zypper | Rolling release |

## Architecture

```
frontend (React + Tailwind)  ←→  backend (FastAPI)  ←→  rpm-repo (Nginx + createrepo_c)
```

- **rpm-repo** : Serveur Nginx exposant les dépôts RPM. `createrepo_c` gère les métadonnées.
- **backend** : API FastAPI avec validation ClamAV + Grype CVE, RBAC 5 rôles, scheduler APScheduler.
- **frontend** : Interface React avec upload drag-and-drop, dashboard CVE, gestion distributions.

## Démarrage rapide

```bash
# 1. Configuration
cp .env.example .env
cp backend.env.example backend.env
# Éditer backend.env : JWT_SECRET_KEY, ADMIN_PASSWORD_HASH

# 2. Démarrage
docker compose up -d

# 3. Accès
#   Frontend  : http://localhost:3003
#   Backend   : http://localhost:8000
#   Dépôts    : http://localhost:80/repos/
```

**Avertissement** : Changez impérativement `JWT_SECRET_KEY` et `ADMIN_PASSWORD_HASH` avant tout déploiement.

## Configuration clients

### DNF / YUM (AlmaLinux, Rocky, CentOS, Oracle, Fedora)

```bash
# Importer la clé GPG
sudo rpm --import http://REPO_HOST/repos/RPM-GPG-KEY-DepotRPM

# Créer le fichier .repo
cat > /etc/yum.repos.d/depot-rpm.repo << 'EOF'
[depot-rpm]
name=Depot RPM Privé
baseurl=http://REPO_HOST/repos/almalinux8/$basearch/
enabled=1
gpgcheck=1
gpgkey=http://REPO_HOST/repos/RPM-GPG-KEY-DepotRPM
EOF

# Installation d'un paquet
dnf install mon-paquet
```

### Zypper (openSUSE)

```bash
# Importer la clé GPG
sudo rpm --import http://REPO_HOST/repos/RPM-GPG-KEY-DepotRPM

# Ajouter le dépôt
sudo zypper addrepo http://REPO_HOST/repos/opensuse-leap-15.6/x86_64/ depot-rpm

# Rafraîchir et installer
sudo zypper refresh
sudo zypper install mon-paquet
```

## Fonctionnalités

- **Upload** : Drag-and-drop `.rpm`, pipeline de validation complet avec SSE temps réel
- **Validation** : Format RPM, SHA-256, ClamAV antivirus, Grype CVE, dépendances
- **Import** : Import depuis miroirs upstream (AlmaLinux, Rocky, CentOS, openSUSE...)
- **Distributions** : 9 distributions, promotion entre distributions, migration en masse
- **SBOM** : Génération CycloneDX + SPDX
- **Sécurité** : Scan CVE avec politique block/review/warn, CISA KEV, EPSS
- **RBAC** : 5 rôles (admin, maintainer, uploader, auditor, reader)
- **Audit** : Logs JSONL immuables append-only
- **Scheduler** : Sync quotidienne sources sécurité, purge rétention, alertes SLA CVE

## Déploiement production

```bash
# Lier uniquement localhost (derrière reverse proxy)
BIND_HOST=127.0.0.1 docker compose up -d

# TLS recommandé via Caddy ou Nginx en reverse proxy
```

## Variables d'environnement

| Variable | Description | Défaut |
|---|---|---|
| `JWT_SECRET_KEY` | Clé secrète JWT (obligatoire) | — |
| `ADMIN_USERNAME` | Nom du compte admin initial | `admin` |
| `ADMIN_PASSWORD_HASH` | Hash bcrypt du mot de passe admin | — |
| `CORS_ORIGINS` | Origines CORS autorisées | localhost |
| `BIND_HOST` | Interface d'écoute Docker | `0.0.0.0` |
| `RPM_PORT` | Port nginx dépôt RPM | `80` |
| `BACKEND_PORT` | Port API backend | `8000` |
| `FRONTEND_PORT` | Port interface web | `3003` |

---

Projet dérivé de **Repod-deb** — mêmes principes, même stack, pour l'écosystème RPM.
