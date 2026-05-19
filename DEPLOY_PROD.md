# Procédure de déploiement — Production RPM Repo Manager

## 1. Prérequis serveur

| Composant | Minimum | Recommandé |
|-----------|---------|------------|
| OS | RHEL 8/9, AlmaLinux 8/9, Rocky 8/9 | AlmaLinux 9 |
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 Go | 8 Go |
| Disque OS | 30 Go | 50 Go |
| Disque données | 300 Go | 500 Go+ |

```bash
# Installer les dépendances système
dnf install -y lvm2 xfsprogs docker-ce docker-compose-plugin
systemctl enable --now docker
```

---

## 2. Initialisation du stockage (LVM)

> **À faire une seule fois** sur le serveur vierge.

```bash
# Vérifier les disques disponibles
lsblk

# Lancer le script (adapter /dev/sdb selon votre serveur)
sudo ./scripts/setup-storage.sh /dev/sdb

# Avec plusieurs disques (LVM agrège automatiquement)
sudo ./scripts/setup-storage.sh /dev/sdb /dev/sdc
```

Le script crée automatiquement :
- Le Volume Group `vg_repo`
- 14 Logical Volumes dédiés (distros + infra)
- Le formatage XFS avec `noatime`
- Les points de montage sous `/repo/`
- Les entrées `/etc/fstab` persistantes

**Structure résultante :**
```
/repo/
├── almalinux8/          → lv_almalinux8   (20 Go)
├── almalinux9/          → lv_almalinux9   (20 Go)
├── rocky8/              → lv_rocky8       (20 Go)
├── rocky9/              → lv_rocky9       (20 Go)
├── centos-stream9/      → lv_centos_stream9 (15 Go)
├── oraclelinux8/        → lv_oraclelinux8 (15 Go)
├── fedora/              → lv_fedora       (20 Go)
├── opensuse-leap/       → lv_opensuse_leap (15 Go)
├── opensuse-tumbleweed/ → lv_opensuse_tw  (15 Go)
├── pool/                → lv_pool         (50 Go)  ← uploads RPM
├── grype-db/            → lv_grype_db     (15 Go)  ← base CVE
├── data/                → lv_data         (15 Go)  ← manifestes, auth, audit
├── logs/                → lv_logs         (5 Go)   ← nginx + backend
└── clamav-db/           → lv_clamav       (5 Go)   ← antivirus
```

---

## 3. Configuration

```bash
# Copier et renseigner les fichiers de configuration
cp .env.example .env
cp backend.env.example backend.env
vim .env          # REACT_APP_API_URL, REACT_APP_REPO_URL, BIND_HOST
vim backend.env   # JWT_SECRET_KEY, ADMIN_PASSWORD_HASH, SMTP...
```

Variables critiques dans `.env` :
```ini
BIND_HOST=127.0.0.1          # Écoute localhost uniquement (reverse-proxy devant)
REACT_APP_API_URL=https://repo.example.com/api
REACT_APP_REPO_URL=https://repo.example.com
APP_VERSION=v1.0.0
```

---

## 4. Build et démarrage

```bash
# Build des images (une seule fois, ou après mise à jour du code)
docker compose -f docker-compose.prod.yml build

# Démarrage
docker compose -f docker-compose.prod.yml up -d

# Vérifier l'état
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f backend
```

---

## 5. Reverse-proxy (Nginx ou Caddy devant Docker)

En production, `BIND_HOST=127.0.0.1` — les containers n'écoutent que localement.
Le reverse-proxy gère TLS et route vers les bons ports.

**Exemple Nginx (`/etc/nginx/conf.d/repod.conf`) :**
```nginx
server {
    listen 443 ssl http2;
    server_name repo.example.com;

    ssl_certificate     /etc/letsencrypt/live/repo.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/repo.example.com/privkey.pem;

    # Frontend
    location / {
        proxy_pass http://127.0.0.1:3003;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 600m;  # Pour les gros RPMs
    }

    # Dépôt RPM (téléchargement direct)
    location /repos/ {
        proxy_pass http://127.0.0.1:80/repos/;
    }
}

server {
    listen 80;
    server_name repo.example.com;
    return 301 https://$host$request_uri;
}
```

---

## 6. Opérations courantes

### Étendre un volume si un dépôt est plein
```bash
# Vérifier l'espace libre dans le VG
sudo vgs vg_repo

# Étendre le LV AlmaLinux 8 de 10 Go supplémentaires
sudo lvextend -L +10G /dev/vg_repo/lv_almalinux8
sudo xfs_growfs /repo/almalinux8   # XFS s'étend à chaud, sans redémarrage
```

### Surveiller l'occupation des volumes
```bash
df -h /repo/*
```

### Sauvegarder la configuration LVM
```bash
sudo vgcfgbackup vg_repo -f /backup/vg_repo_$(date +%Y%m%d).cfg
```

### Snapshot avant une opération risquée
```bash
# Créer un snapshot de 2 Go (COW) — rapide et sans downtime
sudo lvcreate -L 2G -s -n snap_almalinux8 /dev/vg_repo/lv_almalinux8

# Restaurer si besoin
sudo lvconvert --merge /dev/vg_repo/snap_almalinux8
```

---

## 7. Checklist avant mise en production

- [ ] Script `setup-storage.sh` exécuté avec succès
- [ ] `df -h /repo/*` — tous les volumes montés
- [ ] `.env` et `backend.env` renseignés (pas de valeurs `CHANGE_ME`)
- [ ] `BIND_HOST=127.0.0.1` dans `.env`
- [ ] Reverse-proxy configuré avec TLS
- [ ] `docker compose -f docker-compose.prod.yml ps` — tous les services `healthy`
- [ ] Connexion admin fonctionnelle sur l'interface
- [ ] Firewall : seul le port 443 (et 80 pour redirect) exposé publiquement
- [ ] Cron de sauvegarde configuré (`backup.sh`)
- [ ] Alertes monitoring sur l'occupation des LV
