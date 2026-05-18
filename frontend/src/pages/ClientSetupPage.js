import { useState } from "react";
import toast from "react-hot-toast";

const REPO_URL = process.env.REACT_APP_REPO_URL || "http://localhost:80";
const REPO_HOST = REPO_URL.replace(/^https?:\/\//, "").replace(/:\d+$/, "");

// ─── Composants ───────────────────────────────────────────────────────────────

function CodeBlock({ code, label }) {
  const copy = () => {
    navigator.clipboard.writeText(code).then(
      () => toast.success("Copié"),
      () => toast.error("Impossible de copier")
    );
  };
  return (
    <div className="rounded-xl overflow-hidden border border-gray-200">
      {label && (
        <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
          <span className="text-xs text-gray-400 font-mono">{label}</span>
          <button onClick={copy}
            className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white transition-colors">
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
            Copier
          </button>
        </div>
      )}
      <pre className="bg-gray-900 text-green-400 text-sm font-mono px-5 py-4 overflow-x-auto whitespace-pre w-0 min-w-full">
        {code}
      </pre>
    </div>
  );
}

function Step({ number, title, warning, children }) {
  return (
    <div className="flex gap-5">
      <div className={`shrink-0 w-8 h-8 rounded-full text-white flex items-center justify-center text-sm font-bold mt-0.5
        ${warning ? "bg-orange-500" : "bg-blue-600"}`}>
        {number}
      </div>
      <div className="flex-1 space-y-3 pb-8 border-b border-gray-100 last:border-0 last:pb-0">
        <h3 className="font-semibold text-gray-900">{title}</h3>
        {children}
      </div>
    </div>
  );
}

function InfoBox({ type = "info", children }) {
  const styles = {
    info:    "bg-blue-50 border-blue-200 text-blue-800",
    warning: "bg-amber-50 border-amber-200 text-amber-800",
    danger:  "bg-red-50 border-red-200 text-red-800",
    success: "bg-green-50 border-green-200 text-green-800",
  };
  const icons = {
    info:    "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    warning: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
    danger:  "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
    success: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
  };
  return (
    <div className={`flex gap-3 border rounded-xl px-4 py-3 text-sm ${styles[type]}`}>
      <svg className="w-5 h-5 shrink-0 mt-0.5 opacity-70" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={icons[type]} />
      </svg>
      <div>{children}</div>
    </div>
  );
}

// ─── Onglet 1 : Connexion DNF (RHEL/Fedora) ──────────────────────────────────

function TabDnf({ distro }) {
  const repoFile = `/etc/yum.repos.d/depot-interne.repo`;
  const repoContent = `[depot-interne]
name=Dépôt RPM Interne — ${distro}
baseurl=${REPO_URL}/repos/${distro}/$basearch/
enabled=1
gpgcheck=1
gpgkey=${REPO_URL}/repos/RPM-GPG-KEY-DepotRPM
repo_gpgcheck=0`;

  const fullScript = `#!/bin/bash
# Configuration du dépôt RPM interne (DNF/YUM)
# Exécuter en tant que root ou avec sudo

# 1. Importer la clé GPG de signature
sudo rpm --import ${REPO_URL}/repos/RPM-GPG-KEY-DepotRPM

# 2. Créer le fichier .repo
cat << 'EOF' | sudo tee /etc/yum.repos.d/depot-interne.repo
[depot-interne]
name=Dépôt RPM Interne — ${distro}
baseurl=${REPO_URL}/repos/${distro}/\\$basearch/
enabled=1
gpgcheck=1
gpgkey=${REPO_URL}/repos/RPM-GPG-KEY-DepotRPM
repo_gpgcheck=0
EOF

# 3. Vérifier la configuration
sudo dnf repolist

echo "Dépôt interne configuré avec succès."`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="info">
        Ces étapes connectent la machine au dépôt RPM interne via DNF/YUM (AlmaLinux, Rocky, CentOS, Oracle, Fedora).
        La clé GPG garantit l'authenticité des paquets signés.
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">
        <Step number="1" title="Importer la clé GPG du dépôt">
          <p className="text-sm text-gray-600">
            Enregistre la clé publique du dépôt dans la base RPM de la machine.
          </p>
          <CodeBlock code={`sudo rpm --import ${REPO_URL}/repos/RPM-GPG-KEY-DepotRPM`} label="bash" />
        </Step>

        <Step number="2" title="Créer le fichier .repo">
          <p className="text-sm text-gray-600">
            Déclare le dépôt interne comme source de paquets DNF/YUM.
          </p>
          <CodeBlock code={`cat << 'EOF' | sudo tee ${repoFile}\n${repoContent}\nEOF`} label="bash" />
          <p className="text-xs text-gray-400">
            Fichier créé : <code className="bg-gray-100 px-1 rounded">{repoFile}</code>
          </p>
        </Step>

        <Step number="3" title="Vérifier et rafraîchir la liste des paquets">
          <CodeBlock code={`sudo dnf repolist\nsudo dnf makecache`} label="bash" />
        </Step>

        <Step number="4" title="Installer un paquet">
          <p className="text-sm text-gray-600">
            Une fois le dépôt configuré, l'installation se fait normalement.
          </p>
          <CodeBlock code="sudo dnf install <nom-du-paquet>" label="bash" />
        </Step>
      </div>

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900">Script d'installation complet</h2>
          <span className="text-xs text-gray-400">Pour automatiser la configuration</span>
        </div>
        <CodeBlock code={fullScript} label="setup-depot-dnf.sh" />
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-gray-700">Vérifier la configuration</h2>
        <div className="space-y-2">
          <CodeBlock
            code={`# Vérifier que le dépôt est reconnu\nsudo dnf repolist | grep depot-interne\n\n# Rechercher un paquet\ndnf search <nom>\n\n# Afficher les informations d'un paquet\ndnf info <nom>`}
            label="bash"
          />
        </div>
      </div>

      <InfoBox type="warning">
        <p className="font-medium">Accès réseau requis</p>
        <p className="mt-0.5">
          La machine doit pouvoir atteindre{" "}
          <code className="bg-amber-100 px-1 rounded font-mono text-xs">{REPO_URL}</code>{" "}
          sur le réseau interne. Aucune connexion internet n'est nécessaire.
        </p>
      </InfoBox>
    </div>
  );
}

// ─── Onglet 2 : Connexion Zypper (openSUSE) ──────────────────────────────────

function TabZypper({ distro }) {
  const repoAlias = "depot-interne";
  const repoUrl = `${REPO_URL}/repos/${distro}/x86_64/`;

  const fullScript = `#!/bin/bash
# Configuration du dépôt RPM interne (Zypper / openSUSE)
# Exécuter en tant que root ou avec sudo

# 1. Importer la clé GPG de signature
sudo rpm --import ${REPO_URL}/repos/RPM-GPG-KEY-DepotRPM

# 2. Ajouter le dépôt
sudo zypper addrepo --refresh --gpgcheck \\
  ${repoUrl} \\
  ${repoAlias}

# 3. Rafraîchir les métadonnées
sudo zypper refresh

echo "Dépôt interne configuré avec succès."`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="info">
        Ces étapes connectent la machine au dépôt RPM interne via Zypper (openSUSE Leap / Tumbleweed).
        La clé GPG garantit l'authenticité des paquets signés.
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">
        <Step number="1" title="Importer la clé GPG du dépôt">
          <CodeBlock code={`sudo rpm --import ${REPO_URL}/repos/RPM-GPG-KEY-DepotRPM`} label="bash" />
        </Step>

        <Step number="2" title="Ajouter le dépôt avec Zypper">
          <p className="text-sm text-gray-600">
            Enregistre le dépôt et active la vérification GPG.
          </p>
          <CodeBlock code={`sudo zypper addrepo --refresh --gpgcheck \\\n  ${repoUrl} \\\n  ${repoAlias}`} label="bash" />
        </Step>

        <Step number="3" title="Rafraîchir les métadonnées">
          <CodeBlock code="sudo zypper refresh" label="bash" />
        </Step>

        <Step number="4" title="Installer un paquet">
          <CodeBlock code="sudo zypper install <nom-du-paquet>" label="bash" />
        </Step>
      </div>

      <div className="space-y-3">
        <h2 className="text-base font-semibold text-gray-900">Script d'installation complet</h2>
        <CodeBlock code={fullScript} label="setup-depot-zypper.sh" />
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-gray-700">Vérifier la configuration</h2>
        <CodeBlock
          code={`# Lister les dépôts configurés\nzypper repos\n\n# Rechercher un paquet\nzypper search <nom>\n\n# Supprimer le dépôt si nécessaire\nsudo zypper removerepo ${repoAlias}`}
          label="bash"
        />
      </div>

      <InfoBox type="warning">
        <p className="font-medium">Accès réseau requis</p>
        <p className="mt-0.5">
          La machine doit pouvoir atteindre{" "}
          <code className="bg-amber-100 px-1 rounded font-mono text-xs">{REPO_URL}</code>{" "}
          sur le réseau interne.
        </p>
      </InfoBox>
    </div>
  );
}

// ─── Onglet 3 : Isolation réseau ─────────────────────────────────────────────

function TabIsolation({ distro, family }) {
  const isDnf = family === "dnf";

  const disableSources = isDnf
    ? `# Désactiver tous les dépôts publics (RHEL/Fedora/CentOS)
# On conserve les fichiers en .bak pour pouvoir revenir en arrière

sudo find /etc/yum.repos.d/ -name "*.repo" \\
  ! -name "depot-interne.repo" \\
  -exec mv {} {}.bak \\;

# Vérifier qu'il ne reste que le dépôt interne
sudo dnf repolist`
    : `# Désactiver tous les dépôts publics (openSUSE)
# On conserve les dépôts en les désactivant (--disable)

for repo in $(zypper repos | awk 'NR>4 && $1 ~ /^[0-9]+$/ {print $NF}'); do
  if [ "$repo" != "depot-interne" ]; then
    sudo zypper modifyrepo --disable "$repo"
  fi
done

# Vérifier qu'il ne reste que le dépôt interne
zypper repos`;

  const ufwRules = isDnf
    ? `# Bloquer les dépôts RPM publics avec firewalld (RHEL/Fedora)
# Bloquer les miroirs connus
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 \\
  -d mirrors.almalinux.org -j DROP
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 \\
  -d dl.fedoraproject.org -j DROP
sudo firewall-cmd --reload`
    : `# Bloquer les dépôts openSUSE publics avec iptables
for host in download.opensuse.org mirrorcache.opensuse.org; do
  ip=$(dig +short "$host" | head -1)
  [ -n "$ip" ] && sudo iptables -A OUTPUT -d "$ip" -p tcp --dport 443 -j DROP
done`;

  const testIsolation = `# Tester que les dépôts publics sont inaccessibles
${isDnf
  ? `curl -v --max-time 5 https://mirrors.almalinux.org/ 2>&1 | grep -E "connect|refused|timed"`
  : `curl -v --max-time 5 https://download.opensuse.org/ 2>&1 | grep -E "connect|refused|timed"`}
# Résultat attendu : "Connection refused" ou "timed out"

# Tester que le dépôt interne est toujours accessible
curl -v --max-time 5 ${REPO_URL}/repos/RPM-GPG-KEY-DepotRPM 2>&1 | grep -E "200|OK"
# Résultat attendu : "200 OK"`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="danger">
        <p className="font-medium">Étape critique — À faire après la connexion au dépôt interne</p>
        <p className="mt-1">
          Ces commandes désactivent les sources internet publiques. Assurez-vous que le dépôt interne
          est correctement configuré avant de les exécuter.
        </p>
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">
        <Step number="1" title="Désactiver les sources publiques" warning>
          <CodeBlock code={disableSources} label="bash" />
        </Step>

        <Step number="2" title="Bloquer les dépôts publics au niveau firewall">
          <p className="text-sm text-gray-600">
            Double protection réseau même si un dépôt public est réintroduit par erreur.
          </p>
          <CodeBlock code={ufwRules} label="bash" />
        </Step>

        <Step number="3" title="Tester l'isolation">
          <CodeBlock code={testIsolation} label="bash" />
        </Step>
      </div>
    </div>
  );
}

// ─── Onglet 4 : Mises à jour automatiques ────────────────────────────────────

function TabAutoUpdate({ distro, family }) {
  const isDnf = family === "dnf";

  const dnfAutomatic = `# Installer dnf-automatic (RHEL/Fedora/CentOS)
sudo dnf install -y dnf-automatic

# Configurer /etc/dnf/automatic.conf
# Modifier la section [commands] :
#   apply_updates = yes
#   upgrade_type = security   # ou 'default' pour toutes les MAJ

# Activer le timer systemd
sudo systemctl enable --now dnf-automatic.timer
sudo systemctl status dnf-automatic.timer

# Tester immédiatement (dry-run)
sudo dnf-automatic --no-download --installupdates --timer=0`;

  const zypperAuto = `# Mises à jour automatiques openSUSE via systemd timer

# Créer le script de mise à jour
cat << 'EOF' | sudo tee /usr/local/bin/auto-update-depot.sh
#!/bin/bash
zypper --non-interactive refresh depot-interne
zypper --non-interactive update --repo depot-interne
EOF
sudo chmod +x /usr/local/bin/auto-update-depot.sh

# Créer le service systemd
cat << 'EOF' | sudo tee /etc/systemd/system/depot-update.service
[Unit]
Description=Mise à jour automatique depuis le dépôt interne
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/auto-update-depot.sh
EOF

# Créer le timer (quotidien à 3h)
cat << 'EOF' | sudo tee /etc/systemd/system/depot-update.timer
[Unit]
Description=Timer mise à jour dépôt interne

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now depot-update.timer`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="info">
        <p className="font-medium">Principe</p>
        <p className="mt-1">
          Les mises à jour automatiques appliquent uniquement les paquets provenant du dépôt interne,
          sans connexion internet. Seuls les paquets validés et signés sont installés.
        </p>
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <CodeBlock
          code={isDnf ? dnfAutomatic : zypperAuto}
          label={isDnf ? "bash — dnf-automatic" : "bash — zypper timer"}
        />
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
        <h2 className="text-sm font-semibold text-gray-800">Bonnes pratiques en production</h2>
        <div className="space-y-3 text-sm text-gray-600">
          <div className="flex gap-3">
            <span className="text-blue-500 font-bold shrink-0">→</span>
            <p><strong>Jamais de redémarrage automatique</strong> sur les serveurs de production.
              Planifier une fenêtre de maintenance.</p>
          </div>
          <div className="flex gap-3">
            <span className="text-blue-500 font-bold shrink-0">→</span>
            <p><strong>Tester d'abord</strong> sur un serveur de staging avant de promouvoir
              vers la distribution de production dans le gestionnaire de dépôts.</p>
          </div>
          <div className="flex gap-3">
            <span className="text-blue-500 font-bold shrink-0">→</span>
            <p><strong>Surveiller les logs</strong>{" "}
              {isDnf
                ? <code className="bg-gray-100 px-1 rounded text-xs">/var/log/dnf/automatic.log</code>
                : <code className="bg-gray-100 px-1 rounded text-xs">journalctl -u depot-update</code>
              }.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────

const DISTROS = [
  { id: "almalinux8",         label: "AlmaLinux 8",           family: "dnf" },
  { id: "rocky8",             label: "Rocky Linux 8",         family: "dnf" },
  { id: "centos-stream9",     label: "CentOS Stream 9",       family: "dnf" },
  { id: "oraclelinux8",       label: "Oracle Linux 8",        family: "dnf" },
  { id: "fedora",             label: "Fedora",                family: "dnf" },
  { id: "opensuse-leap-15.5", label: "openSUSE Leap 15.5",   family: "zypper" },
  { id: "opensuse-leap-15.6", label: "openSUSE Leap 15.6",   family: "zypper" },
  { id: "opensuse-leap",      label: "openSUSE Leap",        family: "zypper" },
  { id: "opensuse-tumbleweed",label: "openSUSE Tumbleweed",  family: "zypper" },
];

const TABS = [
  { id: "dnf",        label: "1. Config DNF/YUM",          icon: "M13 10V3L4 14h7v7l9-11h-7z" },
  { id: "zypper",     label: "2. Config Zypper",            icon: "M13 10V3L4 14h7v7l9-11h-7z" },
  { id: "isolation",  label: "3. Isolation réseau",         icon: "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" },
  { id: "autoupdate", label: "4. Mises à jour automatiques",icon: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" },
];

export default function ClientSetupPage() {
  const [distro, setDistro] = useState("almalinux8");
  const [activeTab, setActiveTab] = useState("dnf");

  const currentDistro = DISTROS.find((d) => d.id === distro) || DISTROS[0];

  const handleDistroSelect = (d) => {
    setDistro(d.id);
    if (d.family === "zypper" && activeTab === "dnf") setActiveTab("zypper");
    if (d.family === "dnf"    && activeTab === "zypper") setActiveTab("dnf");
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Configuration des machines clientes</h1>
        <p className="text-sm text-gray-500 mt-1">
          Guide complet : connexion au dépôt RPM interne, isolation réseau et mises à jour automatiques.
        </p>
      </div>

      {/* Sélecteur de distribution */}
      <div className="bg-white rounded-xl border border-gray-200 p-4">
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
          Distribution cible — les scripts s'adaptent automatiquement
        </p>
        <div className="flex flex-wrap gap-2">
          {DISTROS.map((d) => (
            <button key={d.id} onClick={() => handleDistroSelect(d)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors border ${
                distro === d.id
                  ? "bg-blue-600 text-white border-blue-600"
                  : "bg-white text-gray-600 border-gray-300 hover:border-blue-400"
              }`}>
              {d.label}
              <span className={`ml-1.5 text-[10px] px-1 rounded ${
                d.family === "dnf"
                  ? distro === d.id ? "bg-blue-500 text-blue-100" : "bg-orange-100 text-orange-600"
                  : distro === d.id ? "bg-blue-500 text-blue-100" : "bg-green-100 text-green-600"
              }`}>
                {d.family === "dnf" ? "DNF" : "Zypper"}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Onglets */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex gap-1 flex-wrap">
          {TABS.map((tab) => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? "border-blue-600 text-blue-600"
                  : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
              }`}>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
              </svg>
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Contenu */}
      {activeTab === "dnf"        && <TabDnf       distro={distro} />}
      {activeTab === "zypper"     && <TabZypper    distro={distro} />}
      {activeTab === "isolation"  && <TabIsolation distro={distro} family={currentDistro.family} />}
      {activeTab === "autoupdate" && <TabAutoUpdate distro={distro} family={currentDistro.family} />}
    </div>
  );
}
