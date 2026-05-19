import { useState, useEffect, useRef, useCallback } from "react";
import toast from "react-hot-toast";
import HelpTooltip from "../components/HelpTooltip";
import {
  getSettings,
  patchSettings,
  testWebhook,
  testEmail,
  testLdap,
  runRetention,
  getNextSync,
  getApiBaseUrl,
  getGpgInfo,
  generateGpgKey,
} from "../api";

const API_URL = getApiBaseUrl();

// ─── Sources connues (label lisible) ─────────────────────────────────────────

const SOURCE_META = {
  // ── Sources standard (index de paquets) ──────────────────────────────────
  "almalinux8-baseos":          { label: "AlmaLinux 8 — BaseOS",           security: false },
  "almalinux8-appstream":       { label: "AlmaLinux 8 — AppStream",        security: false },
  "almalinux8-extras":          { label: "AlmaLinux 8 — Extras",           security: false },
  "almalinux9-baseos":          { label: "AlmaLinux 9 — BaseOS",           security: false },
  "almalinux9-appstream":       { label: "AlmaLinux 9 — AppStream",        security: false },
  "rocky8-baseos":              { label: "Rocky Linux 8 — BaseOS",         security: false },
  "rocky8-appstream":           { label: "Rocky Linux 8 — AppStream",      security: false },
  "rocky9-baseos":              { label: "Rocky Linux 9 — BaseOS",         security: false },
  "rocky9-appstream":           { label: "Rocky Linux 9 — AppStream",      security: false },
  "centos-stream9-baseos":      { label: "CentOS Stream 9 — BaseOS",       security: false },
  "centos-stream9-appstream":   { label: "CentOS Stream 9 — AppStream",    security: false },
  "oraclelinux8-baseos":        { label: "Oracle Linux 8 — BaseOS",        security: false },
  "oraclelinux8-appstream":     { label: "Oracle Linux 8 — AppStream",     security: false },
  "oraclelinux9-baseos":        { label: "Oracle Linux 9 — BaseOS",        security: false },
  "fedora42":                   { label: "Fedora 42 — Everything",         security: false },
  "epel8":                      { label: "EPEL 8 — Extra Packages",        security: false },
  "epel9":                      { label: "EPEL 9 — Extra Packages",        security: false },
  "opensuse-leap-15.6-oss":     { label: "openSUSE Leap 15.6 — OSS",       security: false },
  "opensuse-tumbleweed-oss":    { label: "openSUSE Tumbleweed — OSS",       security: false },
  // ── Sources sécurité (avis CVE / mises à jour) ───────────────────────────
  "fedora42-updates":           { label: "Fedora 42 — Updates",            security: true  },
  "opensuse-leap-15.6-updates": { label: "openSUSE Leap 15.6 — Updates",   security: true  },
};

// ─── Composants utilitaires ───────────────────────────────────────────────────

function SectionCard({ title, description, tooltip, icon, children }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 flex items-center gap-3">
        <span className="w-5 h-5 text-gray-500 shrink-0">{icon}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-gray-900">{title}</h2>
            {tooltip && <HelpTooltip text={tooltip} position="right" />}
          </div>
          {description && <p className="text-xs text-gray-500 mt-0.5">{description}</p>}
        </div>
      </div>
      <div className="px-6 py-5 space-y-5">{children}</div>
    </div>
  );
}

function Toggle({ checked, onChange, disabled = false }) {
  return (
    <button
      type="button"
      onClick={() => !disabled && onChange(!checked)}
      disabled={disabled}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none
        ${checked ? "bg-blue-600" : "bg-gray-300"}
        ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform
          ${checked ? "translate-x-6" : "translate-x-1"}`}
      />
    </button>
  );
}

function FieldRow({ label, hint, children }) {
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="min-w-0">
        <p className="text-sm font-medium text-gray-800">{label}</p>
        {hint && <p className="text-xs text-gray-400 mt-0.5">{hint}</p>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function SaveButton({ onClick, saving, dirty }) {
  return (
    <div className="flex justify-end pt-2">
      <button
        onClick={onClick}
        disabled={saving || !dirty}
        className="px-5 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg
                   hover:bg-blue-700 disabled:opacity-40 transition-colors"
      >
        {saving ? "Enregistrement..." : "Enregistrer"}
      </button>
    </div>
  );
}

// ─── Logs SSE (sync manuelle) ─────────────────────────────────────────────────

function LogLine({ line }) {
  if (!line) return null;
  const [level, ...rest] = line.split("|");
  const msg = rest.join("|");
  const styles = {
    info: "text-gray-300", success: "text-green-400",
    error: "text-red-400", warning: "text-yellow-400",
    done: "text-blue-400 font-semibold",
  };
  return (
    <p className={`text-xs font-mono leading-relaxed ${styles[level] || "text-gray-300"}`}>
      {msg}
    </p>
  );
}

// ─── Section : Synchronisation ────────────────────────────────────────────────

function SyncSection({ settings, onChange }) {
  const sync = settings.sync || {};
  const [logs, setLogs] = useState([]);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const [nextRun, setNextRun] = useState(null);
  const logsRef = useRef(null);

  useEffect(() => {
    getNextSync()
      .then((d) => setNextRun(d.next_run))
      .catch(() => {});
  }, [done]);

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  const handleManualSync = () => {
    const token = localStorage.getItem("token");
    setLogs([]);
    setDone(false);
    setRunning(true);

    fetch(`${API_URL}/import/sync-security`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({}),
    }).then(async (resp) => {
      if (!resp.ok) {
        setLogs(["error|Erreur serveur"]);
        setRunning(false);
        return;
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { value, done: streamDone } = await reader.read();
        if (streamDone) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop();
        for (const part of parts) {
          const dataLine = part.split("\n").find((l) => l.startsWith("data:"));
          if (!dataLine) continue;
          const payload = dataLine.slice(5).trim();
          setLogs((prev) => [...prev, payload]);
          if (payload.startsWith("done|")) { setDone(true); setRunning(false); }
        }
      }
      setRunning(false);
    }).catch(() => { setLogs(["error|Connexion perdue"]); setRunning(false); });
  };

  const HOURS = Array.from({ length: 24 }, (_, i) => i);
  const MINUTES = [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55];

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>}
      title="Synchronisation automatique"
      description="Planifiez la récupération quotidienne des métadonnées RPM de sécurité."
      tooltip="Repod interroge chaque nuit les sources RPM configurées pour détecter les nouvelles CVE. Le cron s'exécute à l'heure définie et met à jour la base de données de sécurité locale."
    >
      <FieldRow
        label="Activer la sync automatique"
        hint="Désactiver stoppe le cron — la sync manuelle reste disponible."
      >
        <Toggle
          checked={sync.enabled ?? true}
          onChange={(v) => onChange("sync", { ...sync, enabled: v })}
        />
      </FieldRow>

      <div className={`space-y-4 ${!(sync.enabled ?? true) ? "opacity-40 pointer-events-none" : ""}`}>
        <FieldRow
          label="Heure de déclenchement"
          hint="Heure et minute (fuseau Europe/Paris)"
        >
          <div className="flex items-center gap-2">
            <select
              value={sync.hour ?? 3}
              onChange={(e) => onChange("sync", { ...sync, hour: parseInt(e.target.value) })}
              className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {HOURS.map((h) => (
                <option key={h} value={h}>{String(h).padStart(2, "0")}h</option>
              ))}
            </select>
            <span className="text-gray-400 text-sm">:</span>
            <select
              value={sync.minute ?? 0}
              onChange={(e) => onChange("sync", { ...sync, minute: parseInt(e.target.value) })}
              className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {MINUTES.map((m) => (
                <option key={m} value={m}>{String(m).padStart(2, "0")}</option>
              ))}
            </select>
          </div>
        </FieldRow>

        {nextRun && (
          <p className="text-xs text-gray-500 bg-blue-50 border border-blue-100 rounded-lg px-3 py-2">
            <span className="inline-flex items-center justify-center w-4 h-4 shrink-0 align-middle mr-1"><svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></span> Prochain déclenchement :{" "}
            <strong>{new Date(nextRun).toLocaleString("fr-FR")}</strong>
          </p>
        )}
      </div>

      {/* Sync manuelle */}
      <div className="pt-2 border-t border-gray-100">
        <div className="flex items-center justify-between mb-3">
          <div>
            <p className="text-sm font-medium text-gray-800">Synchronisation manuelle</p>
            <p className="text-xs text-gray-400">Déclenche immédiatement la sync des sources sécurité actives.</p>
          </div>
          <button
            onClick={handleManualSync}
            disabled={running}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white text-sm font-medium
                       rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
            {running ? "En cours..." : "Sync sécurité"}
          </button>
        </div>
        {logs.length > 0 && (
          <div className="border border-gray-800 rounded-lg bg-gray-900 p-3">
            <div ref={logsRef} className="max-h-40 overflow-y-auto space-y-0.5">
              {logs.map((line, i) => <LogLine key={i} line={line} />)}
            </div>
          </div>
        )}
      </div>
    </SectionCard>
  );
}

// ─── Section : Sources RPM ────────────────────────────────────────────────────

function SourcesSection({ settings, onChange }) {
  const sources = settings.sources || {};
  const standardIds = Object.keys(SOURCE_META).filter((id) => !SOURCE_META[id].security);
  const securityIds = Object.keys(SOURCE_META).filter((id) => SOURCE_META[id].security);

  const SourceRow = ({ id }) => {
    const meta = SOURCE_META[id] || { label: id, security: false };
    const enabled = sources[id] ?? true;
    return (
      <div className="flex items-center justify-between py-2.5 border-b border-gray-50 last:border-0">
        <div className="flex items-center gap-2">
          {meta.security && <span title="Source de sécurité"><svg className="w-3 h-3 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></span>}
          <div>
            <p className="text-sm text-gray-800">{meta.label}</p>
            <p className="text-xs text-gray-400 font-mono">{id}</p>
          </div>
        </div>
        <Toggle
          checked={enabled}
          onChange={(v) => onChange("sources", { ...sources, [id]: v })}
        />
      </div>
    );
  };

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 2 7 12 12 22 7"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>}
      title="Sources RPM"
      description="Activez ou désactivez chaque source. Les sources désactivées sont ignorées lors de la synchronisation et de la recherche."
      tooltip="Les sources APT sont les dépôts RPM officiels depuis lesquels Repod indexe les paquets disponibles. Les sources marquées 'Sécurité' contiennent les correctifs CVE et sont prioritaires pour les alertes."
    >
      <div>
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Sources standard</p>
        {standardIds.map((id) => <SourceRow key={id} id={id} />)}
      </div>
      <div>
        <p className="text-xs font-semibold text-red-500 uppercase tracking-wider mb-2 flex items-center gap-1"><svg className="w-3 h-3 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Sources de sécurité (CVE)</p>
        {securityIds.map((id) => <SourceRow key={id} id={id} />)}
      </div>
    </SectionCard>
  );
}

// ─── Section : Notifications ──────────────────────────────────────────────────

function NotificationsSection({ settings, onChange }) {
  const notif = settings.notifications || {};
  const [testing, setTesting] = useState(false);

  const handleTest = async () => {
    setTesting(true);
    try {
      await testWebhook();
      toast.success("Message de test envoyé !");
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur lors du test webhook");
    } finally {
      setTesting(false);
    }
  };

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>}
      title="Notifications"
      description="Recevez un rapport après chaque sync de sécurité (Slack, Teams, Mattermost ou tout service compatible webhook)."
      tooltip="Collez l'URL d'un Incoming Webhook Slack/Teams/Mattermost. Repod enverra un résumé après chaque synchronisation de sécurité : nombre de CVE détectées, paquets affectés et décisions automatiques appliquées."
    >
      <FieldRow label="Activer les notifications" hint="Envoie un résumé après chaque sync automatique.">
        <Toggle
          checked={notif.webhook_enabled ?? false}
          onChange={(v) => onChange("notifications", { ...notif, webhook_enabled: v })}
        />
      </FieldRow>

      <div className={`space-y-4 ${!(notif.webhook_enabled) ? "opacity-40 pointer-events-none" : ""}`}>
        <div>
          <label className="block text-sm font-medium text-gray-800 mb-1.5">URL Webhook</label>
          <div className="flex gap-2">
            <input
              type="url"
              value={notif.webhook_url || ""}
              onChange={(e) => onChange("notifications", { ...notif, webhook_url: e.target.value })}
              placeholder="https://hooks.slack.com/services/..."
              className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm
                         focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={handleTest}
              disabled={testing || !notif.webhook_url}
              className="px-4 py-2 bg-gray-800 text-white text-sm rounded-lg
                         hover:bg-gray-700 disabled:opacity-40 transition-colors"
            >
              {testing ? "..." : "Tester"}
            </button>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Compatible Slack, Teams (Incoming Webhook), Mattermost, Discord (/slack endpoint).
          </p>
        </div>

        <FieldRow
          label="Seuil de notification"
          hint="N'envoie une alerte que si au moins N nouveaux paquets sont indexés."
        >
          <div className="flex items-center gap-2">
            <input
              type="number"
              min={1}
              max={100}
              value={notif.webhook_min_packages ?? 1}
              onChange={(e) =>
                onChange("notifications", { ...notif, webhook_min_packages: parseInt(e.target.value) || 1 })
              }
              className="w-20 px-3 py-1.5 border border-gray-300 rounded-lg text-sm text-center
                         focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <span className="text-sm text-gray-500">paquet(s)</span>
          </div>
        </FieldRow>
      </div>
    </SectionCard>
  );
}

// ─── Section : Rétention ─────────────────────────────────────────────────────

function RetentionSection({ settings, onChange }) {
  const ret = settings.retention || {};
  const [running, setRunning]   = useState(false);
  const [lastRun, setLastRun]   = useState(null);   // { ran_at, audit_logs, packages, total_freed_bytes }

  const handleRunNow = async () => {
    setRunning(true);
    try {
      const res = await runRetention();
      setLastRun(res.result);
      toast.success("Nettoyage terminé !");
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Erreur lors du nettoyage");
    } finally {
      setRunning(false);
    }
  };

  const fmtBytes = (b) => {
    if (b >= 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} Mo`;
    if (b >= 1024)         return `${(b / 1024).toFixed(0)} Ko`;
    return `${b} o`;
  };

  const fmtDate = (iso) => {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString("fr-FR", {
        day: "2-digit", month: "2-digit", year: "numeric",
        hour: "2-digit", minute: "2-digit",
      });
    } catch { return iso; }
  };

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>}
      title="Rétention & nettoyage"
      tooltip="Définit combien de temps les logs d'audit et les anciennes versions de paquets sont conservés. Les logs d'audit sont requis pour la conformité NIS2. Les anciens paquets sont déplacés vers /repos/archive avant suppression."
      description="Conservation automatique des logs et des anciennes versions de paquets."
    >
      <FieldRow
        label="Rétention des logs d'audit"
        hint="Les fichiers JSONL plus anciens que ce délai sont supprimés automatiquement (cron 02h00)."
      >
        <div className="flex items-center gap-2">
          <input
            type="number"
            min={7}
            max={3650}
            value={ret.audit_days ?? 90}
            onChange={(e) =>
              onChange("retention", { ...ret, audit_days: parseInt(e.target.value) || 90 })
            }
            className="w-24 px-3 py-1.5 border border-gray-300 rounded-lg text-sm text-center
                       focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <span className="text-sm text-gray-500">jours</span>
        </div>
      </FieldRow>

      <FieldRow
        label="Rétention des vieux paquets"
        hint="Les versions périmées (remplacées par une plus récente) sont supprimées après ce délai."
      >
        <div className="flex items-center gap-2">
          <input
            type="number"
            min={1}
            max={365}
            value={ret.import_cleanup_days ?? 30}
            onChange={(e) =>
              onChange("retention", { ...ret, import_cleanup_days: parseInt(e.target.value) || 30 })
            }
            className="w-24 px-3 py-1.5 border border-gray-300 rounded-lg text-sm text-center
                       focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <span className="text-sm text-gray-500">jours</span>
        </div>
      </FieldRow>

      {/* Déclenchement manuel */}
      <div className="pt-2 border-t border-gray-100">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-gray-700">Nettoyage manuel</p>
            <p className="text-xs text-gray-500 mt-0.5">
              Planifié chaque nuit à 02h00. Déclenchez-le immédiatement si besoin.
            </p>
          </div>
          <button
            onClick={handleRunNow}
            disabled={running}
            className="flex items-center gap-1.5 px-4 py-2 bg-orange-600 text-white text-sm
                       font-medium rounded-lg hover:bg-orange-700 disabled:opacity-50
                       disabled:cursor-not-allowed transition-colors"
          >
            {running ? (
              <>
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                </svg>
                Nettoyage…
              </>
            ) : (
              <><svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg> Lancer maintenant</>
            )}
          </button>
        </div>

        {/* Résultat du dernier nettoyage */}
        {lastRun && (
          <div className="mt-3 bg-green-50 border border-green-200 rounded-lg p-3 text-xs text-green-800 space-y-1">
            <p className="font-medium">Dernier nettoyage : {fmtDate(lastRun.ran_at)}</p>
            <div className="grid grid-cols-3 gap-2 mt-1">
              <div className="bg-white rounded p-2 text-center border border-green-100">
                <p className="text-lg font-bold text-green-700">
                  {lastRun.audit_logs?.deleted ?? 0}
                </p>
                <p className="text-gray-500">logs supprimés</p>
              </div>
              <div className="bg-white rounded p-2 text-center border border-green-100">
                <p className="text-lg font-bold text-green-700">
                  {lastRun.packages?.deleted ?? 0}
                </p>
                <p className="text-gray-500">paquets supprimés</p>
              </div>
              <div className="bg-white rounded p-2 text-center border border-green-100">
                <p className="text-lg font-bold text-green-700">
                  {fmtBytes(lastRun.total_freed_bytes ?? 0)}
                </p>
                <p className="text-gray-500">libérés</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </SectionCard>
  );
}

// ─── Section : Validation ─────────────────────────────────────────────────────

function ValidationSection({ settings, onChange }) {
  const val = settings.validation || {};

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>}
      title="Validation des paquets"
      tooltip="Pipeline de validation exécuté à chaque upload. Chaque étape peut bloquer ou laisser passer le paquet selon sa configuration. Le scan ClamAV utilise le daemon clamd (signatures chargées en mémoire — rapide). Le scan CVE utilise Grype."
      description="Contrôles appliqués à chaque paquet importé ou uploadé manuellement."
    >
      <FieldRow
        label="Vérification SHA256"
        hint="Compare le hash du fichier téléchargé avec celui de l'index upstream."
      >
        <Toggle
          checked={val.sha256_check ?? true}
          onChange={(v) => onChange("validation", { ...val, sha256_check: v })}
        />
      </FieldRow>

      <FieldRow
        label="Scan antivirus ClamAV"
        hint="Analyse chaque .rpm avant de l'accepter dans le dépôt."
      >
        <Toggle
          checked={val.clamav_scan ?? true}
          onChange={(v) => onChange("validation", { ...val, clamav_scan: v })}
        />
      </FieldRow>

      <FieldRow
        label="Taille max upload manuel"
        hint="Limite la taille des fichiers .rpm uploadés via l'interface."
      >
        <div className="flex items-center gap-2">
          <input
            type="number"
            min={1}
            max={4096}
            value={val.max_upload_size_mb ?? 500}
            onChange={(e) =>
              onChange("validation", { ...val, max_upload_size_mb: parseInt(e.target.value) || 500 })
            }
            className="w-24 px-3 py-1.5 border border-gray-300 rounded-lg text-sm text-center
                       focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <span className="text-sm text-gray-500">Mo</span>
        </div>
      </FieldRow>
    </SectionCard>
  );
}

// ─── Section Politique CVE ───────────────────────────────────────────────────

const CVE_ACTIONS = [
  { key: "block",  label: "Bloquer",    color: "bg-red-500",    desc: "Rejet immédiat, quarantaine" },
  { key: "review", label: "Révision",   color: "bg-amber-500",  desc: "En attente RSSI" },
  { key: "warn",   label: "Avertir",    color: "bg-yellow-400", desc: "Import OK, avertissement" },
  { key: "allow",  label: "Autoriser",  color: "bg-green-500",  desc: "Transparent" },
];

function PolicySelect({ value, onChange }) {
  return (
    <div className="flex gap-1.5">
      {CVE_ACTIONS.map((a) => (
        <button
          key={a.key}
          title={a.desc}
          onClick={() => onChange(a.key)}
          className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all border-2 ${
            value === a.key
              ? `${a.color} text-white border-transparent shadow`
              : "bg-white text-gray-600 border-gray-200 hover:border-gray-400"
          }`}
        >
          {a.label}
        </button>
      ))}
    </div>
  );
}

function CvePolicySection({ settings, onChange }) {
  const pol = settings?.cve_policy || {};
  const set = (key, val) => onChange("cve_policy", { ...pol, [key]: val });

  return (
    <SectionCard
      title="Politique CVE"
      tooltip="Définit l'action automatique par niveau de sévérité CVSS. Bloquer : le paquet est rejeté en quarantaine. Révision : en attente de décision RSSI. Avertir : accepté avec alerte. Autoriser : transparant, aucune action."
      description="Comportement à l'import selon la sévérité des vulnérabilités détectées par Grype."
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>}
    >
      <div className="space-y-4">
        {/* Grille severité → action */}
        {[
          { key: "critical",   label: "CRITICAL",   desc: "CVE de score CVSS ≥ 9" },
          { key: "high",       label: "HIGH",        desc: "CVE de score CVSS 7–9" },
          { key: "medium",     label: "MEDIUM",      desc: "CVE de score CVSS 4–7" },
          { key: "low",        label: "LOW",         desc: "CVE de score CVSS < 4" },
          { key: "negligible", label: "NEGLIGIBLE",  desc: "CVE sans impact réel" },
        ].map(({ key, label, desc }) => (
          <div key={key} className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-gray-800">{label}</p>
              <p className="text-xs text-gray-400">{desc}</p>
            </div>
            <PolicySelect
              value={pol[key] || (key === "critical" ? "block" : key === "high" ? "review" : "allow")}
              onChange={(v) => set(key, v)}
            />
          </div>
        ))}

        <div className="border-t border-gray-100 pt-4 space-y-3">
          {/* SLA */}
          <FieldRow
            label="SLA HIGH (jours)"
            hint="Délai maximal de remédiation pour un HIGH en révision. Alerte à J-7."
          >
            <input
              type="number" min={1} max={365}
              value={pol.sla_high_days ?? 30}
              onChange={(e) => set("sla_high_days", parseInt(e.target.value) || 30)}
              className="w-20 px-3 py-1.5 border border-gray-300 rounded-lg text-sm text-center
                         focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </FieldRow>

          {/* Enrichissement EPSS/KEV */}
          <FieldRow
            label="Enrichissement EPSS + KEV"
            hint="Ajoute le score EPSS et le statut CISA KEV à chaque CVE à l'import (nécessite internet)."
          >
            <Toggle
              checked={pol.auto_enrich !== false}
              onChange={(v) => set("auto_enrich", v)}
            />
          </FieldRow>
        </div>

        {/* Légende */}
        <div className="bg-gray-50 rounded-lg p-3">
          <p className="text-xs font-semibold text-gray-500 mb-2">Légende des actions</p>
          <div className="grid grid-cols-2 gap-1.5">
            {CVE_ACTIONS.map((a) => (
              <div key={a.key} className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${a.color}`}></span>
                <span className="text-xs text-gray-600"><strong>{a.label}</strong> — {a.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </SectionCard>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────

export default function SettingsPage() {
  const [settings, setSettings] = useState(null);
  const [original, setOriginal] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getSettings()
      .then((data) => {
        setSettings(data);
        setOriginal(JSON.stringify(data));
      })
      .catch(() => toast.error("Impossible de charger les paramètres"))
      .finally(() => setLoading(false));
  }, []);

  const isDirty = settings && JSON.stringify(settings) !== original;

  const handleChange = (section, value) => {
    setSettings((prev) => ({ ...prev, [section]: value }));
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const updated = await patchSettings(settings);
      setSettings(updated);
      setOriginal(JSON.stringify(updated));
      toast.success("Paramètres enregistrés");
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur lors de la sauvegarde");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 text-gray-400 text-sm">
        Chargement des paramètres...
      </div>
    );
  }

  if (!settings) {
    return (
      <div className="text-center py-24 text-red-500 text-sm">
        Impossible de charger les paramètres. Vérifiez que vous êtes connecté en tant qu'administrateur.
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* En-tête */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Paramètres</h1>
          <p className="text-sm text-gray-500 mt-1">
            Configuration du serveur repod (admin uniquement).
          </p>
        </div>
        {isDirty && (
          <span className="text-xs bg-yellow-100 text-yellow-700 border border-yellow-200
                           px-3 py-1 rounded-full font-medium">
            Modifications non sauvegardées
          </span>
        )}
      </div>

      {/* Sections */}
      <SyncSection settings={settings} onChange={handleChange} />
      <SourcesSection settings={settings} onChange={handleChange} />
      <NotificationsSection settings={settings} onChange={handleChange} />
      <EmailSection settings={settings} onChange={handleChange} />
      <LdapSection settings={settings} onChange={handleChange} />
      <RetentionSection settings={settings} onChange={handleChange} />
      <ValidationSection settings={settings} onChange={handleChange} />
      <CvePolicySection settings={settings} onChange={handleChange} />
      <GpgSection />

      {/* Bouton global de sauvegarde */}
      <div className="bg-white rounded-xl border border-gray-200 px-6 py-4">
        <SaveButton onClick={handleSave} saving={saving} dirty={isDirty} />
      </div>
    </div>
  );
}

// ─── Section LDAP / Active Directory ─────────────────────────────────────────

function LdapSection({ settings, onChange }) {
  const ldap = settings.ldap || {};
  const set  = (patch) => onChange("ldap", { ...ldap, ...patch });

  const [testing, setTesting]   = useState(false);
  const [testResult, setResult] = useState(null); // { ok, message }

  const handleTest = async () => {
    setTesting(true);
    setResult(null);
    try {
      const r = await testLdap();
      setResult({ ok: true, message: r.message });
    } catch (e) {
      setResult({ ok: false, message: e?.response?.data?.detail || "Connexion échouée" });
    } finally {
      setTesting(false);
    }
  };

  const Field = ({ label, hint, children }) => (
    <FieldRow label={label} hint={hint}>{children}</FieldRow>
  );

  const inp = (key, type = "text", placeholder = "") => (
    <input
      type={type}
      value={ldap[key] ?? ""}
      onChange={(e) => set({ [key]: type === "number" ? parseInt(e.target.value) || 0 : e.target.value })}
      placeholder={placeholder}
      className="w-full px-3 py-1.5 border border-gray-300 rounded-lg text-sm
                 focus:outline-none focus:ring-2 focus:ring-blue-500"
    />
  );

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>}
      title="LDAP / Active Directory"
      description="Authentification centralisée via un annuaire d'entreprise."
      tooltip="Permet aux utilisateurs de se connecter avec leurs identifiants Active Directory ou OpenLDAP. Une fois activé, la connexion LDAP est tentée en priorité. Les comptes locaux restent actifs en secours. Requiert que le serveur LDAP soit accessible depuis le conteneur backend."
    >
      <FieldRow label="Activer l'authentification LDAP">
        <Toggle checked={!!ldap.enabled} onChange={(v) => set({ enabled: v })} />
      </FieldRow>

      <div className={!ldap.enabled ? "opacity-40 pointer-events-none space-y-5" : "space-y-5"}>

        {/* Connexion */}
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">Serveur</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label className="text-xs text-gray-500 mb-1 block">Hôte</label>
              {inp("host", "text", "ldap.example.com ou 192.168.1.10")}
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Port</label>
              {inp("port", "number", "389")}
            </div>
          </div>
          <div className="flex gap-6 mt-3">
            <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
              <input
                type="checkbox"
                checked={!!ldap.use_ssl}
                onChange={(e) => set({ use_ssl: e.target.checked })}
                className="rounded"
              />
              SSL/LDAPS (port 636)
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
              <input
                type="checkbox"
                checked={!!ldap.use_starttls}
                onChange={(e) => set({ use_starttls: e.target.checked })}
                className="rounded"
              />
              STARTTLS
            </label>
          </div>
        </div>

        {/* Compte de service */}
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">Compte de service</p>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Bind DN</label>
              {inp("bind_dn", "text", "CN=svc-repod,OU=ServiceAccounts,DC=example,DC=com")}
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Mot de passe</label>
              {inp("bind_password", "password", "••••••••")}
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Base DN de recherche</label>
              {inp("base_dn", "text", "DC=example,DC=com")}
            </div>
          </div>
        </div>

        {/* Recherche utilisateur */}
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">Recherche utilisateur</p>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-gray-500 mb-1 block">
                Filtre utilisateur{" "}
                <span className="text-blue-500 font-mono">{"{username}"}</span>
                {" "}sera remplacé par la saisie au login
              </label>
              {inp("user_filter", "text", "(sAMAccountName={username})")}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="text-xs text-gray-500 mb-1 block">Attribut login</label>
                {inp("attr_username", "text", "sAMAccountName")}
              </div>
              <div>
                <label className="text-xs text-gray-500 mb-1 block">Attribut email</label>
                {inp("attr_email", "text", "mail")}
              </div>
              <div>
                <label className="text-xs text-gray-500 mb-1 block">Attribut nom complet</label>
                {inp("attr_fullname", "text", "displayName")}
              </div>
            </div>
          </div>
        </div>

        {/* Mapping des groupes */}
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">
            Mapping groupes → rôles
          </p>
          <p className="text-xs text-gray-400 mb-3">
            DN complet ou nom partiel du groupe AD. Laissez vide pour ignorer ce rôle.
          </p>
          <div className="space-y-2">
            {[
              { key: "group_admin",      label: "Administrateur",     color: "text-red-600"    },
              { key: "group_maintainer", label: "Mainteneur",         color: "text-purple-600" },
              { key: "group_uploader",   label: "Packager / CI-CD",   color: "text-blue-600"   },
              { key: "group_auditor",    label: "Auditeur",           color: "text-yellow-600" },
              { key: "group_reader",     label: "Lecteur",            color: "text-gray-600"   },
            ].map(({ key, label, color }) => (
              <div key={key} className="flex items-center gap-3">
                <span className={`text-xs font-semibold w-32 shrink-0 ${color}`}>{label}</span>
                <input
                  type="text"
                  value={ldap[key] ?? ""}
                  onChange={(e) => set({ [key]: e.target.value })}
                  placeholder="CN=GRP-repod-admin,OU=Groups,DC=example,DC=com"
                  className="flex-1 px-3 py-1.5 border border-gray-300 rounded-lg text-xs font-mono
                             focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            ))}
          </div>
          <div className="mt-3 flex items-center gap-3">
            <label className="text-xs text-gray-500 shrink-0">Rôle par défaut</label>
            <select
              value={ldap.default_role ?? "reader"}
              onChange={(e) => set({ default_role: e.target.value })}
              className="border border-gray-300 rounded-lg px-3 py-1.5 text-sm
                         focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
            >
              {["admin","maintainer","uploader","auditor","reader"].map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
            <span className="text-xs text-gray-400">
              Attribué si aucun groupe ne correspond
            </span>
          </div>
        </div>

        {/* Auto-provisioning */}
        <FieldRow
          label="Auto-provisionnement"
          hint="Crée automatiquement le compte local après la première connexion LDAP réussie."
        >
          <Toggle
            checked={ldap.auto_provision !== false}
            onChange={(v) => set({ auto_provision: v })}
          />
        </FieldRow>

        {/* TLS / Certificat */}
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">Certificat TLS</p>
          <div className="space-y-3">
            <FieldRow
              label="Accepter les certificats auto-signés"
              hint={
                <span>
                  Désactive la validation du certificat SSL/TLS.{" "}
                  <span className="text-amber-600 font-medium">Risque MITM — à éviter en production.</span>
                  <br />Utilisez un bundle CA pour une sécurité complète.
                </span>
              }
            >
              <Toggle
                checked={ldap.verify_cert === false}
                onChange={(v) => set({ verify_cert: !v })}
              />
            </FieldRow>

            {ldap.verify_cert !== false && (
              <div>
                <label className="text-xs text-gray-500 mb-1 block">
                  Chemin bundle CA{" "}
                  <span className="text-gray-400 font-normal">(optionnel — CA interne auto-signée)</span>
                </label>
                {inp("ca_bundle_path", "text", "/repos/certs/internal-ca.crt")}
                <p className="text-xs text-gray-400 mt-1">
                  Chemin dans le conteneur backend vers le fichier .crt/.pem de votre CA.
                  Laissez vide pour utiliser le bundle système.
                </p>
              </div>
            )}

            {ldap.verify_cert === false && (
              <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2.5">
                <svg className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd"/>
                </svg>
                <p className="text-xs text-amber-700">
                  Validation SSL désactivée. Tous les certificats seront acceptés, y compris les non valides.
                  À utiliser uniquement pour les tests ou les environnements isolés.
                </p>
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Test de connexion — hors du bloc désactivé pour rester cliquable */}
      <div className="pt-3 border-t border-gray-100">
        <div className="flex items-center gap-3 flex-wrap">
          <button
            type="button"
            onClick={handleTest}
            disabled={testing || !ldap.host}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm
                       font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50
                       disabled:cursor-not-allowed transition-colors"
          >
            {testing ? (
              <>
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                </svg>
                Test en cours…
              </>
            ) : <><svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M18 6L6 18"/><path d="M7 6h1m4 0h1M7 10v5a5 5 0 0010 0v-5"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="16" y1="2" x2="16" y2="6"/></svg> Tester la connexion</>}
          </button>
          {testResult && (
            <span className={`text-sm flex items-center gap-1.5 ${
              testResult.ok ? "text-green-700" : "text-red-700"
            }`}>
              {testResult.ok ? (
                <svg className="w-4 h-4 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
              ) : (
                <svg className="w-4 h-4 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              )} {testResult.message}
            </span>
          )}
        </div>
      </div>
    </SectionCard>
  );
}


// ─── Section Email SMTP ────────────────────────────────────────────────────────

function EmailSection({ settings, onChange }) {
  const cfg = settings?.email || {};
  const [testing, setTesting] = useState(false);
  const [testTo, setTestTo] = useState("");

  const set = (key, val) => onChange("email", { ...cfg, [key]: val });

  const handleTest = async () => {
    setTesting(true);
    try {
      await testEmail(testTo || null);
      toast.success("Email de test envoyé !");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Échec envoi email");
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-gray-900">Notifications email (SMTP)</h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Alertes CVE, SLA et révisions envoyées par email en complément du webhook.
          </p>
        </div>
        <label className="flex items-center gap-2 cursor-pointer">
          <div className={`w-9 h-5 rounded-full transition-colors relative ${cfg.enabled ? "bg-blue-500" : "bg-gray-300"}`}
            onClick={() => set("enabled", !cfg.enabled)}>
            <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${cfg.enabled ? "translate-x-4" : "translate-x-0.5"}`}/>
          </div>
          <span className="text-xs font-medium text-gray-600">{cfg.enabled ? "Activé" : "Désactivé"}</span>
        </label>
      </div>

      <div className={`p-6 space-y-4 ${!cfg.enabled ? "opacity-50 pointer-events-none" : ""}`}>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Serveur SMTP</label>
            <input type="text" value={cfg.smtp_host || ""} onChange={e => set("smtp_host", e.target.value)}
              placeholder="smtp.example.com"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Port</label>
            <input type="number" value={cfg.smtp_port || 587} onChange={e => set("smtp_port", parseInt(e.target.value))}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Utilisateur SMTP</label>
            <input type="text" value={cfg.smtp_user || ""} onChange={e => set("smtp_user", e.target.value)}
              placeholder="repod@example.com"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Mot de passe</label>
            <input type="password" value={cfg.smtp_password || ""} onChange={e => set("smtp_password", e.target.value)}
              placeholder="••••••••"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Adresse expéditeur</label>
          <input type="email" value={cfg.from_address || ""} onChange={e => set("from_address", e.target.value)}
            placeholder="repod@example.com"
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>

        <div>
          <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">
            Destinataires <span className="text-gray-400 font-normal normal-case">(séparés par des virgules)</span>
          </label>
          <input type="text" value={cfg.to_addresses || ""} onChange={e => set("to_addresses", e.target.value)}
            placeholder="rssi@example.com, admin@example.com"
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>

        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={cfg.use_tls !== false}
              onChange={e => set("use_tls", e.target.checked)}
              className="rounded" />
            <span className="text-sm text-gray-700">Utiliser STARTTLS (recommandé)</span>
          </label>
        </div>

        {/* Test email */}
        <div className="pt-2 border-t border-gray-100">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Tester la configuration</p>
          <div className="flex gap-2">
            <input type="email" value={testTo} onChange={e => setTestTo(e.target.value)}
              placeholder="Destinataire test (optionnel)"
              className="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
            <button onClick={handleTest} disabled={testing}
              className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors">
              {testing ? "Envoi..." : "Envoyer un test"}
            </button>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Si vide, l'email est envoyé aux destinataires configurés ci-dessus.
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Section GPG ──────────────────────────────────────────────────────────────

function GpgSection() {
  const [gpg, setGpg]           = useState(null);
  const [loading, setLoading]   = useState(true);
  const [generating, setGen]    = useState(false);
  const [showPubKey, setShow]   = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getGpgInfo();
      setGpg(data);
    } catch {
      setGpg(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleGenerate = async () => {
    if (!window.confirm("Générer une nouvelle clé GPG 4096 bits ? L'ancienne clé sera conservée mais les clients devront mettre à jour leur trousseau.")) return;
    setGen(true);
    try {
      const r = await generateGpgKey();
      toast.success(r.message || "Clé GPG générée");
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Erreur génération GPG");
    } finally {
      setGen(false);
    }
  };

  const key = gpg?.keys?.[0];

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-gray-900">Clé GPG du dépôt</h2>
          <p className="text-xs text-gray-500 mt-0.5">Utilisée pour signer les packages et les fichiers Release</p>
        </div>
        <button onClick={handleGenerate} disabled={generating}
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium border border-gray-200 rounded-lg hover:bg-gray-50 disabled:opacity-50 text-gray-600 transition-colors">
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4"/>
          </svg>
          {generating ? "Génération…" : "Générer une nouvelle clé"}
        </button>
      </div>

      <div className="px-6 py-4">
        {loading ? (
          <p className="text-sm text-gray-400">Chargement…</p>
        ) : !key ? (
          <div className="bg-amber-50 border border-amber-200 rounded-xl px-4 py-3">
            <p className="text-sm font-semibold text-amber-800">Aucune clé GPG trouvée</p>
            <p className="text-xs text-amber-600 mt-0.5">Cliquez sur "Générer une nouvelle clé" pour initialiser le trousseau GPG du dépôt.</p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Key ID",      value: key.key_id || "—" },
                { label: "Algorithme",  value: `RSA ${key.algo || ""}` },
                { label: "UID",         value: key.uids?.[0] || "—" },
                { label: "Expire le",   value: key.expires || "Pas d'expiration" },
              ].map(({ label, value }) => (
                <div key={label} className="bg-gray-50 rounded-lg px-3 py-2.5">
                  <p className="text-xs text-gray-500 mb-0.5">{label}</p>
                  <p className="text-sm font-mono text-gray-800 truncate">{value}</p>
                </div>
              ))}
            </div>

            {key.fingerprint && (
              <div className="bg-gray-50 rounded-lg px-3 py-2.5">
                <p className="text-xs text-gray-500 mb-0.5">Fingerprint</p>
                <p className="text-xs font-mono text-gray-700 break-all">{key.fingerprint}</p>
              </div>
            )}

            {gpg.public_key_armored && (
              <div>
                <button onClick={() => setShow(!showPubKey)}
                  className="text-xs text-blue-600 hover:underline font-medium">
                  {showPubKey ? "Masquer la clé publique" : "Afficher la clé publique (PEM)"}
                </button>
                {showPubKey && (
                  <div className="mt-2 relative">
                    <pre className="bg-gray-900 text-green-400 text-xs font-mono p-4 rounded-xl overflow-x-auto max-h-48 overflow-y-auto">
                      {gpg.public_key_armored}
                    </pre>
                    <button
                      onClick={() => { navigator.clipboard.writeText(gpg.public_key_armored); toast.success("Clé copiée"); }}
                      className="absolute top-2 right-2 px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded hover:bg-gray-600">
                      Copier
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
