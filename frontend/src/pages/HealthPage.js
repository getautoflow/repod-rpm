import { useState, useEffect, useCallback } from "react";
import { getHealth, getBaseUrl } from "../api";

const BASE_URL = getBaseUrl();

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const handle = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      onClick={handle}
      className="ml-auto px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-200
                 hover:bg-gray-100 text-gray-600 transition-colors flex items-center gap-1.5"
    >
      {copied ? (
        <>
          <svg className="w-3 h-3 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
          Copié !
        </>
      ) : (
        <>
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round"
              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
          Copier
        </>
      )}
    </button>
  );
}

function StatusBadge({ status }) {
  const cfg = {
    healthy:  { bg: "bg-green-100",  text: "text-green-800",  dot: "bg-green-500",  label: "Opérationnel" },
    degraded: { bg: "bg-orange-100", text: "text-orange-800", dot: "bg-orange-500", label: "Dégradé"       },
    error:    { bg: "bg-red-100",    text: "text-red-800",    dot: "bg-red-500",    label: "Erreur"        },
    unknown:  { bg: "bg-gray-100",   text: "text-gray-600",   dot: "bg-gray-400",   label: "Inconnu"       },
  }[status] ?? { bg: "bg-gray-100", text: "text-gray-600", dot: "bg-gray-400", label: status };

  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold ${cfg.bg} ${cfg.text}`}>
      <span className={`w-2 h-2 rounded-full ${cfg.dot} ${status === "healthy" ? "animate-pulse" : ""}`} />
      {cfg.label}
    </span>
  );
}

function CheckCard({ title, icon, check, children }) {
  const ok = check?.ok !== false;
  return (
    <div className={`bg-white rounded-xl border ${ok ? "border-gray-200" : "border-red-200"} p-4 space-y-3`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="w-5 h-5 text-gray-500 shrink-0">{icon}</span>
          <span className="text-sm font-semibold text-gray-800">{title}</span>
        </div>
        <StatusBadge status={check?.ok ? "healthy" : check === null ? "unknown" : "error"} />
      </div>
      {children}
    </div>
  );
}

function MetaRow({ label, value, mono = false }) {
  return (
    <div className="flex justify-between items-center text-xs">
      <span className="text-gray-500">{label}</span>
      <span className={`font-medium text-gray-700 ${mono ? "font-mono" : ""}`}>{value ?? "—"}</span>
    </div>
  );
}

function DiskBar({ usedPct }) {
  if (usedPct == null) return null;
  const color = usedPct > 90 ? "bg-red-500" : usedPct > 75 ? "bg-orange-400" : "bg-green-500";
  return (
    <div className="mt-2">
      <div className="flex justify-between text-xs text-gray-500 mb-1">
        <span>Utilisation disque</span>
        <span className={usedPct > 90 ? "text-red-600 font-semibold" : ""}>{usedPct}%</span>
      </div>
      <div className="w-full bg-gray-100 rounded-full h-2">
        <div className={`${color} h-2 rounded-full transition-all`} style={{ width: `${usedPct}%` }} />
      </div>
    </div>
  );
}

function fmtDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("fr-FR", {
      day: "2-digit", month: "2-digit", year: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch { return iso; }
}

export default function HealthPage() {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState("");
  const [lastRefresh, setLastRefresh] = useState(null);

  const load = useCallback(async () => {
    try {
      const d = await getHealth();
      setData(d);
      setError("");
      setLastRefresh(new Date());
    } catch (e) {
      setError("Impossible de charger le statut de santé.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30_000); // refresh toutes les 30s
    return () => clearInterval(interval);
  }, [load]);

  const checks = data?.checks ?? {};

  return (
    <div className="p-6 space-y-6">

      {/* En-tête */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Supervision système</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            État des composants · refresh auto 30s
            {lastRefresh && (
              <span className="ml-2 text-gray-400">
                · mis à jour {lastRefresh.toLocaleTimeString("fr-FR")}
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {data && <StatusBadge status={data.status} />}
          <button
            onClick={load}
            disabled={loading}
            className="p-2 rounded-lg border border-gray-200 hover:bg-gray-50 text-gray-500
                       disabled:opacity-50 transition-colors"
            title="Rafraîchir"
          >
            <svg className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700">{error}</div>
      )}

      {loading && !data && (
        <div className="flex justify-center py-16">
          <svg className="animate-spin w-8 h-8 text-blue-500" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
          </svg>
        </div>
      )}

      {data && (
        <>
          {/* Infos API */}
          <div className="bg-blue-50 border border-blue-200 rounded-xl px-5 py-3 flex flex-wrap gap-6 text-sm">
            <div>
              <span className="text-blue-500 font-medium">Version</span>
              <span className="ml-2 font-mono text-blue-800">{data.version || "dev"}</span>
            </div>
            <div>
              <span className="text-blue-500 font-medium">Timestamp</span>
              <span className="ml-2 text-blue-800">{fmtDate(data.timestamp)}</span>
            </div>
          </div>

          {/* ─── Section Prometheus ─────────────────────────────── */}
          {(() => {
            const metricsUrl = `${BASE_URL}/metrics`;
            const scrapeYaml = `- job_name: 'repod'\n  scrape_interval: 30s\n  static_configs:\n    - targets: ['${(BASE_URL || "localhost:8000").replace(/^https?:\/\//, "")}']  # host:port\n  metrics_path: /metrics`;
            return (
              <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
                <div className="flex items-center gap-2">
                  <svg className="w-5 h-5 text-orange-500 shrink-0" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm0 18a8 8 0 110-16 8 8 0 010 16zm-1-5h2v2h-2v-2zm0-8h2v6h-2V7z"/>
                  </svg>
                  <h2 className="text-sm font-semibold text-gray-800">Métriques Prometheus</h2>
                </div>
                <p className="text-xs text-gray-500">
                  Endpoint <span className="font-mono">/metrics</span> disponible pour le scraping.
                  Expose les compteurs HTTP, latences, paquets et vulnérabilités.
                </p>

                {/* Lien endpoint */}
                <div className="flex items-center gap-2 bg-gray-50 rounded-lg px-3 py-2">
                  <span className="text-xs font-mono font-semibold text-green-700 bg-green-100 px-2 py-0.5 rounded">GET</span>
                  <span className="text-xs font-mono text-gray-700 flex-1">{metricsUrl}</span>
                  <a
                    href={metricsUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-blue-600 hover:underline whitespace-nowrap"
                  >
                    Ouvrir ↗
                  </a>
                </div>

                {/* Métriques exposées */}
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {[
                    ["repod_http_requests_total",            "Requêtes HTTP (method, path, status)"],
                    ["repod_http_request_duration_seconds",  "Latence des requêtes (histogramme)"],
                    ["repod_packages_total",                 "Paquets par distribution et arch"],
                    ["repod_vulnerabilities_total",          "CVE par sévérité"],
                    ["repod_uploads_total",                  "Uploads de paquets (succès/échec)"],
                  ].map(([name, desc]) => (
                    <div key={name} className="bg-gray-50 rounded-lg px-3 py-2">
                      <p className="font-mono text-gray-800 text-xs leading-tight">{name}</p>
                      <p className="text-gray-400 mt-0.5">{desc}</p>
                    </div>
                  ))}
                </div>

                {/* Config scrape */}
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <p className="text-xs font-medium text-gray-700">Configuration <span className="font-mono">prometheus.yml</span></p>
                    <CopyButton text={scrapeYaml} />
                  </div>
                  <pre className="bg-gray-900 text-green-400 text-xs rounded-lg p-4 overflow-x-auto leading-relaxed">
{scrapeYaml}
                  </pre>
                </div>
              </div>
            );
          })()}

          {/* Grille des checks */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

            {/* Volumes */}
            <CheckCard title="Volume Manifests" icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>} check={checks.manifests}>
              <MetaRow label="Espace libre"  value={checks.manifests?.free_gb != null ? `${checks.manifests.free_gb} Go` : null} />
              <MetaRow label="Espace total"  value={checks.manifests?.total_gb != null ? `${checks.manifests.total_gb} Go` : null} />
              <DiskBar usedPct={checks.manifests?.used_pct} />
            </CheckCard>

            <CheckCard title="Volume Pool (.rpm)" icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>} check={checks.pool}>
              <MetaRow label="Espace libre"  value={checks.pool?.free_gb != null ? `${checks.pool.free_gb} Go` : null} />
              <MetaRow label="Espace total"  value={checks.pool?.total_gb != null ? `${checks.pool.total_gb} Go` : null} />
              <DiskBar usedPct={checks.pool?.used_pct} />
            </CheckCard>

            <CheckCard title="Volume Audit" icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2"/><rect x="9" y="3" width="6" height="4" rx="1"/></svg>} check={checks.audit}>
              <MetaRow label="Espace libre"  value={checks.audit?.free_gb != null ? `${checks.audit.free_gb} Go` : null} />
              <MetaRow label="Espace total"  value={checks.audit?.total_gb != null ? `${checks.audit.total_gb} Go` : null} />
              <DiskBar usedPct={checks.audit?.used_pct} />
            </CheckCard>

            <CheckCard title="ClamAV" icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>} check={checks.clamav}>
              <MetaRow label="Version" value={checks.clamav?.version} mono />
              {!checks.clamav?.ok && (
                <p className="text-xs text-red-600 mt-1">
                  ClamAV non disponible — les scans antivirus seront désactivés.
                </p>
              )}
            </CheckCard>

            {/* Paquets */}
            <CheckCard title="Paquets" icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>} check={checks.packages}>
              <MetaRow label="Manifests"    value={checks.packages?.total_manifests} />
              <MetaRow label="Fichiers .rpm" value={checks.packages?.pool_files} />
              <MetaRow label="Taille pool"  value={checks.packages?.pool_size_mb != null ? `${checks.packages.pool_size_mb} Mo` : null} />
            </CheckCard>

            {/* Scheduler */}
            <CheckCard title="Scheduler (tâches planifiées)" icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>} check={checks.scheduler}>
              {checks.scheduler?.jobs?.length > 0 ? (
                <div className="space-y-2">
                  {checks.scheduler.jobs.map((job) => (
                    <div key={job.id} className="flex items-start justify-between text-xs">
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-gray-700 truncate">{job.name}</p>
                        <p className="text-gray-400 font-mono">{job.id}</p>
                      </div>
                      <div className="ml-3 text-right shrink-0">
                        {job.paused ? (
                          <span className="text-orange-500 font-semibold">En pause</span>
                        ) : (
                          <span className="text-gray-500">{fmtDate(job.next_run)}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-gray-400">Aucune tâche planifiée.</p>
              )}
            </CheckCard>
          </div>
        </>
      )}
    </div>
  );
}
