import { useState, useEffect, useCallback } from "react";
import { getDownloadStats } from "../api";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer,
} from "recharts";

function fmtBytes(b) {
  if (b >= 1073741824) return `${(b / 1073741824).toFixed(1)} Go`;
  if (b >= 1048576)    return `${(b / 1048576).toFixed(0)} Mo`;
  if (b >= 1024)       return `${(b / 1024).toFixed(0)} Ko`;
  return `${b} o`;
}

function StatCard({ label, value, sub, color = "blue" }) {
  const colors = {
    blue:   "bg-blue-50   border-blue-200  text-blue-700",
    green:  "bg-green-50  border-green-200 text-green-700",
    purple: "bg-purple-50 border-purple-200 text-purple-700",
    orange: "bg-orange-50 border-orange-200 text-orange-700",
  };
  return (
    <div className={`rounded-xl border p-4 ${colors[color]}`}>
      <p className="text-xs font-medium opacity-70 mb-1">{label}</p>
      <p className="text-2xl font-bold">{value}</p>
      {sub && <p className="text-xs opacity-60 mt-0.5">{sub}</p>}
    </div>
  );
}

export default function DownloadStatsPage() {
  const [days, setDays]       = useState(30);
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch]   = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const d = await getDownloadStats(days);
      setData(d);
    } catch (e) {
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => { load(); }, [load]);

  const summary    = data?.summary ?? {};
  const perPackage = (data?.per_package ?? []).filter(
    (p) => !search || p.name.toLowerCase().includes(search.toLowerCase())
  );
  const perDay = (data?.per_day ?? []).map((d) => ({
    ...d,
    label: d.date.slice(5), // "MM-DD"
  }));

  if (!summary.log_available && !loading) {
    return (
      <div className="p-6">
        <div className="bg-orange-50 border border-orange-200 rounded-xl p-6 text-center space-y-3">
          <svg className="w-10 h-10 text-gray-400 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
          <p className="font-semibold text-orange-800">Logs de téléchargement non disponibles</p>
          <p className="text-sm text-orange-700">
            Le fichier <code className="font-mono bg-orange-100 px-1 rounded">downloads.log</code> n'existe pas encore.
            Il sera créé automatiquement dès qu'un client APT téléchargera un paquet.
          </p>
          <p className="text-xs text-orange-600">
            Assurez-vous que le volume <code className="font-mono">./repos/logs</code> est bien monté
            (relancez <code className="font-mono">docker compose up -d</code> si besoin).
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">

      {/* En-tête */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Statistiques de téléchargements</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Paquets téléchargés par les clients DNF/Zypper
          </p>
        </div>
        <div className="flex items-center gap-2">
          {[7, 30, 90].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                days === d
                  ? "bg-blue-600 text-white"
                  : "border border-gray-200 text-gray-600 hover:bg-gray-50"
              }`}
            >
              {d}j
            </button>
          ))}
          <button
            onClick={load}
            disabled={loading}
            className="ml-2 p-2 rounded-lg border border-gray-200 hover:bg-gray-50
                       text-gray-500 disabled:opacity-50 transition-colors"
          >
            <svg className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
          </button>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Téléchargements"
          value={summary.total_downloads?.toLocaleString("fr-FR") ?? "—"}
          sub={`dont ${summary.rpm_downloads ?? 0} via DNF/Zypper`}
          color="blue"
        />
        <StatCard
          label="Paquets distincts"
          value={summary.unique_packages ?? "—"}
          color="purple"
        />
        <StatCard
          label="Clients uniques"
          value={summary.unique_clients ?? "—"}
          sub="adresses IP"
          color="green"
        />
        <StatCard
          label="Volume servi"
          value={fmtBytes(summary.total_bytes ?? 0)}
          color="orange"
        />
      </div>

      {/* Graphe par jour */}
      {perDay.length > 0 && (
        <div className="bg-white rounded-xl border border-gray-200 p-5">
          <h2 className="text-sm font-semibold text-gray-800 mb-4">
            Téléchargements par jour — {days} derniers jours
          </h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={perDay} margin={{ top: 0, right: 10, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis dataKey="label" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip
                formatter={(v) => [v, "téléchargements"]}
                contentStyle={{ fontSize: 12, borderRadius: 8 }}
              />
              <Bar dataKey="downloads" fill="#3b82f6" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Top paquets */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-800">
            Paquets les plus téléchargés
          </h2>
          <input
            type="text"
            placeholder="Rechercher…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm
                       focus:outline-none focus:ring-2 focus:ring-blue-500 w-48"
          />
        </div>

        {perPackage.length === 0 ? (
          <div className="py-10 text-center text-sm text-gray-400">
            {search ? "Aucun paquet correspondant." : "Aucun téléchargement enregistré sur cette période."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-50 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  <th className="px-5 py-3 text-left">#</th>
                  <th className="px-5 py-3 text-left">Paquet</th>
                  <th className="px-5 py-3 text-right">Téléchargements</th>
                  <th className="px-5 py-3 text-right">Volume servi</th>
                  <th className="px-5 py-3 text-right">Clients uniques</th>
                  <th className="px-5 py-3 text-left">Versions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {perPackage.map((pkg, i) => {
                  const maxDl = perPackage[0]?.downloads || 1;
                  const pct   = Math.round((pkg.downloads / maxDl) * 100);
                  return (
                    <tr key={pkg.name} className="hover:bg-gray-50 transition-colors">
                      <td className="px-5 py-3 text-gray-400 font-mono text-xs">{i + 1}</td>
                      <td className="px-5 py-3">
                        <div className="font-medium text-gray-800">{pkg.name}</div>
                        <div className="w-full bg-gray-100 rounded-full h-1 mt-1">
                          <div
                            className="bg-blue-500 h-1 rounded-full"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </td>
                      <td className="px-5 py-3 text-right font-semibold text-gray-800">
                        {pkg.downloads.toLocaleString("fr-FR")}
                      </td>
                      <td className="px-5 py-3 text-right text-gray-600">
                        {fmtBytes(pkg.bytes)}
                      </td>
                      <td className="px-5 py-3 text-right text-gray-600">
                        {pkg.clients}
                      </td>
                      <td className="px-5 py-3">
                        <div className="flex flex-wrap gap-1">
                          {pkg.versions.slice(0, 3).map((v) => (
                            <span key={v} className="inline-block px-1.5 py-0.5 bg-gray-100 text-gray-600
                                                      rounded text-xs font-mono">
                              {v}
                            </span>
                          ))}
                          {pkg.versions.length > 3 && (
                            <span className="text-xs text-gray-400">+{pkg.versions.length - 3}</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Téléchargements récents */}
      {(data?.recent ?? []).length > 0 && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-100">
            <h2 className="text-sm font-semibold text-gray-800">50 derniers téléchargements</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gray-50 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  <th className="px-5 py-3 text-left">Date</th>
                  <th className="px-5 py-3 text-left">Fichier</th>
                  <th className="px-5 py-3 text-left">Client IP</th>
                  <th className="px-5 py-3 text-right">Taille</th>
                  <th className="px-5 py-3 text-left">User-Agent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {data.recent.map((r, i) => (
                  <tr key={i} className="hover:bg-gray-50">
                    <td className="px-5 py-2.5 font-mono text-gray-500">{r.date}</td>
                    <td className="px-5 py-2.5 font-medium text-gray-800 max-w-xs truncate">{r.filename}</td>
                    <td className="px-5 py-2.5 font-mono text-gray-600">{r.ip}</td>
                    <td className="px-5 py-2.5 text-right text-gray-500">{fmtBytes(r.bytes)}</td>
                    <td className="px-5 py-2.5 text-gray-400 max-w-xs truncate">{r.user_agent}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
