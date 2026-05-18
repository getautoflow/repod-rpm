import { useState, useEffect } from "react";
import toast from "react-hot-toast";
import {
  getDistributions, getDistribPackages,
  promotePackage, initDistributions,
} from "../api";

const DISTRO_META = {
  almalinux8:           { color: "bg-blue-50 border-blue-200",   badge: "bg-blue-100 text-blue-700",   icon: "text-blue-500",   label: "AlmaLinux 8" },
  rocky8:               { color: "bg-green-50 border-green-200", badge: "bg-green-100 text-green-700", icon: "text-green-500", label: "Rocky Linux 8" },
  "centos-stream9":     { color: "bg-purple-50 border-purple-200", badge: "bg-purple-100 text-purple-700", icon: "text-purple-500", label: "CentOS Stream 9" },
  oraclelinux8:         { color: "bg-red-50 border-red-200",     badge: "bg-red-100 text-red-700",     icon: "text-red-500",   label: "Oracle Linux 8" },
  fedora:               { color: "bg-indigo-50 border-indigo-200", badge: "bg-indigo-100 text-indigo-700", icon: "text-indigo-500", label: "Fedora" },
  "opensuse-leap-15.5": { color: "bg-teal-50 border-teal-200",   badge: "bg-teal-100 text-teal-700",   icon: "text-teal-500",  label: "openSUSE Leap 15.5" },
  "opensuse-leap-15.6": { color: "bg-teal-50 border-teal-200",   badge: "bg-teal-100 text-teal-700",   icon: "text-teal-500",  label: "openSUSE Leap 15.6" },
  "opensuse-leap":      { color: "bg-teal-50 border-teal-200",   badge: "bg-teal-100 text-teal-700",   icon: "text-teal-500",  label: "openSUSE Leap" },
  "opensuse-tumbleweed":{ color: "bg-cyan-50 border-cyan-200",   badge: "bg-cyan-100 text-cyan-700",   icon: "text-cyan-500",  label: "openSUSE Tumbleweed" },
};

function DistribCard({ distrib, onSelect, selected }) {
  const meta = DISTRO_META[distrib.codename] || {
    color: "bg-gray-50 border-gray-200",
    badge: "bg-gray-100 text-gray-700",
    icon:  "text-gray-500",
    label: distrib.codename,
  };
  return (
    <button
      onClick={() => onSelect(distrib.codename)}
      className={`text-left w-full rounded-xl border-2 p-5 transition-all ${
        selected ? "border-blue-500 bg-blue-50" : `${meta.color} hover:border-blue-300`
      }`}
    >
      <div className="flex items-start justify-between mb-3">
        <div className={`w-10 h-10 rounded-xl ${selected ? "bg-blue-100" : "bg-white/60"} flex items-center justify-center`}>
          <svg className={`w-5 h-5 ${selected ? "text-blue-600" : meta.icon}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
          </svg>
        </div>
        <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${meta.badge}`}>
          {distrib.badge || (distrib.codename.startsWith("opensuse") ? "Zypper" : "DNF")}
        </span>
      </div>
      <p className="font-bold text-gray-900 text-sm">{meta.label}</p>
      <p className="text-xs text-gray-500 font-mono mt-0.5">{distrib.codename}</p>
      <p className="text-2xl font-bold text-gray-800 mt-3">{distrib.package_count}</p>
      <p className="text-xs text-gray-400">paquet(s)</p>
    </button>
  );
}

// ─── Panneau promotion ────────────────────────────────────────────────────────

function PromotePanel({ distribs, onClose, onDone }) {
  const [pkg, setPkg] = useState("");
  const [fromDist, setFromDist] = useState(distribs[0]?.codename || "almalinux8");
  const [toDist, setToDist] = useState(distribs[1]?.codename || "rocky8");
  const [loading, setLoading] = useState(false);
  const [packages, setPackages] = useState([]);
  const [loadingPkgs, setLoadingPkgs] = useState(false);

  useEffect(() => {
    if (!fromDist) return;
    setLoadingPkgs(true);
    getDistribPackages(fromDist)
      .then((d) => setPackages(d.packages || []))
      .catch(() => setPackages([]))
      .finally(() => setLoadingPkgs(false));
  }, [fromDist]);

  const handlePromote = async () => {
    if (!pkg) { toast.error("Sélectionnez un paquet"); return; }
    if (fromDist === toDist) { toast.error("Source et destination identiques"); return; }
    setLoading(true);
    try {
      const res = await promotePackage(pkg, fromDist, toDist);
      toast.success(res.message);
      onDone();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur lors de la promotion");
    } finally {
      setLoading(false);
    }
  };

  const codenames = distribs.map((d) => d.codename);

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30" onClick={onClose} />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
        <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md">
          <div className="flex items-center justify-between p-6 border-b border-gray-100">
            <div>
              <h2 className="font-bold text-gray-900">Promouvoir un paquet RPM</h2>
              <p className="text-xs text-gray-500 mt-0.5">Copie un paquet d'une distribution vers une autre</p>
            </div>
            <button onClick={onClose} className="p-1.5 text-gray-400 hover:text-gray-600 rounded-lg">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div className="p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Distribution source</label>
              <select value={fromDist} onChange={(e) => { setFromDist(e.target.value); setPkg(""); }}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                {codenames.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Paquet RPM</label>
              {loadingPkgs ? (
                <p className="text-xs text-gray-400 italic">Chargement...</p>
              ) : (
                <select value={pkg} onChange={(e) => setPkg(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                  <option value="">-- Sélectionner --</option>
                  {packages.map((p) => <option key={p.name} value={p.name}>{p.name} ({p.version})</option>)}
                </select>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Distribution destination</label>
              <select value={toDist} onChange={(e) => setToDist(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                {codenames.filter((c) => c !== fromDist).map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div className="flex items-center gap-3 bg-gray-50 border border-gray-200 rounded-lg px-4 py-3 text-sm">
              <span className="font-mono font-semibold text-gray-700">{pkg || "…"}</span>
              <svg className="w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
              </svg>
              <span className="font-mono text-blue-600 font-semibold">{toDist}</span>
            </div>
            <button
              onClick={handlePromote}
              disabled={loading || !pkg}
              className="w-full py-3 bg-blue-600 text-white text-sm font-medium rounded-xl hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {loading ? "Promotion en cours..." : "Promouvoir"}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────

export default function DistributionsPage() {
  const [distribs, setDistribs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDist, setSelectedDist] = useState(null);
  const [distPackages, setDistPackages] = useState([]);
  const [loadingPkgs, setLoadingPkgs] = useState(false);
  const [showPromote, setShowPromote] = useState(false);
  const [initing, setIniting] = useState(false);

  useEffect(() => { load(); }, []);

  useEffect(() => {
    if (!selectedDist) return;
    setLoadingPkgs(true);
    getDistribPackages(selectedDist)
      .then((d) => setDistPackages(d.packages || []))
      .catch(() => setDistPackages([]))
      .finally(() => setLoadingPkgs(false));
  }, [selectedDist]);

  const load = async () => {
    setLoading(true);
    try {
      const data = await getDistributions();
      setDistribs(data.distributions || []);
    } catch {
      toast.error("Impossible de charger les distributions");
    } finally {
      setLoading(false);
    }
  };

  const handleInit = async () => {
    if (!window.confirm("Initialiser les répertoires createrepo_c pour les 9 distributions RPM ?")) return;
    setIniting(true);
    try {
      const res = await initDistributions();
      const ok = res.results.filter((r) => r.ok).length;
      toast.success(`${ok}/${res.results.length} distributions initialisées`);
      load();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur d'initialisation");
    } finally {
      setIniting(false);
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-gray-400 text-sm">Chargement...</div>;
  }

  return (
    <div className="space-y-6 p-6">
      {showPromote && (
        <PromotePanel
          distribs={distribs}
          onClose={() => setShowPromote(false)}
          onDone={() => { setShowPromote(false); load(); }}
        />
      )}

      {/* En-tête */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Distributions RPM</h1>
          <p className="text-sm text-gray-500 mt-1">
            Gestion des 9 distributions RPM (AlmaLinux, Rocky, CentOS, Oracle, Fedora, openSUSE).
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleInit}
            disabled={initing}
            className="flex items-center gap-2 px-3 py-2 text-sm text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 disabled:opacity-40 transition-colors"
            title="Initialise les répertoires createrepo_c pour les distributions"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
            </svg>
            {initing ? "Init..." : "Init distributions"}
          </button>
          <button
            onClick={() => setShowPromote(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-white border border-gray-200 rounded-lg hover:bg-gray-50 hover:border-blue-400 hover:text-blue-600 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
            </svg>
            Promouvoir un paquet
          </button>
        </div>
      </div>

      {/* Cartes distributions */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {distribs.map((d) => (
          <DistribCard
            key={d.codename}
            distrib={d}
            selected={selectedDist === d.codename}
            onSelect={(c) => setSelectedDist(selectedDist === c ? null : c)}
          />
        ))}
      </div>

      {/* Liste des paquets de la distribution sélectionnée */}
      {selectedDist && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
            <div className="flex items-center gap-3">
              <h2 className="text-sm font-semibold text-gray-800">
                Paquets RPM dans <span className="font-mono text-blue-600">{selectedDist}</span>
              </h2>
              <span className="px-2 py-0.5 bg-gray-100 rounded text-xs text-gray-600">
                {loadingPkgs ? "…" : `${distPackages.length} paquet(s)`}
              </span>
            </div>
            <button onClick={() => setSelectedDist(null)}
              className="p-1 text-gray-400 hover:text-gray-600">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          {loadingPkgs ? (
            <div className="p-8 text-center text-gray-400 text-sm">Chargement...</div>
          ) : distPackages.length === 0 ? (
            <div className="p-8 text-center text-gray-400 text-sm">
              Aucun paquet RPM dans cette distribution.
            </div>
          ) : (
            <div className="divide-y divide-gray-100 max-h-96 overflow-y-auto">
              {distPackages.map((pkg) => (
                <div key={pkg.name} className="flex items-center justify-between px-5 py-3 hover:bg-gray-50">
                  <div>
                    <span className="font-mono text-sm font-medium text-gray-900">{pkg.name}</span>
                    <span className="ml-3 text-xs text-gray-400">{pkg.version}</span>
                    {pkg.arch && <span className="ml-2 text-xs text-gray-300 font-mono">{pkg.arch}</span>}
                  </div>
                  <button
                    onClick={() => setShowPromote(true)}
                    className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                  >
                    Promouvoir →
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
