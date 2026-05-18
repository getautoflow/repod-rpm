import { useState, useEffect, useCallback } from "react";
import { getSbomPreview, getSbomExportUrl, getSbomPackageUrl, getDistributions } from "../api";
import { useAuth } from "../context/AuthContext";

const FORMATS = [
  {
    id: "cyclonedx",
    label: "CycloneDX JSON",
    badge: "OWASP",
    desc: "Format le plus répandu. Compatible Dependency-Track, Grype, Trivy, GitHub.",
    ext: ".cdx.json",
  },
  {
    id: "spdx",
    label: "SPDX JSON",
    badge: "ISO/IEC 5962",
    desc: "Standard ISO. Compatible FOSSA, Black Duck, OpenChain, NTIA.",
    ext: ".spdx.json",
  },
];

function FormatCard({ fmt, selected, onSelect }) {
  return (
    <button
      onClick={() => onSelect(fmt.id)}
      className={`w-full text-left rounded-xl border-2 p-4 transition-all ${
        selected
          ? "border-blue-500 bg-blue-50"
          : "border-gray-200 bg-white hover:border-gray-300"
      }`}
    >
      <div className="flex items-center justify-between mb-1">
        <span className="font-semibold text-gray-800 text-sm">{fmt.label}</span>
        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
          selected ? "bg-blue-100 text-blue-700" : "bg-gray-100 text-gray-500"
        }`}>
          {fmt.badge}
        </span>
      </div>
      <p className="text-xs text-gray-500">{fmt.desc}</p>
      <p className="text-xs font-mono text-gray-400 mt-1">{fmt.ext}</p>
    </button>
  );
}

export default function SbomPage() {
  const { token } = useAuth();
  const [format, setFormat]           = useState("cyclonedx");
  const [distribution, setDistrib]    = useState("");
  const [distributions, setDistribs]  = useState([]);
  const [preview, setPreview]         = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [exporting, setExporting]     = useState(false);

  // Charger les distributions disponibles
  useEffect(() => {
    getDistributions()
      .then((d) => setDistribs(Array.isArray(d) ? d.map(x => x.codename || x) : []))
      .catch(() => {});
  }, []);

  const loadPreview = useCallback(async () => {
    setPreviewLoading(true);
    try {
      const d = await getSbomPreview(format, distribution || null);
      setPreview(d);
    } catch {
      setPreview(null);
    } finally {
      setPreviewLoading(false);
    }
  }, [format, distribution]);

  useEffect(() => { loadPreview(); }, [loadPreview]);

  // Téléchargement via lien authentifié
  const handleExport = async () => {
    setExporting(true);
    try {
      const url = getSbomExportUrl(format, distribution || null);
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!resp.ok) throw new Error("Export échoué");
      const blob = await resp.blob();
      const cd   = resp.headers.get("content-disposition") || "";
      const match = cd.match(/filename="?([^"]+)"?/);
      const filename = match ? match[1] : `sbom.${format === "cyclonedx" ? "cdx" : "spdx"}.json`;
      const a = document.createElement("a");
      a.href  = URL.createObjectURL(blob);
      a.download = filename;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch {
      /* silencieux — l'utilisateur verra l'absence de téléchargement */
    } finally {
      setExporting(false);
    }
  };

  const handlePackageExport = async (name, version, arch = "x86_64") => {
    const url = getSbomPackageUrl(name, version, format, arch);
    try {
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!resp.ok) throw new Error();
      const blob = await resp.blob();
      const cd   = resp.headers.get("content-disposition") || "";
      const match = cd.match(/filename="?([^"]+)"?/);
      const filename = match ? match[1] : `sbom-${name}-${version}.json`;
      const a = document.createElement("a");
      a.href  = URL.createObjectURL(blob);
      a.download = filename;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch {}
  };

  const components =
    format === "cyclonedx"
      ? (preview?.preview?.components ?? [])
      : (preview?.preview?.packages ?? []).filter((p) => p.SPDXID !== "SPDXRef-REPO");

  return (
    <div className="p-6 space-y-6">

      {/* En-tête */}
      <div>
        <h1 className="text-xl font-bold text-gray-900">SBOM — Software Bill of Materials</h1>
        <p className="text-sm text-gray-500 mt-1">
          Inventaire formel des composants logiciels. Requis NIS2 / ANSSI pour la traçabilité des dépendances.
        </p>
      </div>

      {/* Configuration */}
      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-5">
        <h2 className="text-sm font-semibold text-gray-800">Configuration de l'export</h2>

        {/* Choix du format */}
        <div>
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-3">Format</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {FORMATS.map((f) => (
              <FormatCard
                key={f.id}
                fmt={f}
                selected={format === f.id}
                onSelect={setFormat}
              />
            ))}
          </div>
        </div>

        {/* Filtre distribution */}
        <div className="flex items-center gap-4 flex-wrap">
          <div>
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1.5">Distribution</p>
            <select
              value={distribution}
              onChange={(e) => setDistrib(e.target.value)}
              className="border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none
                         focus:ring-2 focus:ring-blue-500 bg-white min-w-[180px]"
            >
              <option value="">Toutes les distributions</option>
              {distributions.map((d) => (
                <option key={d} value={d}>{d}</option>
              ))}
            </select>
          </div>

          {/* Compteur */}
          <div className="mt-5">
            {preview && (
              <div className="flex items-center gap-2 bg-blue-50 border border-blue-200 rounded-lg px-4 py-2">
                <span className="text-2xl font-bold text-blue-700">
                  {preview.total_packages ?? 0}
                </span>
                <span className="text-sm text-blue-600">paquets dans le SBOM</span>
              </div>
            )}
          </div>
        </div>

        {/* Bouton export principal */}
        <div className="pt-2 border-t border-gray-100 flex items-center gap-3">
          <button
            onClick={handleExport}
            disabled={exporting || !preview?.total_packages}
            className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700
                       disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm
                       font-semibold rounded-lg transition-colors"
          >
            {exporting ? (
              <>
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                </svg>
                Génération…
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                </svg>
                Exporter le SBOM complet
              </>
            )}
          </button>
          <p className="text-xs text-gray-400">
            Fichier JSON · format {format === "cyclonedx" ? "CycloneDX v1.5" : "SPDX v2.3"}
            {distribution ? ` · ${distribution}` : " · toutes distributions"}
          </p>
        </div>
      </div>

      {/* Aperçu des composants */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-gray-800">Aperçu — 5 premiers composants</h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Extrait du SBOM tel qu'il sera exporté
            </p>
          </div>
          {previewLoading && (
            <svg className="animate-spin w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
            </svg>
          )}
        </div>

        {components.length === 0 && !previewLoading ? (
          <div className="py-10 text-center text-sm text-gray-400">
            Aucun paquet trouvé pour cette sélection.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-50 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  <th className="px-5 py-3 text-left">Paquet</th>
                  <th className="px-5 py-3 text-left">Version</th>
                  <th className="px-5 py-3 text-left">PURL / Identifiant</th>
                  <th className="px-5 py-3 text-left">SHA-256</th>
                  <th className="px-5 py-3 text-right">Export individuel</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {components.map((c, i) => {
                  const isCdx  = format === "cyclonedx";
                  const name   = isCdx ? c.name : c.name;
                  const ver    = isCdx ? c.version : c.versionInfo;
                  const purl   = isCdx
                    ? c.purl
                    : c.externalRefs?.find((r) => r.referenceType === "purl")?.referenceLocator;
                  const sha256 = isCdx
                    ? c.hashes?.find((h) => h.alg === "SHA-256")?.content
                    : c.checksums?.find((h) => h.algorithm === "SHA256")?.checksumValue;

                  // Extraire arch depuis les propriétés CycloneDX
                  const arch = isCdx
                    ? (c.properties?.find((p) => p.name === "arch")?.value ?? "x86_64")
                    : "x86_64";

                  return (
                    <tr key={i} className="hover:bg-gray-50 transition-colors">
                      <td className="px-5 py-3 font-medium text-gray-800">{name}</td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-600">{ver}</td>
                      <td className="px-5 py-3 font-mono text-xs text-blue-600 max-w-xs truncate" title={purl}>
                        {purl ?? "—"}
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-400 max-w-[120px] truncate" title={sha256}>
                        {sha256 ? sha256.slice(0, 12) + "…" : "—"}
                      </td>
                      <td className="px-5 py-3 text-right">
                        <button
                          onClick={() => handlePackageExport(name, ver, arch)}
                          className="inline-flex items-center gap-1 px-3 py-1 text-xs font-medium
                                     border border-gray-200 rounded-lg hover:bg-gray-50
                                     text-gray-600 transition-colors"
                        >
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                              d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                          </svg>
                          .json
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {preview?.total_packages > 5 && (
          <div className="px-5 py-3 border-t border-gray-100 bg-gray-50 text-xs text-gray-400">
            Aperçu limité à 5 composants sur {preview.total_packages} —
            cliquez sur « Exporter » pour obtenir le fichier complet.
          </div>
        )}
      </div>

      {/* Infos réglementaires */}
      <div className="bg-amber-50 border border-amber-200 rounded-xl p-5">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-amber-600 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="3" x2="12" y2="21"/><path d="M17 6H9.5a3.5 3.5 0 000 7H17"/><path d="M7 18h9.5a3.5 3.5 0 000-7H7"/></svg>
          <div className="space-y-2 text-sm">
            <p className="font-semibold text-amber-800">Contexte réglementaire</p>
            <ul className="text-amber-700 space-y-1 text-xs list-disc list-inside">
              <li>
                <strong>NIS2 (EU 2022/2555)</strong> — La directive impose la traçabilité des
                composants logiciels dans les entités essentielles et importantes.
              </li>
              <li>
                <strong>ANSSI — Guide SecNumCloud</strong> — Le SBOM est recommandé pour
                justifier l'inventaire logiciel lors des audits.
              </li>
              <li>
                <strong>Executive Order US 14028</strong> — Exige un SBOM pour tout logiciel
                vendu au gouvernement américain.
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
