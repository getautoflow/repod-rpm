import { useState, useEffect, useRef, useCallback } from "react";
import { Outlet, NavLink, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getMeInfo, mfaSetup, mfaConfirm, mfaDisable } from "../api";

// ─── Icônes SVG professionnelles ─────────────────────────────────────────────

const Icon = {
  Dashboard: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1"/>
      <rect x="14" y="3" width="7" height="7" rx="1"/>
      <rect x="3" y="14" width="7" height="7" rx="1"/>
      <rect x="14" y="14" width="7" height="7" rx="1"/>
    </svg>
  ),
  Package: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/>
      <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
      <line x1="12" y1="22.08" x2="12" y2="12"/>
    </svg>
  ),
  Upload: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
      <polyline points="17 8 12 3 7 8"/>
      <line x1="12" y1="3" x2="12" y2="15"/>
    </svg>
  ),
  Import: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
      <polyline points="7 10 12 15 17 10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  ),
  Distribution: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <ellipse cx="12" cy="5" rx="9" ry="3"/>
      <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
      <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
    </svg>
  ),
  Shield: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  Terminal: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5"/>
      <line x1="12" y1="19" x2="20" y2="19"/>
    </svg>
  ),
  Audit: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2"/>
      <rect x="9" y="3" width="6" height="4" rx="1"/>
      <line x1="9" y1="12" x2="15" y2="12"/>
      <line x1="9" y1="16" x2="13" y2="16"/>
    </svg>
  ),
  Users: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
      <circle cx="9" cy="7" r="4"/>
      <path d="M23 21v-2a4 4 0 00-3-3.87"/>
      <path d="M16 3.13a4 4 0 010 7.75"/>
    </svg>
  ),
  Settings: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
    </svg>
  ),
  Logout: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/>
      <polyline points="16 17 21 12 16 7"/>
      <line x1="21" y1="12" x2="9" y2="12"/>
    </svg>
  ),
  Bell: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>
      <path d="M13.73 21a2 2 0 01-3.46 0"/>
    </svg>
  ),
  ChevronRight: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6"/>
    </svg>
  ),
  Download: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
      <polyline points="7 10 12 15 17 10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  ),
  Health: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
    </svg>
  ),
  Sbom: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="16" y1="13" x2="8" y2="13"/>
      <line x1="16" y1="17" x2="8" y2="17"/>
      <polyline points="10 9 9 9 8 9"/>
    </svg>
  ),
  HelpCircle: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  ),
  ExternalLink: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/>
      <polyline points="15 3 21 3 21 9"/>
      <line x1="10" y1="14" x2="21" y2="3"/>
    </svg>
  ),
  BookOpen: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 3h6a4 4 0 014 4v14a3 3 0 00-3-3H2z"/>
      <path d="M22 3h-6a4 4 0 00-4 4v14a3 3 0 013-3h7z"/>
    </svg>
  ),
  Zap: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
    </svg>
  ),
  FileText: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="16" y1="13" x2="8" y2="13"/>
      <line x1="16" y1="17" x2="8" y2="17"/>
      <polyline points="10 9 9 9 8 9"/>
    </svg>
  ),
  MessageCircle: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
    </svg>
  ),
  Sso: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
    </svg>
  ),
};

// ─── Menu Help ────────────────────────────────────────────────────────────────
const DOC_BASE = "https://docs.repod.getautoflow.dev";

const HELP_LINKS = [
  {
    section: "Documentation",
    items: [
      { label: "Démarrage rapide",   href: `${DOC_BASE}/getting-started/`,           icon: "Zap" },
      { label: "Guide d'administration", href: `${DOC_BASE}/fr/ADMINISTRATION/`,     icon: "BookOpen" },
      { label: "Référence API",      href: `${DOC_BASE}/fr/API_REFERENCE/`,          icon: "FileText" },
      { label: "Rotation des clés GPG", href: `${DOC_BASE}/how-to/rotate-gpg-keys/`, icon: "ExternalLink" },
    ],
  },
  {
    section: "Ressources",
    items: [
      { label: "Changelog",          href: `${DOC_BASE}/changelog/`,                 icon: "FileText" },
      { label: "Contacter le support", href: "mailto:support@getautoflow.dev",       icon: "MessageCircle" },
    ],
  },
];

function HelpMenu() {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className={`relative w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${
          open ? "bg-slate-100 text-slate-700" : "text-slate-400 hover:bg-slate-100 hover:text-slate-600"
        }`}
        aria-label="Aide"
        title="Aide"
      >
        <span className="w-4 h-4"><Icon.HelpCircle /></span>
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-72 bg-white rounded-xl shadow-xl border border-slate-200 z-50 overflow-hidden">
          {/* En-tête */}
          <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
            <p className="text-xs font-bold text-slate-500 uppercase tracking-widest">Centre d'aide</p>
            <p className="text-[11px] text-slate-400 mt-0.5">Repod — Enterprise Edition</p>
          </div>

          {/* Sections */}
          {HELP_LINKS.map((section, si) => (
            <div key={si}>
              {si > 0 && <div className="h-px bg-slate-100 mx-4" />}
              <div className="py-1.5">
                <p className="px-4 py-1 text-[10px] font-bold tracking-widest uppercase text-slate-400">
                  {section.section}
                </p>
                {section.items.map((item, ii) => {
                  const ItemIcon = Icon[item.icon];
                  return (
                    <a
                      key={ii}
                      href={item.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={() => setOpen(false)}
                      className="flex items-center gap-3 px-4 py-2 text-sm text-slate-600 hover:bg-slate-50 hover:text-slate-900 transition-colors"
                    >
                      <span className="w-3.5 h-3.5 text-slate-400 shrink-0">
                        {ItemIcon && <ItemIcon />}
                      </span>
                      <span className="flex-1">{item.label}</span>
                      <span className="w-3 h-3 text-slate-300 shrink-0"><Icon.ExternalLink /></span>
                    </a>
                  );
                })}
              </div>
            </div>
          ))}

          {/* Footer version */}
          <div className="px-4 py-2.5 bg-slate-50 border-t border-slate-100">
            <p className="text-[10px] text-slate-400 text-center">
              Repod Enterprise — <span className="font-mono">v1.0.1</span>
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Libellés des pages pour le topbar ───────────────────────────────────────
const PAGE_TITLES = {
  "/":             { label: "Tableau de bord",  icon: "Dashboard" },
  "/packages":     { label: "Paquets",           icon: "Package" },
  "/upload":       { label: "Upload",            icon: "Upload" },
  "/import":       { label: "Importer",          icon: "Import" },
  "/distributions":{ label: "Distributions",     icon: "Distribution" },
  "/security":     { label: "Sécurité",          icon: "Shield" },
  "/audit":        { label: "Audit",             icon: "Audit" },
  "/setup":        { label: "Config client",     icon: "Terminal" },
  "/users":        { label: "Utilisateurs",      icon: "Users" },
  "/settings":     { label: "Paramètres",        icon: "Settings" },
  "/downloads":    { label: "Téléchargements",   icon: "Download" },
  "/health":       { label: "Supervision",       icon: "Health"   },
  "/sbom":         { label: "SBOM",              icon: "Sbom"     },
  "/sso":          { label: "SSO / OIDC",        icon: "Sso"      },
};

// ─── Item de navigation ───────────────────────────────────────────────────────
function NavItem({ to, end, icon, label, badge }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `group relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
          isActive
            ? "bg-navy-700 text-white shadow-sm"
            : "text-slate-400 hover:bg-navy-800 hover:text-slate-200"
        }`
      }
    >
      {({ isActive }) => (
        <>
          {/* Accent bar gauche */}
          {isActive && (
            <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-brand rounded-full" />
          )}
          <span className={`w-4 h-4 shrink-0 ${isActive ? "text-brand-light" : "text-slate-500 group-hover:text-slate-300"} transition-colors`}>
            {icon}
          </span>
          <span className="flex-1 leading-none">{label}</span>
          {badge > 0 && (
            <span className="ml-auto flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-bold">
              {badge > 99 ? "99+" : badge}
            </span>
          )}
        </>
      )}
    </NavLink>
  );
}

// ─── Séparateur de section ─────────────────────────────────────────────────
function NavSection({ label }) {
  return (
    <p className="px-3 pt-5 pb-1.5 text-[10px] font-bold tracking-widest uppercase text-navy-500 select-none">
      {label}
    </p>
  );
}

// ─── Modal "Mon compte" ───────────────────────────────────────────────────────
function MonCompteModal({ onClose }) {
  const [me, setMe]         = useState(null);
  const [loading, setLoading] = useState(true);

  // États MFA — garde l'approche RPM (code TOTP pour désactiver, pas mot de passe)
  const [mfaStep,   setMfaStep]   = useState("idle"); // idle|qr|confirm|disabling|ok_enable|ok_disable
  const [qrData,    setQrData]    = useState(null);
  const [code,      setCode]      = useState("");
  const [err,       setErr]       = useState("");
  const [busy,      setBusy]      = useState(false);

  const loadMe = useCallback(async () => {
    setLoading(true);
    try { setMe(await getMeInfo()); }
    catch { /* silencieux */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { loadMe(); }, [loadMe]);

  const handleSetup = async () => {
    setBusy(true); setErr("");
    try { const data = await mfaSetup(); setQrData(data); setMfaStep("qr"); }
    catch { setErr("Erreur lors de la génération du QR code."); }
    finally { setBusy(false); }
  };

  const handleConfirm = async (e) => {
    e.preventDefault();
    if (code.length !== 6) { setErr("Code à 6 chiffres requis."); return; }
    setBusy(true); setErr("");
    try {
      await mfaConfirm(code);
      setMfaStep("ok_enable"); loadMe();
    } catch (ex) { setErr(ex?.response?.data?.detail || "Code invalide."); }
    finally { setBusy(false); setCode(""); }
  };

  const handleDisable = async (e) => {
    e.preventDefault();
    if (code.length !== 6) { setErr("Code à 6 chiffres requis."); return; }
    setBusy(true); setErr("");
    try {
      await mfaDisable(code);
      setMfaStep("ok_disable"); loadMe();
    } catch (ex) { setErr(ex?.response?.data?.detail || "Code invalide."); }
    finally { setBusy(false); setCode(""); }
  };

  const CodeInput = ({ ringColor = "blue" }) => (
    <input
      type="text" inputMode="numeric" maxLength={6} value={code} autoFocus autoComplete="one-time-code"
      onChange={(e) => { setCode(e.target.value.replace(/\D/g, "").slice(0, 6)); setErr(""); }}
      className={`w-full border rounded-lg px-3 py-2.5 text-center font-mono text-xl tracking-[0.4em]
        focus:outline-none focus:ring-2 focus:ring-${ringColor}-500 focus:border-transparent
        ${err ? "border-red-400 bg-red-50" : "border-gray-300"}`}
      placeholder="000000"
    />
  );

  const roleColors = {
    admin: "bg-red-100 text-red-700", maintainer: "bg-purple-100 text-purple-700",
    uploader: "bg-blue-100 text-blue-700", auditor: "bg-yellow-100 text-yellow-700",
    reader: "bg-gray-100 text-gray-600",
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/50" />
      <div className="relative w-full max-w-md bg-white rounded-2xl shadow-2xl overflow-hidden"
           onClick={(e) => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <h2 className="text-base font-bold text-gray-900">Mon compte</h2>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-gray-100 text-gray-400 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>

        <div className="px-6 py-5 space-y-5">
          {loading ? (
            <div className="flex justify-center py-8">
              <svg className="animate-spin w-6 h-6 text-blue-500" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
              </svg>
            </div>
          ) : (
            <>
              {/* ── Infos utilisateur ─────────────────────────────────────── */}
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-full bg-blue-100 flex items-center justify-center shrink-0">
                  <span className="text-xl font-bold text-blue-700 uppercase">
                    {(me?.username || "?")[0]}
                  </span>
                </div>
                <div className="min-w-0">
                  <p className="font-semibold text-gray-900">{me?.username}</p>
                  <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${roleColors[me?.role] || "bg-gray-100 text-gray-600"}`}>
                      {me?.role}
                    </span>
                    {me?.auth_source && me.auth_source !== "local" && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-100 text-indigo-700 font-semibold">
                        {me.auth_source.toUpperCase()}
                      </span>
                    )}
                  </div>
                  {me?.email && <p className="text-xs text-gray-500 mt-0.5">{me.email}</p>}
                  {me?.full_name && <p className="text-xs text-gray-400">{me.full_name}</p>}
                </div>
              </div>

              {/* ── Section MFA ───────────────────────────────────────────── */}
              <div className="border border-gray-200 rounded-xl overflow-hidden">
                <div className="px-4 py-3 bg-gray-50 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <svg className="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round"
                        d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                    </svg>
                    <span className="text-sm font-semibold text-gray-800">Double authentification (MFA)</span>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${
                    me?.mfa_enabled ? "bg-green-100 text-green-700" : "bg-gray-100 text-gray-500"
                  }`}>
                    {me?.mfa_enabled ? "Activé" : "Désactivé"}
                  </span>
                </div>

                <div className="px-4 py-4 space-y-4">
                  {/* Idle */}
                  {mfaStep === "idle" && (
                    <>
                      <p className="text-xs text-gray-500">
                        {me?.mfa_enabled
                          ? "Un code TOTP est demandé à chaque connexion. Compatible Google Authenticator, Authy, Bitwarden…"
                          : "Ajoutez une deuxième couche de sécurité — un code de votre application mobile sera requis à chaque connexion."}
                      </p>
                      {me?.mfa_enabled ? (
                        <button onClick={() => { setMfaStep("disabling"); setErr(""); setCode(""); }}
                          className="w-full px-4 py-2 border border-red-200 text-red-600 rounded-lg text-sm font-medium hover:bg-red-50 transition-colors">
                          Désactiver le MFA
                        </button>
                      ) : (
                        <button onClick={handleSetup} disabled={busy}
                          className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
                          {busy ? "Initialisation…" : "Activer le MFA"}
                        </button>
                      )}
                    </>
                  )}

                  {/* QR code */}
                  {mfaStep === "qr" && qrData && (
                    <div className="space-y-4">
                      <p className="text-xs text-gray-600">
                        Scannez ce QR code avec <strong>Google Authenticator</strong>, <strong>Authy</strong> ou <strong>Bitwarden</strong>.
                      </p>
                      <div className="flex justify-center">
                        <img src={qrData.qr_code} alt="QR code TOTP"
                          className="w-40 h-40 rounded-xl border border-gray-200 shadow-sm" />
                      </div>
                      <details className="text-xs text-gray-400">
                        <summary className="cursor-pointer hover:text-gray-600">Entrer le code manuellement</summary>
                        <p className="mt-1 font-mono break-all bg-gray-50 rounded p-2 select-all">{qrData.secret}</p>
                      </details>
                      <button onClick={() => { setMfaStep("confirm"); setCode(""); setErr(""); }}
                        className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors">
                        J'ai scanné le QR code →
                      </button>
                      <button onClick={() => { setMfaStep("idle"); setQrData(null); }}
                        className="w-full text-xs text-gray-400 hover:text-gray-600">Annuler</button>
                    </div>
                  )}

                  {/* Confirmation code */}
                  {mfaStep === "confirm" && (
                    <form onSubmit={handleConfirm} className="space-y-3">
                      <p className="text-xs text-gray-600">
                        Saisissez le code affiché dans votre application pour confirmer l'activation.
                      </p>
                      <CodeInput ringColor="blue" />
                      {err && <p className="text-xs text-red-600">{err}</p>}
                      <button type="submit" disabled={busy || code.length !== 6}
                        className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
                        {busy ? "Activation…" : "Confirmer et activer"}
                      </button>
                      <button type="button" onClick={() => setMfaStep("qr")}
                        className="w-full text-xs text-gray-400 hover:text-gray-600">← Retour au QR code</button>
                    </form>
                  )}

                  {/* Désactivation — code TOTP */}
                  {mfaStep === "disabling" && (
                    <form onSubmit={handleDisable} className="space-y-3">
                      <div className="bg-orange-50 border border-orange-200 rounded-xl p-3 text-xs text-orange-700">
                        <strong>Confirmation requise.</strong> Entrez votre code TOTP actuel pour désactiver le MFA.
                      </div>
                      <CodeInput ringColor="red" />
                      {err && <p className="text-xs text-red-600">{err}</p>}
                      <button type="submit" disabled={busy || code.length !== 6}
                        className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
                        {busy ? "Désactivation…" : "Désactiver le MFA"}
                      </button>
                      <button type="button" onClick={() => { setMfaStep("idle"); setCode(""); setErr(""); }}
                        className="w-full text-xs text-gray-400 hover:text-gray-600">Annuler</button>
                    </form>
                  )}

                  {/* Succès MFA activé */}
                  {mfaStep === "ok_enable" && (
                    <div className="text-center space-y-3 py-1">
                      <div className="inline-flex items-center justify-center w-10 h-10 bg-green-100 rounded-full">
                        <svg className="w-5 h-5 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7"/>
                        </svg>
                      </div>
                      <p className="text-sm font-semibold text-gray-900">MFA activé !</p>
                      <p className="text-xs text-gray-500">Votre compte est maintenant protégé par la double authentification TOTP.</p>
                      <button onClick={() => setMfaStep("idle")} className="text-sm text-blue-600 hover:underline">OK</button>
                    </div>
                  )}

                  {/* Succès MFA désactivé */}
                  {mfaStep === "ok_disable" && (
                    <div className="text-center space-y-3 py-1">
                      <div className="inline-flex items-center justify-center w-10 h-10 bg-gray-100 rounded-full">
                        <svg className="w-5 h-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                            d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"/>
                        </svg>
                      </div>
                      <p className="text-sm font-semibold text-gray-900">MFA désactivé</p>
                      <p className="text-xs text-gray-500">La double authentification a été retirée de votre compte.</p>
                      <button onClick={() => setMfaStep("idle")} className="text-sm text-blue-600 hover:underline">OK</button>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Layout principal ─────────────────────────────────────────────────────────
export default function DashboardLayout() {
  const { signOut, user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [showMonCompte, setShowMonCompte] = useState(false);

  const handleLogout = () => { signOut(); navigate("/login"); };

  const currentPage = PAGE_TITLES[location.pathname] || { label: "repod", icon: "Dashboard" };
  const CurrentPageIcon = Icon[currentPage.icon];

  return (
    <div className="flex h-screen bg-slate-100 font-sans overflow-hidden">
      {/* ── Sidebar ── */}
      <aside className="w-56 bg-navy-900 flex flex-col shrink-0 shadow-2xl z-20">

        {/* Logo / Brand */}
        <div className="flex items-center gap-3 px-4 py-4 border-b border-navy-800">
          <img src="/logo.png" alt="Repod" className="w-9 h-9 object-contain shrink-0" />
          <div className="min-w-0">
            <p className="text-white font-black text-base tracking-wider uppercase leading-none">Repod</p>
            <p className="text-navy-500 text-[10px] mt-0.5 font-medium">RPM Repository</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-2 py-3 overflow-y-auto space-y-px">
          <NavItem to="/" end icon={<Icon.Dashboard />} label="Tableau de bord" />

          <NavSection label="Dépôt" />
          <NavItem to="/packages"      icon={<Icon.Package />}      label="Paquets" />
          <NavItem to="/upload"        icon={<Icon.Upload />}        label="Upload" />
          <NavItem to="/import"        icon={<Icon.Import />}        label="Importer" />
          <NavItem to="/distributions" icon={<Icon.Distribution />}  label="Distributions" />
          <NavItem to="/security"      icon={<Icon.Shield />}        label="Sécurité" />
          <NavItem to="/audit"         icon={<Icon.Audit />}         label="Audit" />

          <NavSection label="Clients" />
          <NavItem to="/setup" icon={<Icon.Terminal />} label="Config client" />

          <NavSection label="Administration" />
          <NavItem to="/downloads" icon={<Icon.Download />} label="Téléchargements" />
          <NavItem to="/sbom"      icon={<Icon.Sbom />}     label="SBOM" />
          <NavItem to="/health"    icon={<Icon.Health />}   label="Supervision" />
          <NavItem to="/users"     icon={<Icon.Users />}    label="Utilisateurs" />
          <NavItem to="/settings"  icon={<Icon.Settings />} label="Paramètres" />
          <NavItem to="/sso"       icon={<Icon.Sso />}      label="SSO / OIDC" />
        </nav>

        {/* Footer utilisateur */}
        <div className="px-2 py-3 border-t border-navy-800 space-y-1">
          <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg">
            <div className="w-7 h-7 rounded-full bg-navy-700 border border-navy-600 flex items-center justify-center shrink-0">
              <span className="text-xs font-bold text-slate-300 uppercase">
                {(user?.username || user?.sub || "A")[0]}
              </span>
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-slate-200 text-xs font-semibold truncate">{user?.username || user?.sub || "admin"}</p>
              <p className="text-navy-500 text-[10px]">{user?.role || "admin"}</p>
            </div>
          </div>
          {/* Bouton Mon compte */}
          <button
            onClick={() => setShowMonCompte(true)}
            className="flex items-center gap-2.5 w-full px-3 py-2 rounded-lg text-xs font-medium text-slate-500 hover:bg-navy-800 hover:text-slate-300 transition-colors"
          >
            <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
              <path d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
            </svg>
            Mon compte
          </button>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2.5 w-full px-3 py-2 rounded-lg text-xs font-medium text-slate-500 hover:bg-red-900/30 hover:text-red-400 transition-colors"
          >
            <span className="w-4 h-4"><Icon.Logout /></span>
            Déconnexion
          </button>
        </div>
      </aside>

      {/* ── Main area ── */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* Top bar */}
        <header className="h-12 bg-white border-b border-slate-200 flex items-center justify-between px-6 shrink-0 z-10 shadow-sm">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-400 w-4 h-4">
              {CurrentPageIcon && <CurrentPageIcon />}
            </span>
            <span className="font-semibold text-slate-700">{currentPage.label}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-400 font-mono">
              {new Date().toLocaleString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" })}
            </span>
            <button className="relative w-8 h-8 rounded-lg flex items-center justify-center text-slate-400 hover:bg-slate-100 transition-colors">
              <span className="w-4 h-4"><Icon.Bell /></span>
            </button>
            <HelpMenu />
            <div className="w-px h-5 bg-slate-200" />
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              Connecté
            </div>
          </div>
        </header>

        {/* Page content — fond dark géré par chaque page */}
        <main className="flex-1 overflow-y-auto bg-slate-50">
          <Outlet />
        </main>
      </div>

      {/* Modal Mon compte */}
      {showMonCompte && <MonCompteModal onClose={() => setShowMonCompte(false)} />}
    </div>
  );
}
