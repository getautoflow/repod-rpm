import { useState, useEffect, useCallback } from "react";
import { Responsive, WidthProvider } from "react-grid-layout";
import { getDashboardStats, getDashboardHistory } from "../api";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer,
} from "recharts";

const ResponsiveGridLayout = WidthProvider(Responsive);

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmtBytes = b => {
  if (!b) return "0 B";
  if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b/1048576).toFixed(1)} MB`;
  return `${(b/1073741824).toFixed(2)} GB`;
};
const fmtTs = iso => iso
  ? new Date(iso).toLocaleString("fr-FR", { day:"2-digit", month:"2-digit", hour:"2-digit", minute:"2-digit" })
  : "—";

// ─── Layout par défaut ────────────────────────────────────────────────────────
const STORAGE_KEY = "repod_dashboard_layout_v6";
const DEFAULT_LAYOUTS = {
  lg: [
    { i:"stat-packages",   x:0,  y:0,  w:3, h:3, minW:2, minH:2 },
    { i:"stat-imports",    x:3,  y:0,  w:3, h:3, minW:2, minH:2 },
    { i:"stat-security",   x:6,  y:0,  w:3, h:3, minW:2, minH:2 },
    { i:"stat-alerts",     x:9,  y:0,  w:3, h:3, minW:2, minH:2 },
    { i:"cve-posture",     x:0,  y:3,  w:4, h:9, minW:3, minH:6 },
    { i:"security-review", x:4,  y:3,  w:4, h:9, minW:3, minH:6 },
    { i:"clamav",          x:8,  y:3,  w:4, h:9, minW:3, minH:6 },
    { i:"history-imports", x:0,  y:12, w:8, h:10, minW:4, minH:8 },
    { i:"history-decisions",x:8, y:12, w:4, h:10, minW:3, minH:8 },
    { i:"activity",        x:0,  y:22, w:6, h:9, minW:4, minH:7 },
    { i:"alerts",          x:6,  y:22, w:6, h:9, minW:3, minH:6 },
    { i:"imports",         x:0,  y:31, w:12, h:9, minW:6, minH:6 },
  ],
};

// ─── Palette claire ────────────────────────────────────────────────────────────
const T = {
  bg:      "#F8FAFC",
  panel:   "#FFFFFF",
  border:  "#E2E8F0",
  text:    "#0F172A",
  sub:     "#475569",
  muted:   "#94A3B8",
  blue:    "#3B82F6",
  green:   "#22C55E",
  yellow:  "#F59E0B",
  orange:  "#F97316",
  red:     "#EF4444",
  purple:  "#8B5CF6",
  teal:    "#14B8A6",
  indigo:  "#6366F1",
};

const SEV = [
  { key:"critical",   label:"CRITICAL", color:T.red,    bg:"#FEF2F2" },
  { key:"high",       label:"HIGH",     color:T.orange, bg:"#FFF7ED" },
  { key:"medium",     label:"MEDIUM",   color:T.yellow, bg:"#FFFBEB" },
  { key:"low",        label:"LOW",      color:T.green,  bg:"#F0FDF4" },
  { key:"negligible", label:"NEG.",     color:T.muted,  bg:"#F8FAFC" },
];

const STATUS_META = {
  pending_review:   { label:"En révision",   color:T.orange },
  blocked:          { label:"Bloqués",        color:T.red },
  quarantined:      { label:"Quarantaine",    color:T.purple },
  accepted_risk:    { label:"Risque accepté", color:T.green },
  exception:        { label:"Exception",      color:T.blue },
  upgrade_required: { label:"Upgrade requis", color:T.teal },
};

// ─── Wrapper Panel ────────────────────────────────────────────────────────────
function Panel({ title, children, onHeaderClick, badge, icon }) {
  return (
    <div style={{
      background: T.panel,
      border: `1px solid ${T.border}`,
      borderRadius: "12px",
      height: "100%",
      display: "flex",
      flexDirection: "column",
      overflow: "hidden",
      boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
    }}>
      {/* Header */}
      <div className="drag-handle" style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "12px 16px 10px",
        borderBottom: `1px solid ${T.border}`,
        cursor: "grab",
        flexShrink: 0,
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:"8px" }}>
          {icon && <span style={{ color: T.muted, display:"flex" }}>{icon}</span>}
          <span style={{ fontSize:"11px", fontWeight:700, letterSpacing:"0.06em", textTransform:"uppercase", color: T.sub }}>
            {title}
          </span>
          {badge != null && badge > 0 && (
            <span style={{
              fontSize:"10px", fontWeight:700,
              padding:"1px 6px", borderRadius:"99px",
              background: T.red+"15", color: T.red,
              border: `1px solid ${T.red}30`,
            }}>{badge}</span>
          )}
        </div>
        {onHeaderClick && (
          <button onClick={onHeaderClick} style={{
            fontSize:"11px", fontWeight:600, color: T.blue,
            background:"none", border:"none", cursor:"pointer", padding:0,
          }}>
            Voir →
          </button>
        )}
      </div>
      {/* Body */}
      <div style={{ flex:1, overflow:"hidden", padding:"14px 16px", minHeight:0 }}>
        {children}
      </div>
    </div>
  );
}

// ─── Stat panel ───────────────────────────────────────────────────────────────
function StatPanel({ label, value, sub, color, iconPath, onClick }) {
  return (
    <div
      onClick={onClick}
      style={{
        background: T.panel,
        border: `1px solid ${T.border}`,
        borderRadius: "12px",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        padding: "16px",
        boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
        cursor: onClick ? "pointer" : "default",
        transition: "box-shadow .15s",
      }}
      onMouseEnter={e => { if (onClick) e.currentTarget.style.boxShadow="0 4px 12px rgba(0,0,0,0.10)"; }}
      onMouseLeave={e => { if (onClick) e.currentTarget.style.boxShadow="0 1px 3px rgba(0,0,0,0.06)"; }}
    >
      <div className="drag-handle" style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", cursor:"grab" }}>
        <span style={{ fontSize:"11px", fontWeight:700, letterSpacing:"0.06em", textTransform:"uppercase", color: T.sub }}>
          {label}
        </span>
        <div style={{
          width:32, height:32, borderRadius:8,
          background: color+"15",
          display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0,
        }}>
          <svg viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth={1.8}
            strokeLinecap="round" strokeLinejoin="round" style={{width:16,height:16}}>
            <path d={iconPath}/>
          </svg>
        </div>
      </div>
      <div>
        <div style={{ fontSize:"34px", fontWeight:800, color, lineHeight:1, fontVariantNumeric:"tabular-nums" }}>
          {value}
        </div>
        {sub && <p style={{ fontSize:"11px", color: T.muted, marginTop:4 }}>{sub}</p>}
      </div>
    </div>
  );
}

// ─── CVE Posture ──────────────────────────────────────────────────────────────
function CvePosture({ posture }) {
  if (!posture || posture.scanned === 0) return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100%", color: T.muted, fontSize:12 }}>
      Aucun paquet scanné
    </div>
  );
  const total = SEV.reduce((s,{key})=>s+(posture[key]||0),0);
  const max = Math.max(...SEV.map(({key})=>posture[key]||0),1);
  return (
    <div style={{ height:"100%", display:"flex", flexDirection:"column", gap:8 }}>
      <div style={{ display:"flex", alignItems:"baseline", gap:8 }}>
        <span style={{ fontSize:28, fontWeight:800, color: total>0?T.red:T.green, fontVariantNumeric:"tabular-nums" }}>{total}</span>
        <span style={{ fontSize:11, color:T.muted }}>CVE · {posture.scanned}/{posture.total} analysés</span>
      </div>
      <div style={{ flex:1, display:"flex", flexDirection:"column", justifyContent:"space-around" }}>
        {SEV.map(({key,label,color,bg})=>{
          const n = posture[key]||0;
          const pct = n>0 ? Math.max((n/max)*100,4) : 0;
          return (
            <div key={key} style={{ display:"flex", alignItems:"center", gap:8 }}>
              <span style={{ fontSize:"10px", fontWeight:700, width:40, textAlign:"right", color, flexShrink:0 }}>{label}</span>
              <div style={{ flex:1, height:8, borderRadius:99, background:"#F1F5F9", overflow:"hidden" }}>
                <div style={{ height:"100%", borderRadius:99, width:`${pct}%`, background:color, transition:"width .5s ease" }}/>
              </div>
              <span style={{ fontSize:12, fontWeight:700, width:24, textAlign:"right", color:n>0?color:T.border, fontVariantNumeric:"tabular-nums" }}>{n}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Security Review ──────────────────────────────────────────────────────────
function SecurityReview({ review, navigate }) {
  if (!review) return null;
  const counts = Object.entries(STATUS_META)
    .map(([key,meta])=>({key,meta,count:review[key]||0}))
    .filter(({count})=>count>0);
  const expiring = review.expiring_soon||[];

  if (!counts.length && !expiring.length) return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:"100%", gap:8, color:T.green }}>
      <svg viewBox="0 0 24 24" fill="none" stroke={T.green} strokeWidth={1.5} style={{width:32,height:32,opacity:.7}}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
      </svg>
      <span style={{fontSize:12}}>Aucune action requise</span>
    </div>
  );

  return (
    <div style={{ height:"100%", display:"flex", flexDirection:"column", gap:10 }}>
      <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
        {counts.map(({key,meta,count})=>(
          <div key={key} style={{
            display:"flex", alignItems:"center", gap:6,
            padding:"6px 10px", borderRadius:8,
            background: meta.color+"10", border:`1px solid ${meta.color}25`,
          }}>
            <span style={{ width:6, height:6, borderRadius:"50%", background:meta.color, flexShrink:0 }}/>
            <span style={{ fontSize:13, fontWeight:800, color:meta.color, fontVariantNumeric:"tabular-nums" }}>{count}</span>
            <span style={{ fontSize:11, color:T.sub }}>{meta.label}</span>
          </div>
        ))}
      </div>
      {expiring.length>0 && (
        <div style={{ borderTop:`1px solid ${T.border}`, paddingTop:10 }}>
          <p style={{ fontSize:"10px", fontWeight:700, color:T.orange, marginBottom:6, letterSpacing:"0.05em", textTransform:"uppercase", display:"flex", alignItems:"center", gap:4 }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{width:12,height:12}}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Expirantes
          </p>
          {expiring.slice(0,4).map((item,i)=>(
            <div key={i} style={{
              display:"flex", justifyContent:"space-between", alignItems:"center",
              padding:"5px 8px", borderRadius:6, marginBottom:4,
              background: item.expired?"#FEF2F2":"#FFF7ED",
              border:`1px solid ${item.expired?T.red+"20":T.orange+"20"}`,
              fontSize:11,
            }}>
              <span style={{ fontFamily:"monospace", fontWeight:600, color:T.text }}>{item.package}</span>
              <span style={{ fontWeight:700, color:item.expired?T.red:T.orange }}>
                {item.expired?"Expirée":(`J-${item.remaining_days}`)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── ClamAV ───────────────────────────────────────────────────────────────────
function ClamavPanel({ clamav }) {
  if (!clamav) return null;
  const ok = clamav.available && clamav.daemon_running;
  const statusColor = ok ? T.green : clamav.available ? T.yellow : T.red;
  const statusLabel = ok ? "ACTIF" : clamav.available ? "Sans daemon" : "INACTIF";
  const pct = ok ? 100 : clamav.available ? 60 : 15;
  const r = 42, circ = 2*Math.PI*r;

  return (
    <div style={{ height:"100%", display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", gap:12 }}>
      <div style={{ position:"relative", width:110, height:110 }}>
        <svg viewBox="0 0 100 100" style={{width:"100%",height:"100%",transform:"rotate(-90deg)"}}>
          <circle cx="50" cy="50" r={r} fill="none" stroke={T.border} strokeWidth={7}/>
          <circle cx="50" cy="50" r={r} fill="none" stroke={statusColor} strokeWidth={7}
            strokeDasharray={`${(pct/100)*circ} ${circ}`} strokeLinecap="round"
            style={{transition:"stroke-dasharray .8s ease"}}/>
        </svg>
        <div style={{ position:"absolute", inset:0, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
          <svg viewBox="0 0 24 24" fill="none" stroke={statusColor} strokeWidth={1.5} style={{width:26,height:26}}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
      </div>
      <div style={{ textAlign:"center" }}>
        <div style={{ fontSize:13, fontWeight:700, color:statusColor }}>ClamAV {statusLabel}</div>
        {clamav.db_version && <div style={{fontSize:11,color:T.muted,marginTop:2}}>DB v{clamav.db_version}</div>}
        {clamav.db_date && <div style={{fontSize:10,color:T.muted}}>{clamav.db_date.slice(0,10)}</div>}
      </div>
    </div>
  );
}

// ─── Activity — Bar chart ─────────────────────────────────────────────────────
function ActivityChart({ activity }) {
  if (!activity?.length) return null;
  const max = Math.max(...activity.map(d=>d.imports+d.failures),1);
  const BAR_H = 90;

  return (
    <div style={{ height:"100%", display:"flex", flexDirection:"column", gap:8 }}>
      <div style={{ display:"flex", gap:16, fontSize:11 }}>
        <span style={{ display:"flex", alignItems:"center", gap:5 }}>
          <span style={{ width:10, height:10, borderRadius:2, background:T.blue, display:"inline-block" }}/>
          <span style={{ color:T.sub }}>Imports</span>
        </span>
        <span style={{ display:"flex", alignItems:"center", gap:5 }}>
          <span style={{ width:10, height:10, borderRadius:2, background:T.red, display:"inline-block" }}/>
          <span style={{ color:T.sub }}>Échecs</span>
        </span>
      </div>

      {/* Barres */}
      <div style={{ display:"flex", alignItems:"flex-end", gap:4, height:BAR_H, flex:"0 0 auto" }}>
        {activity.map((d, i) => {
          const importH = d.imports  > 0 ? Math.max((d.imports/max)*BAR_H, 6) : 0;
          const failH   = d.failures > 0 ? Math.max((d.failures/max)*BAR_H, 6) : 0;
          const isEmpty = importH===0 && failH===0;
          return (
            <div key={i} style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", gap:2, height:"100%" }}>
              <div style={{ flex:1, display:"flex", flexDirection:"column", justifyContent:"flex-end", width:"100%", gap:1 }}>
                {failH>0 && (
                  <div title={`${d.failures} échec(s)`}
                    style={{ width:"100%", height:failH, background:T.red, borderRadius:"3px 3px 0 0", opacity:.85 }}/>
                )}
                {importH>0 && (
                  <div title={`${d.imports} import(s)`}
                    style={{ width:"100%", height:importH, background:T.blue, borderRadius:failH>0?"0":"3px 3px 0 0" }}/>
                )}
                {isEmpty && (
                  <div style={{ width:"100%", height:3, background:T.border, borderRadius:2 }}/>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Totaux par jour */}
      <div style={{ display:"flex", gap:4 }}>
        {activity.map((d, i) => (
          <div key={i} style={{ flex:1, textAlign:"center" }}>
            <div style={{ fontSize:9, color:T.muted, fontFamily:"monospace" }}>{d.date.slice(5)}</div>
            {(d.imports+d.failures)>0 && (
              <div style={{ fontSize:9, fontWeight:700, color:T.sub, marginTop:1 }}>
                {d.imports+d.failures}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Stats totales */}
      <div style={{ display:"flex", gap:12, borderTop:`1px solid ${T.border}`, paddingTop:8, marginTop:"auto" }}>
        <div>
          <div style={{ fontSize:18, fontWeight:800, color:T.blue, fontVariantNumeric:"tabular-nums" }}>
            {activity.reduce((s,d)=>s+d.imports,0)}
          </div>
          <div style={{ fontSize:10, color:T.muted }}>imports / 7j</div>
        </div>
        <div>
          <div style={{ fontSize:18, fontWeight:800, color:T.red, fontVariantNumeric:"tabular-nums" }}>
            {activity.reduce((s,d)=>s+d.failures,0)}
          </div>
          <div style={{ fontSize:10, color:T.muted }}>échecs / 7j</div>
        </div>
      </div>
    </div>
  );
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
const ALERT_COLOR = { deps_missing:T.yellow, sla_warning:T.orange, sla_expired:T.red, security:T.red };

function AlertsList({ alerts }) {
  if (!alerts?.length) return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:"100%", gap:8 }}>
      <svg viewBox="0 0 24 24" fill="none" stroke={T.green} strokeWidth={1.5} style={{width:32,height:32,opacity:.6}}>
        <polyline strokeLinecap="round" strokeLinejoin="round" points="20 6 9 17 4 12"/>
      </svg>
      <span style={{ fontSize:12, color:T.green }}>Tout nominal</span>
    </div>
  );
  return (
    <div style={{ overflowY:"auto", height:"100%", display:"flex", flexDirection:"column", gap:6 }}>
      {alerts.map((a,i)=>{
        const color = ALERT_COLOR[a.type]||T.muted;
        return (
          <div key={i} style={{
            display:"flex", alignItems:"flex-start", gap:10, padding:"9px 12px",
            borderRadius:8, background:color+"0D", border:`1px solid ${color}25`,
            flexShrink:0,
          }}>
            <span style={{ width:6, height:6, borderRadius:"50%", background:color, flexShrink:0, marginTop:3 }}/>
            <div style={{ minWidth:0 }}>
              <p style={{ fontSize:12, fontWeight:600, color:T.text, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{a.package}</p>
              <p style={{ fontSize:11, color:T.sub, marginTop:1 }}>{a.message}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Imports récents ──────────────────────────────────────────────────────────
const ACTION_COLOR = { UPLOAD:T.blue, IMPORT:T.teal, PENDING_REVIEW:T.orange, SECURITY_DECISION:T.purple };

function ImportsList({ imports }) {
  if (!imports?.length) return (
    <div style={{ textAlign:"center", padding:24, color:T.muted, fontSize:12 }}>Aucun import.</div>
  );
  return (
    <div style={{ overflowY:"auto", height:"100%" }}>
      <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
        <thead>
          <tr style={{ borderBottom:`1px solid ${T.border}` }}>
            {["Paquet","Version","Action","Date","Statut"].map(h=>(
              <th key={h} style={{ padding:"6px 12px", textAlign:"left", fontSize:10, fontWeight:700, letterSpacing:"0.05em", textTransform:"uppercase", color:T.muted }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {imports.slice(0,8).map((e,i)=>{
            const color = ACTION_COLOR[e.action]||T.muted;
            return (
              <tr key={i} style={{ borderBottom:`1px solid ${T.border}`, transition:"background .1s" }}
                onMouseEnter={ev=>ev.currentTarget.style.background="#F8FAFC"}
                onMouseLeave={ev=>ev.currentTarget.style.background=""}>
                <td style={{ padding:"8px 12px", fontFamily:"monospace", fontWeight:600, color:T.text }}>{e.package||"—"}</td>
                <td style={{ padding:"8px 12px", fontFamily:"monospace", color:T.muted }}>{e.version||"—"}</td>
                <td style={{ padding:"8px 12px" }}>
                  <span style={{ fontSize:10, fontWeight:700, padding:"2px 7px", borderRadius:4, background:color+"15", color, border:`1px solid ${color}30` }}>
                    {e.action||"—"}
                  </span>
                </td>
                <td style={{ padding:"8px 12px", fontFamily:"monospace", color:T.muted }}>{fmtTs(e.timestamp)}</td>
                <td style={{ padding:"8px 12px" }}>
                  <span style={{ display:"inline-block", width:7, height:7, borderRadius:"50%", background:e.result==="SUCCESS"?T.green:T.red }}/>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ─── Graphiques historiques ───────────────────────────────────────────────────

const fmtDay = iso => {
  const [,m,d] = iso.split("-");
  return `${d}/${m}`;
};

function HistoryImportsChart({ data }) {
  if (!data?.length) return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100%", color:T.muted, fontSize:12 }}>
      Pas encore de données historiques
    </div>
  );
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top:8, right:8, left:-20, bottom:0 }}>
        <defs>
          <linearGradient id="gradImports" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor={T.blue}   stopOpacity={0.2}/>
            <stop offset="95%" stopColor={T.blue}   stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="gradFail" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor={T.red}    stopOpacity={0.15}/>
            <stop offset="95%" stopColor={T.red}    stopOpacity={0}/>
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke={T.border} />
        <XAxis dataKey="date" tickFormatter={fmtDay} tick={{ fontSize:10, fill:T.muted }} tickLine={false} axisLine={false} />
        <YAxis allowDecimals={false} tick={{ fontSize:10, fill:T.muted }} tickLine={false} axisLine={false} />
        <Tooltip
          contentStyle={{ fontSize:12, borderRadius:8, border:`1px solid ${T.border}`, boxShadow:"0 4px 12px rgba(0,0,0,.08)" }}
          labelFormatter={v => v}
        />
        <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize:11, paddingTop:4 }} />
        <Area type="monotone" dataKey="imports"  name="Imports réussis" stroke={T.blue}   strokeWidth={2} fill="url(#gradImports)" dot={false} activeDot={{ r:4 }} />
        <Area type="monotone" dataKey="failures" name="Échecs"          stroke={T.red}    strokeWidth={1.5} fill="url(#gradFail)"    dot={false} strokeDasharray="4 2" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function HistoryDecisionsChart({ data }) {
  if (!data?.length) return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100%", color:T.muted, fontSize:12 }}>
      Pas encore de données
    </div>
  );
  // Ne garder que les 14 derniers jours pour ce graphique compact
  const slice = data.slice(-14);
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={slice} margin={{ top:8, right:8, left:-20, bottom:0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={T.border} vertical={false} />
        <XAxis dataKey="date" tickFormatter={fmtDay} tick={{ fontSize:10, fill:T.muted }} tickLine={false} axisLine={false} />
        <YAxis allowDecimals={false} tick={{ fontSize:10, fill:T.muted }} tickLine={false} axisLine={false} />
        <Tooltip
          contentStyle={{ fontSize:12, borderRadius:8, border:`1px solid ${T.border}` }}
          labelFormatter={v => v}
        />
        <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize:11, paddingTop:4 }} />
        <Bar dataKey="imports"   name="Imports"   fill={T.blue}   radius={[3,3,0,0]} maxBarSize={20} />
        <Bar dataKey="decisions" name="Décisions" fill={T.purple} radius={[3,3,0,0]} maxBarSize={20} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────
export default function DashboardPage() {
  const [stats, setStats]           = useState(null);
  const [history, setHistory]       = useState(null);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLast]      = useState(null);
  const [layouts, setLayouts]       = useState(()=>{
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY))||DEFAULT_LAYOUTS; }
    catch { return DEFAULT_LAYOUTS; }
  });
  const navigate = useNavigate();

  const load = useCallback(async (silent=false) => {
    if (!silent) setRefreshing(true);
    try {
      const [data, hist] = await Promise.all([
        getDashboardStats(),
        getDashboardHistory(30),
      ]);
      setStats(data);
      setHistory(hist?.history || []);
      setLast(new Date());
      if (!silent) toast.success("Tableau de bord actualisé");
    } catch { if(!silent) toast.error("Impossible de charger le tableau de bord"); }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  const resetLayout = useCallback(()=>{
    setLayouts(DEFAULT_LAYOUTS);
    localStorage.removeItem(STORAGE_KEY);
    toast.success("Disposition réinitialisée");
  }, []);

  useEffect(()=>{ load(true); const id=setInterval(()=>load(true),30000); return()=>clearInterval(id); },[load]);

  const onLayoutChange = useCallback((_,all)=>{
    setLayouts(all);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
  },[]);

  if (loading) return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:200 }}>
      <div style={{ width:28, height:28, border:`2px solid ${T.blue}`, borderTopColor:"transparent", borderRadius:"50%", animation:"spin 0.7s linear infinite" }}/>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
  if (!stats) return null;

  const { packages, activity, recent_imports, alerts, clamav, security_posture, security_review } = stats;
  const needsAction = (security_review?.pending_review||0)+(security_review?.blocked||0);

  return (
    <div style={{ background:T.bg, minHeight:"100%", padding:"24px 28px 40px" }}>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>

      {/* ── Header ── */}
      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:16, gap:12 }}>
        <div>
          <h1 style={{ fontSize:18, fontWeight:800, color:T.text, margin:0 }}>Tableau de bord</h1>
          <p style={{ fontSize:11, color:T.muted, margin:"3px 0 0" }}>
            {lastRefresh ? `Actualisé à ${lastRefresh.toLocaleTimeString("fr-FR")}` : "Chargement…"}
            <span style={{ marginLeft:8, opacity:.6 }}>· Glisser les panneaux pour réorganiser</span>
          </p>
        </div>
        <div style={{ display:"flex", gap:8, flexShrink:0 }}>
          <button onClick={resetLayout}
            title="Remettre les panneaux à leur position d'origine"
            style={{ fontSize:11, padding:"6px 12px", borderRadius:8, border:`1px solid ${T.border}`, background:T.panel, color:T.sub, cursor:"pointer", fontWeight:500 }}>
            Réinitialiser disposition
          </button>
          <button onClick={()=>load(false)} disabled={refreshing}
            title="Recharger les données depuis le serveur"
            style={{ fontSize:11, padding:"6px 12px", borderRadius:8, border:`1px solid ${T.blue}40`, background:T.blue+"10", color:T.blue, cursor:refreshing?"not-allowed":"pointer", fontWeight:600, display:"flex", alignItems:"center", gap:5, opacity:refreshing?0.7:1 }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"
              style={{width:13,height:13, animation:refreshing?"spin 0.7s linear infinite":"none"}}>
              <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
              <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
            </svg>
            Actualiser
          </button>
        </div>
      </div>

      {/* ── Grid ── */}
      <ResponsiveGridLayout
        layouts={layouts}
        onLayoutChange={onLayoutChange}
        breakpoints={{lg:1200,md:996,sm:768}}
        cols={{lg:12,md:8,sm:4}}
        rowHeight={28}
        margin={[10,10]}
        draggableHandle=".drag-handle"
        useCSSTransforms
        isResizable
        isDraggable
      >
        <div key="stat-packages">
          <StatPanel label="Paquets" value={packages.total} sub={fmtBytes(packages.total_size_bytes)} color={T.blue}
            iconPath="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z M3.27 6.96 12 12.01 20.73 6.96 M12 22.08 12 12"/>
        </div>

        <div key="stat-imports">
          <StatPanel label="Imports aujourd'hui" value={packages.imports_today} sub="ce jour" color={T.green}
            iconPath="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4 M7 10 12 15 17 10 M12 15 12 3"/>
        </div>

        <div key="stat-security">
          <StatPanel
            label="Révision RSSI"
            value={needsAction>0 ? needsAction : (security_review?.total_decisions||0)}
            sub={needsAction>0 ? "action(s) requise(s)" : "décision(s) active(s)"}
            color={needsAction>0 ? T.orange : T.indigo}
            onClick={()=>navigate("/security")}
            iconPath="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </div>

        <div key="stat-alerts">
          <StatPanel
            label="Alertes" value={alerts.length}
            sub={alerts.length===0 ? "Tout nominal" : "à traiter"}
            color={alerts.length>0 ? T.red : T.green}
            iconPath="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z M12 9 12 13 M12 17 12.01 17"/>
        </div>

        <div key="cve-posture">
          <Panel title="Posture CVE — Grype" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} style={{width:13,height:13}}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>}>
            <CvePosture posture={security_posture}/>
          </Panel>
        </div>

        <div key="security-review">
          <Panel title="Révision RSSI" badge={needsAction} onHeaderClick={()=>navigate("/security")} icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} style={{width:13,height:13}}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>}>
            <SecurityReview review={security_review} navigate={navigate}/>
          </Panel>
        </div>

        <div key="clamav">
          <Panel title="ClamAV — Antivirus" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} style={{width:13,height:13}}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M20.84 4.61a5.5 5.5 0 00-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 00-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 000-7.78z"/>
            </svg>}>
            <ClamavPanel clamav={clamav}/>
          </Panel>
        </div>

        <div key="history-imports">
          <Panel title="Historique — Imports & Échecs (30 jours)" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} style={{width:13,height:13}}>
              <polyline strokeLinecap="round" strokeLinejoin="round" points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>}>
            <HistoryImportsChart data={history} />
          </Panel>
        </div>

        <div key="history-decisions">
          <Panel title="Imports & Décisions (14j)" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} style={{width:13,height:13}}>
              <rect strokeLinecap="round" strokeLinejoin="round" x="3" y="3" width="18" height="18" rx="2"/>
              <path d="M3 9h18M9 21V9"/>
            </svg>}>
            <HistoryDecisionsChart data={history} />
          </Panel>
        </div>

        <div key="activity">
          <Panel title="Activité — 7 derniers jours" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} style={{width:13,height:13}}>
              <polyline strokeLinecap="round" strokeLinejoin="round" points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>}>
            <ActivityChart activity={activity}/>
          </Panel>
        </div>

        <div key="alerts">
          <Panel title="Alertes système" badge={alerts.length} icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} style={{width:13,height:13}}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 01-3.46 0"/>
            </svg>}>
            <AlertsList alerts={alerts}/>
          </Panel>
        </div>

        <div key="imports">
          <Panel title="Activité récente — imports" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} style={{width:13,height:13}}>
              <polyline strokeLinecap="round" strokeLinejoin="round" points="9 11 12 14 22 4"/>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
            </svg>}>
            <ImportsList imports={recent_imports}/>
          </Panel>
        </div>
      </ResponsiveGridLayout>
    </div>
  );
}
