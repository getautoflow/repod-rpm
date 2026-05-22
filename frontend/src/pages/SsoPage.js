/**
 * SsoPage — Configuration SSO / OIDC
 * Route : /sso
 *
 * Permet à l'administrateur de configurer l'authentification SSO OIDC :
 *  - Keycloak, Authentik, Zitadel, Azure AD (Entra ID), Okta, ADFS…
 *  - Authorization Code + PKCE (RFC 7636)
 *  - Auto-provisioning des utilisateurs RPM au 1er login
 *  - Mapping groupes/rôles IdP → rôles repod-rpm
 */

import { useState, useEffect, useCallback } from "react";
import toast from "react-hot-toast";
import { getSettings, patchSettings, oidcTestDiscovery } from "../api";

// ── Composants utilitaires ────────────────────────────────────────────────────

function Field({ label, hint, children }) {
  return (
    <div className="space-y-1.5">
      <div>
        <label className="text-sm font-medium text-gray-800">{label}</label>
        {hint && <p className="text-xs text-gray-400 mt-0.5">{hint}</p>}
      </div>
      {children}
    </div>
  );
}

function Input({ value, onChange, placeholder = "", type = "text", mono = false, readOnly = false }) {
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      readOnly={readOnly}
      className={`w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none
        focus:ring-2 focus:ring-blue-500 bg-white
        ${mono ? "font-mono" : ""}
        ${readOnly ? "bg-gray-50 text-gray-500 cursor-default" : ""}`}
    />
  );
}

function Toggle({ checked, onChange, label, description }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <p className="text-sm font-medium text-gray-800">{label}</p>
        {description && <p className="text-xs text-gray-400 mt-0.5">{description}</p>}
      </div>
      <button
        type="button"
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors
          ${checked ? "bg-blue-600" : "bg-gray-300"}`}
      >
        <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform
          ${checked ? "translate-x-6" : "translate-x-1"}`} />
      </button>
    </div>
  );
}

// ── Rôles disponibles dans repod-rpm ─────────────────────────────────────────
const REPOD_ROLES = ["admin", "maintainer", "uploader", "auditor", "reader"];

// ── Composant mapping rôles ───────────────────────────────────────────────────
function RoleMapEditor({ roleMap, onChange }) {
  const [newIdpRole,   setNewIdpRole]   = useState("");
  const [newRepodRole, setNewRepodRole] = useState("reader");

  const handleAdd = () => {
    if (!newIdpRole.trim()) return;
    onChange({ ...roleMap, [newIdpRole.trim()]: newRepodRole });
    setNewIdpRole("");
  };

  const handleRemove = (key) => {
    const next = { ...roleMap };
    delete next[key];
    onChange(next);
  };

  return (
    <div className="space-y-2">
      {Object.entries(roleMap).length > 0 && (
        <div className="border border-gray-200 rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-gray-50 text-gray-500 font-semibold uppercase tracking-wide">
                <th className="px-3 py-2 text-left">Groupe / Rôle IdP</th>
                <th className="px-3 py-2 text-left">Rôle repod-rpm</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {Object.entries(roleMap).map(([idpRole, repodRole]) => (
                <tr key={idpRole}>
                  <td className="px-3 py-2 font-mono text-gray-700">{idpRole}</td>
                  <td className="px-3 py-2">
                    <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded font-medium">
                      {repodRole}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right">
                    <button onClick={() => handleRemove(idpRole)}
                      className="text-red-400 hover:text-red-600 transition-colors">
                      ✕
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="flex gap-2">
        <input
          type="text"
          value={newIdpRole}
          onChange={(e) => setNewIdpRole(e.target.value)}
          placeholder="groupe-idp ou rôle IdP"
          onKeyDown={(e) => e.key === "Enter" && handleAdd()}
          className="flex-1 border border-gray-200 rounded-lg px-3 py-1.5 text-sm font-mono
                     focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <select
          value={newRepodRole}
          onChange={(e) => setNewRepodRole(e.target.value)}
          className="border border-gray-200 rounded-lg px-2 py-1.5 text-sm focus:outline-none
                     focus:ring-2 focus:ring-blue-500 bg-white"
        >
          {REPOD_ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <button
          type="button"
          onClick={handleAdd}
          disabled={!newIdpRole.trim()}
          className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50
                     text-white text-sm font-medium rounded-lg transition-colors"
        >
          Ajouter
        </button>
      </div>
    </div>
  );
}

// ── Page principale ───────────────────────────────────────────────────────────

const DEFAULT_OIDC = {
  enabled:        false,
  provider_name:  "SSO",
  discovery_url:  "",
  client_id:      "",
  client_secret:  "",
  scopes:         "openid email profile",
  redirect_uri:   "",
  auto_provision: true,
  default_role:   "reader",
  claim_username: "preferred_username",
  claim_email:    "email",
  claim_fullname: "name",
  claim_role:     "",
  role_map:       {},
};

export default function SsoPage() {
  const [oidc,        setOidc]        = useState(DEFAULT_OIDC);
  const [loading,     setLoading]     = useState(true);
  const [saving,      setSaving]      = useState(false);
  const [isDirty,     setDirty]       = useState(false);
  const [testing,     setTesting]     = useState(false);
  const [testResult,  setTestResult]  = useState(null); // {ok, issuer, ...} | null

  const computedRedirectUri = `${window.location.origin}/oidc-callback`;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const s = await getSettings();
      setOidc({ ...DEFAULT_OIDC, ...(s.oidc || {}) });
      setDirty(false);
    } catch {
      toast.error("Impossible de charger la configuration SSO");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const set = (key, value) => {
    setOidc((prev) => ({ ...prev, [key]: value }));
    setDirty(true);
    setTestResult(null);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await patchSettings({ oidc });
      toast.success("Configuration SSO sauvegardée");
      setDirty(false);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Erreur lors de la sauvegarde");
    } finally {
      setSaving(false);
    }
  };

  const handleTestDiscovery = async () => {
    if (!oidc.discovery_url) return;
    setTesting(true);
    setTestResult(null);
    try {
      const r = await oidcTestDiscovery(oidc.discovery_url);
      setTestResult(r);
      if (r.ok) toast.success("Discovery endpoint accessible ✓");
      else toast.error("Discovery endpoint inaccessible");
    } catch (e) {
      setTestResult({ ok: false, error: e.response?.data?.detail || "Erreur réseau" });
      toast.error("Échec du test");
    } finally {
      setTesting(false);
    }
  };

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center py-20">
        <svg className="animate-spin w-7 h-7 text-blue-500" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
        </svg>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">

      {/* En-tête */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">SSO / Authentification unique</h1>
          <p className="text-sm text-gray-500 mt-1">
            Authentification fédérée via OpenID Connect (OIDC) · Authorization Code + PKCE
          </p>
        </div>
        {isDirty && (
          <span className="text-xs bg-yellow-100 text-yellow-700 border border-yellow-200
                           px-3 py-1 rounded-full font-medium shrink-0 mt-1">
            Modifications non sauvegardées
          </span>
        )}
      </div>

      {/* Providers supportés */}
      <div className="flex flex-wrap gap-2">
        {[
          { name: "Keycloak",  color: "blue"   },
          { name: "Authentik", color: "purple" },
          { name: "Zitadel",   color: "indigo" },
          { name: "Azure AD",  color: "sky"    },
          { name: "Okta",      color: "teal"   },
          { name: "ADFS",      color: "gray"   },
        ].map(({ name, color }) => (
          <span key={name}
            className={`text-xs px-2.5 py-1 rounded-full font-medium
              bg-${color}-50 text-${color}-700 border border-${color}-200`}>
            {name}
          </span>
        ))}
      </div>

      {/* ── Bloc 1 : Activation ── */}
      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-4">
        <h2 className="text-sm font-semibold text-gray-900">Activation</h2>
        <Toggle
          checked={oidc.enabled}
          onChange={(v) => set("enabled", v)}
          label="Activer le SSO OIDC"
          description="Affiche le bouton SSO sur la page de connexion. Les connexions locales restent disponibles en parallèle."
        />
        {oidc.enabled && (
          <Field label='Libellé du bouton de connexion' hint='Affiché sur la page de login, ex. "Se connecter avec Keycloak"'>
            <Input value={oidc.provider_name} onChange={(v) => set("provider_name", v)}
              placeholder="Se connecter avec SSO" />
          </Field>
        )}
      </div>

      {/* ── Bloc 2 : Connexion IdP ── */}
      <div className={`bg-white rounded-xl border border-gray-200 p-6 space-y-5 transition-opacity ${!oidc.enabled ? "opacity-40 pointer-events-none" : ""}`}>
        <h2 className="text-sm font-semibold text-gray-900">Connexion à l'IdP</h2>

        <Field label="Discovery URL" hint="URL du document OpenID Connect discovery de votre IdP">
          <div className="flex gap-2">
            <Input
              value={oidc.discovery_url}
              onChange={(v) => set("discovery_url", v)}
              placeholder="https://sso.example.com/realms/myorg/.well-known/openid-configuration"
              mono
            />
            <button
              onClick={handleTestDiscovery}
              disabled={testing || !oidc.discovery_url}
              className="shrink-0 px-3 py-2 border border-gray-200 rounded-lg text-xs font-medium
                         hover:bg-gray-50 disabled:opacity-50 text-gray-600 transition-colors whitespace-nowrap"
            >
              {testing ? "Test…" : "Tester"}
            </button>
          </div>

          {/* Exemples par IdP */}
          <div className="mt-2 text-xs text-gray-400 space-y-0.5">
            <p><span className="font-medium text-gray-500">Keycloak :</span>{" "}
              <span className="font-mono">https://sso.example.com/realms/&lt;realm&gt;/.well-known/openid-configuration</span></p>
            <p><span className="font-medium text-gray-500">Authentik :</span>{" "}
              <span className="font-mono">https://authentik.example.com/application/o/&lt;slug&gt;/.well-known/openid-configuration</span></p>
            <p><span className="font-medium text-gray-500">Azure AD :</span>{" "}
              <span className="font-mono">https://login.microsoftonline.com/&lt;tenant-id&gt;/v2.0/.well-known/openid-configuration</span></p>
            <p><span className="font-medium text-gray-500">Okta :</span>{" "}
              <span className="font-mono">https://&lt;domain&gt;.okta.com/oauth2/default/.well-known/openid-configuration</span></p>
          </div>

          {/* Résultat du test */}
          {testResult && (
            <div className={`mt-3 rounded-lg border p-3 text-xs space-y-1
              ${testResult.ok ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"}`}>
              {testResult.ok ? (
                <>
                  <p className="font-semibold text-green-800">✓ Discovery accessible</p>
                  <p className="text-green-700"><span className="font-medium">Issuer :</span> {testResult.issuer}</p>
                  <p className="text-green-700 font-mono truncate"><span className="font-medium not-italic">Auth :</span> {testResult.auth_ep}</p>
                  <p className="text-green-700 font-mono truncate"><span className="font-medium not-italic">Token :</span> {testResult.token_ep}</p>
                  <p className="text-green-700 font-mono truncate"><span className="font-medium not-italic">JWKS :</span> {testResult.jwks_uri}</p>
                </>
              ) : (
                <>
                  <p className="font-semibold text-red-800">✗ Discovery inaccessible</p>
                  <p className="text-red-700">{testResult.error}</p>
                </>
              )}
            </div>
          )}
        </Field>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field label="Client ID" hint="Identifiant de l'application repod-rpm dans l'IdP">
            <Input value={oidc.client_id} onChange={(v) => set("client_id", v)}
              placeholder="repod-rpm" mono />
          </Field>
          <Field label="Client Secret" hint="Secret généré dans la console IdP">
            <Input value={oidc.client_secret} onChange={(v) => set("client_secret", v)}
              type="password" placeholder="••••••••••••" mono />
          </Field>
        </div>

        <Field label="Scopes" hint="Espaces séparés — openid est obligatoire">
          <Input value={oidc.scopes} onChange={(v) => set("scopes", v)}
            placeholder="openid email profile" mono />
        </Field>

        <Field
          label="Redirect URI"
          hint="Enregistrez cette URL dans la console de votre IdP (Client → Valid redirect URIs)"
        >
          <div className="flex gap-2">
            <Input
              value={oidc.redirect_uri || computedRedirectUri}
              onChange={(v) => set("redirect_uri", v)}
              placeholder={computedRedirectUri}
              mono
            />
            <button
              onClick={() => { navigator.clipboard.writeText(oidc.redirect_uri || computedRedirectUri); toast.success("Copié"); }}
              className="shrink-0 px-3 py-2 border border-gray-200 rounded-lg text-xs font-medium
                         hover:bg-gray-50 text-gray-600 transition-colors"
            >
              Copier
            </button>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Laisser vide pour utiliser la valeur calculée depuis l'URL du navigateur.
          </p>
        </Field>
      </div>

      {/* ── Bloc 3 : Provisioning ── */}
      <div className={`bg-white rounded-xl border border-gray-200 p-6 space-y-5 transition-opacity ${!oidc.enabled ? "opacity-40 pointer-events-none" : ""}`}>
        <h2 className="text-sm font-semibold text-gray-900">Provisioning des utilisateurs</h2>

        <Toggle
          checked={oidc.auto_provision}
          onChange={(v) => set("auto_provision", v)}
          label="Auto-provisioning"
          description="Crée automatiquement le compte repod-rpm au premier login SSO. Si désactivé, l'utilisateur doit être créé manuellement dans la page Utilisateurs."
        />

        <Field label="Rôle par défaut" hint="Attribué si aucun mapping de groupe ne correspond">
          <select
            value={oidc.default_role}
            onChange={(e) => set("default_role", e.target.value)}
            className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none
                       focus:ring-2 focus:ring-blue-500 bg-white"
          >
            {REPOD_ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </Field>
      </div>

      {/* ── Bloc 4 : Mapping des claims ── */}
      <div className={`bg-white rounded-xl border border-gray-200 p-6 space-y-5 transition-opacity ${!oidc.enabled ? "opacity-40 pointer-events-none" : ""}`}>
        <div>
          <h2 className="text-sm font-semibold text-gray-900">Mapping des claims JWT</h2>
          <p className="text-xs text-gray-400 mt-1">
            Noms des claims dans l'ID token retourné par votre IdP.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <Field label="Claim → Nom d'utilisateur" hint="Keycloak : preferred_username · Azure : upn">
            <Input value={oidc.claim_username} onChange={(v) => set("claim_username", v)}
              placeholder="preferred_username" mono />
          </Field>
          <Field label="Claim → Email" hint="Généralement : email">
            <Input value={oidc.claim_email} onChange={(v) => set("claim_email", v)}
              placeholder="email" mono />
          </Field>
          <Field label="Claim → Nom complet" hint="Généralement : name">
            <Input value={oidc.claim_fullname} onChange={(v) => set("claim_fullname", v)}
              placeholder="name" mono />
          </Field>
        </div>

        <Field
          label="Claim → Groupes / Rôles (optionnel)"
          hint="Claim IdP portant les groupes ou rôles. Ex : groups, roles. Laisser vide pour ignorer."
        >
          <Input value={oidc.claim_role} onChange={(v) => set("claim_role", v)}
            placeholder="groups" mono />
        </Field>

        {oidc.claim_role && (
          <Field
            label="Mapping groupes → rôles repod-rpm"
            hint={`Valeur du claim "${oidc.claim_role}" → rôle repod-rpm attribué`}
          >
            <RoleMapEditor roleMap={oidc.role_map || {}} onChange={(v) => set("role_map", v)} />
          </Field>
        )}
      </div>

      {/* ── Bouton de sauvegarde ── */}
      <div className="flex items-center gap-4">
        <button
          onClick={handleSave}
          disabled={saving || !isDirty}
          className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50
                     disabled:cursor-not-allowed text-white text-sm font-semibold
                     rounded-lg transition-colors"
        >
          {saving ? "Sauvegarde…" : "Sauvegarder la configuration SSO"}
        </button>
        {!isDirty && !saving && (
          <span className="text-xs text-gray-400">Configuration à jour</span>
        )}
      </div>

      {/* ── Info flux PKCE ── */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-5 text-sm">
        <p className="font-semibold text-blue-800 mb-2">Flux Authorization Code + PKCE (RFC 7636)</p>
        <ol className="text-blue-700 text-xs space-y-1 list-decimal list-inside">
          <li>Le frontend génère un <span className="font-mono">code_verifier</span> aléatoire et son SHA-256 (<span className="font-mono">code_challenge</span>)</li>
          <li>Redirection vers l'IdP avec <span className="font-mono">code_challenge</span> + <span className="font-mono">state</span></li>
          <li>L'IdP authentifie l'utilisateur et redirige vers <span className="font-mono">/oidc-callback</span> avec un <span className="font-mono">code</span></li>
          <li>repod-rpm échange <span className="font-mono">code + code_verifier</span> contre l'ID token</li>
          <li>L'ID token est validé cryptographiquement via JWKS — aucun secret partagé dans le browser</li>
          <li>repod-rpm émet son propre JWT et la session commence</li>
        </ol>
      </div>

    </div>
  );
}
