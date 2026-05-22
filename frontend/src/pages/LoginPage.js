import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { login, requestPasswordReset, mfaAuthenticate, getOidcPublicConfig, oidcAuthorize } from "../api";
import { useAuth } from "../context/AuthContext";

export default function LoginPage() {
  const [username, setUsername]     = useState("");
  const [password, setPassword]     = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState("");
  const [showForgot, setShowForgot] = useState(false);
  const [mfaToken,   setMfaToken]   = useState("");
  const [totpCode,   setTotpCode]   = useState("");
  const [oidcConfig, setOidcConfig] = useState(null);
  const [ssoLoading, setSsoLoading] = useState(false);
  const { signIn } = useAuth();
  const navigate = useNavigate();

  // Charger la config OIDC publique au montage (sans auth)
  useEffect(() => {
    getOidcPublicConfig()
      .then((cfg) => setOidcConfig(cfg))
      .catch(() => { /* OIDC non configuré — ignorer silencieusement */ });
  }, []);

  // ── Connexion ──────────────────────────────────────────────────────────────
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!username || !password) {
      setError("Veuillez remplir tous les champs.");
      return;
    }
    setLoading(true);
    try {
      const { data } = await login(username, password);
      if (data.mfa_required && data.mfa_token) {
        // Étape 1 réussie — le MFA est requis
        setMfaToken(data.mfa_token);
      } else {
        signIn(data.access_token);
        navigate("/");
      }
    } catch (err) {
      const status = err?.response?.status;
      if (status === 401) {
        setError("Identifiant ou mot de passe incorrect.");
      } else if (status === 429) {
        setError("Trop de tentatives. Réessayez dans quelques minutes.");
      } else {
        setError("Impossible de contacter le serveur. Vérifiez votre connexion.");
      }
    } finally {
      setLoading(false);
    }
  };

  // ── Validation TOTP (étape 2) ──────────────────────────────────────────────
  const handleMfaSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!totpCode || totpCode.length !== 6) {
      setError("Entrez le code à 6 chiffres de votre application.");
      return;
    }
    setLoading(true);
    try {
      const data = await mfaAuthenticate(mfaToken, totpCode);
      signIn(data.access_token);
      navigate("/");
    } catch (err) {
      const status = err?.response?.status;
      if (status === 401) {
        setError("Code TOTP invalide ou expiré. Réessayez.");
      } else if (status === 429) {
        setError("Trop de tentatives. Réessayez dans quelques minutes.");
      } else {
        setError("Impossible de contacter le serveur.");
      }
      setTotpCode("");
    } finally {
      setLoading(false);
    }
  };

  // ── Connexion SSO via PKCE ─────────────────────────────────────────────────
  const handleSsoLogin = async () => {
    setSsoLoading(true);
    setError("");
    try {
      // 1. Générer code_verifier : 96 octets aléatoires → base64url (sans padding)
      const verifierBytes = new Uint8Array(96);
      crypto.getRandomValues(verifierBytes);
      const codeVerifier = btoa(String.fromCharCode(...verifierBytes))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

      // 2. code_challenge = SHA-256(code_verifier) → base64url
      const encoded     = new TextEncoder().encode(codeVerifier);
      const hashBuf     = await crypto.subtle.digest("SHA-256", encoded);
      const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(hashBuf)))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

      // 3. state anti-CSRF : 32 octets aléatoires → hex
      const stateBytes = new Uint8Array(32);
      crypto.getRandomValues(stateBytes);
      const state = Array.from(stateBytes).map((b) => b.toString(16).padStart(2, "0")).join("");

      const redirectUri = `${window.location.origin}/oidc-callback`;

      // 4. Persister en sessionStorage pour la page de callback
      sessionStorage.setItem("oidc_state",         state);
      sessionStorage.setItem("oidc_code_verifier", codeVerifier);
      sessionStorage.setItem("oidc_redirect_uri",  redirectUri);

      // 5. Obtenir l'URL d'autorisation de l'IdP et rediriger
      const { authorization_url } = await oidcAuthorize(codeChallenge, state, redirectUri);
      window.location.href = authorization_url;
    } catch {
      setError("Impossible de démarrer la connexion SSO. Vérifiez la configuration.");
      setSsoLoading(false);
    }
  };

  // ── Écran MFA (étape 2) ─────────────────────────────────────────────────────
  if (mfaToken) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 to-gray-800">
        <div className="w-full max-w-sm">
          <div className="bg-white rounded-2xl shadow-2xl p-8">
            {/* En-tête */}
            <div className="text-center mb-6">
              <div className="inline-flex items-center justify-center w-14 h-14 bg-blue-100 rounded-full mb-4">
                <svg className="w-7 h-7 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h2 className="text-xl font-bold text-gray-900">Vérification en deux étapes</h2>
              <p className="text-sm text-gray-500 mt-1">
                Entrez le code à 6 chiffres de votre application authenticator.
              </p>
            </div>

            <form onSubmit={handleMfaSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2 text-center">
                  Code TOTP
                </label>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => {
                    setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6));
                    setError("");
                  }}
                  className={`w-full border rounded-lg px-4 py-3 text-center text-2xl font-mono
                    tracking-[0.5em] focus:outline-none focus:ring-2 focus:ring-blue-500
                    focus:border-transparent
                    ${error ? "border-red-400 bg-red-50" : "border-gray-300"}`}
                  placeholder="000000"
                  autoFocus
                  autoComplete="one-time-code"
                />
              </div>

              {error && (
                <div className="flex items-start gap-2 bg-red-50 border border-red-200 rounded-lg px-3 py-2.5">
                  <svg className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm-1-9v4a1 1 0 102 0V9a1 1 0 10-2 0zm0-4a1 1 0 112 0 1 1 0 01-2 0z" clipRule="evenodd"/>
                  </svg>
                  <p className="text-sm text-red-700">{error}</p>
                </div>
              )}

              <button
                type="submit"
                disabled={loading || totpCode.length !== 6}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50
                           disabled:cursor-not-allowed text-white font-medium py-2.5 rounded-lg
                           transition-colors text-sm mt-1"
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                    </svg>
                    Vérification…
                  </span>
                ) : "Vérifier"}
              </button>
            </form>

            <div className="mt-4 text-center">
              <button
                onClick={() => { setMfaToken(""); setTotpCode(""); setError(""); }}
                className="text-sm text-gray-500 hover:text-gray-700 hover:underline"
              >
                ← Retour à la connexion
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ── Écran principal (étape 1) ────────────────────────────────────────────────
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 to-gray-800">
      <div className="w-full max-w-sm space-y-3">

        {/* Carte principale */}
        <div className="bg-white rounded-2xl shadow-2xl p-8">
          {/* Logo */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center mb-4">
              <img src="/logo.png" alt="Repod" className="w-16 h-16 object-contain" />
            </div>
            <h1 className="text-2xl font-black tracking-wider text-gray-900 uppercase">Repod</h1>
            <p className="text-sm text-gray-500 mt-1">Connectez-vous pour continuer</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Utilisateur
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => { setUsername(e.target.value); setError(""); }}
                className={`w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2
                  focus:ring-blue-500 focus:border-transparent
                  ${error ? "border-red-400 bg-red-50" : "border-gray-300"}`}
                placeholder="admin"
                autoFocus
                autoComplete="username"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Mot de passe
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); setError(""); }}
                  className={`w-full border rounded-lg px-3 py-2 pr-10 text-sm focus:outline-none focus:ring-2
                    focus:ring-purple-500 focus:border-transparent
                    ${error ? "border-red-400 bg-red-50" : "border-gray-300"}`}
                  placeholder="••••••••"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-400 hover:text-gray-600 transition-colors"
                  tabIndex={-1}
                  aria-label={showPassword ? "Masquer le mot de passe" : "Afficher le mot de passe"}
                >
                  {showPassword ? (
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/>
                    </svg>
                  ) : (
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                    </svg>
                  )}
                </button>
              </div>
            </div>

            {/* Erreur inline — toujours visible, ne disparaît pas */}
            {error && (
              <div className="flex items-start gap-2 bg-red-50 border border-red-200 rounded-lg px-3 py-2.5">
                <svg className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm-1-9v4a1 1 0 102 0V9a1 1 0 10-2 0zm0-4a1 1 0 112 0 1 1 0 01-2 0z" clipRule="evenodd"/>
                </svg>
                <p className="text-sm text-red-700">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gray-900 hover:bg-gray-800 disabled:opacity-50
                         disabled:cursor-not-allowed text-white font-medium py-2 rounded-lg
                         transition-colors text-sm mt-1"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                  </svg>
                  Connexion…
                </span>
              ) : "Se connecter"}
            </button>
          </form>

          {/* Lien mot de passe oublié */}
          <div className="mt-4 text-center">
            <button
              onClick={() => { setShowForgot(!showForgot); setError(""); }}
              className="text-sm text-blue-600 hover:text-blue-700 hover:underline"
            >
              Mot de passe oublié ?
            </button>
          </div>

          {/* Bouton SSO — affiché uniquement si OIDC est activé côté serveur */}
          {oidcConfig?.enabled && (
            <>
              <div className="relative my-3">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-200" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="px-3 bg-white text-gray-400 font-medium tracking-wider">ou</span>
                </div>
              </div>
              <button
                type="button"
                onClick={handleSsoLogin}
                disabled={ssoLoading}
                className="w-full flex items-center justify-center gap-2.5 border border-gray-300
                           rounded-lg px-4 py-2.5 text-sm font-medium text-gray-700
                           hover:bg-gray-50 hover:border-gray-400 disabled:opacity-50
                           disabled:cursor-not-allowed transition-colors"
              >
                {ssoLoading ? (
                  <>
                    <svg className="animate-spin w-4 h-4 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                    </svg>
                    Redirection vers {oidcConfig.provider_name}…
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24"
                         stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
                      <path d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                    </svg>
                    Se connecter avec {oidcConfig.provider_name}
                  </>
                )}
              </button>
            </>
          )}
        </div>

        {/* Panneau de réinitialisation (accordéon) */}
        {showForgot && (
          <ForgotPasswordPanel onClose={() => setShowForgot(false)} />
        )}
      </div>
    </div>
  );
}


// ── Formulaire de demande de reset ────────────────────────────────────────────
function ForgotPasswordPanel({ onClose }) {
  const [username, setUsername] = useState("");
  const [loading, setLoading]   = useState(false);
  const [sent, setSent]         = useState(false);

  const handleRequest = async (e) => {
    e.preventDefault();
    if (!username.trim()) return;
    setLoading(true);
    try {
      await requestPasswordReset(username.trim());
      setSent(true);
    } catch {
      // L'API renvoie toujours 200 — une erreur ici = problème réseau
      toast.error("Impossible de contacter le serveur.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-2xl shadow-xl p-6 border border-blue-100">
      {sent ? (
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center w-12 h-12 bg-green-100 rounded-full">
            <svg className="w-6 h-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7"/>
            </svg>
          </div>
          <p className="text-sm font-medium text-gray-800">Demande envoyée</p>
          <p className="text-xs text-gray-500">
            Si ce compte existe et dispose d'un email, un lien de réinitialisation
            a été envoyé. Il est valable <strong>30 minutes</strong>.
          </p>
          <button
            onClick={onClose}
            className="text-sm text-blue-600 hover:underline"
          >
            Retour à la connexion
          </button>
        </div>
      ) : (
        <>
          <h3 className="text-sm font-semibold text-gray-800 mb-1">
            Réinitialiser le mot de passe
          </h3>
          <p className="text-xs text-gray-500 mb-4">
            Entrez votre nom d'utilisateur. Si un email est associé à ce compte,
            vous recevrez un lien de réinitialisation.
          </p>
          <form onSubmit={handleRequest} className="space-y-3">
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Nom d'utilisateur"
              autoFocus
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm
                         focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <div className="flex gap-2">
              <button
                type="submit"
                disabled={loading || !username.trim()}
                className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50
                           text-white text-sm font-medium py-2 rounded-lg transition-colors"
              >
                {loading ? "Envoi…" : "Envoyer le lien"}
              </button>
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-2 border border-gray-300 rounded-lg text-sm
                           text-gray-600 hover:bg-gray-50 transition-colors"
              >
                Annuler
              </button>
            </div>
          </form>

          {/* Fallback CLI pour les admins sans email */}
          <details className="mt-4">
            <summary className="text-xs text-gray-400 cursor-pointer hover:text-gray-600 select-none">
              Pas d'email configuré ? (accès CLI)
            </summary>
            <div className="mt-2 bg-gray-50 rounded-lg p-3 font-mono text-xs text-gray-600 leading-relaxed">
              <p className="text-gray-400 mb-1"># Depuis le serveur :</p>
              <p className="break-all">
                docker exec backend-api python3 -c
                <br />"from auth.users import change_password;
                <br />change_password('admin', 'NouveauMotDePasse')"
              </p>
            </div>
          </details>
        </>
      )}
    </div>
  );
}
