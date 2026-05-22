/**
 * OidcCallbackPage — Page de callback OIDC
 *
 * L'IdP (Keycloak, Authentik, Azure AD…) redirige ici après authentification :
 *   /oidc-callback?code=<code>&state=<state>[&error=<err>]
 *
 * Flow :
 *   1. Lire code + state depuis l'URL
 *   2. Vérifier state contre sessionStorage (anti-CSRF)
 *   3. Récupérer code_verifier depuis sessionStorage (PKCE)
 *   4. POST /api/v1/auth/oidc/callback → JWT repod-rpm
 *   5. signIn() + navigate("/")
 */

import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { oidcCallback } from "../api";
import { useAuth } from "../context/AuthContext";

export default function OidcCallbackPage() {
  const [searchParams]      = useSearchParams();
  const [status, setStatus] = useState("loading"); // loading | error
  const [errorMsg, setErrorMsg] = useState("");
  const { signIn } = useAuth();
  const navigate   = useNavigate();

  useEffect(() => {
    const run = async () => {
      // ── 1. Lire les paramètres reçus de l'IdP ───────────────────────────────
      const code       = searchParams.get("code");
      const stateParam = searchParams.get("state");
      const errorParam = searchParams.get("error");
      const errorDesc  = searchParams.get("error_description");

      if (errorParam) {
        setErrorMsg(errorDesc || errorParam);
        setStatus("error");
        return;
      }

      if (!code || !stateParam) {
        setErrorMsg("Paramètres de callback manquants (code ou state absent).");
        setStatus("error");
        return;
      }

      // ── 2. Vérifier le state (anti-CSRF) ────────────────────────────────────
      const storedState  = sessionStorage.getItem("oidc_state");
      const codeVerifier = sessionStorage.getItem("oidc_code_verifier");
      const redirectUri  = sessionStorage.getItem("oidc_redirect_uri") || "";

      if (!storedState || storedState !== stateParam) {
        setErrorMsg("State invalide — possible attaque CSRF. Veuillez réessayer.");
        setStatus("error");
        return;
      }

      if (!codeVerifier) {
        setErrorMsg("Code verifier manquant en session. Veuillez réessayer.");
        setStatus("error");
        return;
      }

      // ── 3. Nettoyer sessionStorage ───────────────────────────────────────────
      sessionStorage.removeItem("oidc_state");
      sessionStorage.removeItem("oidc_code_verifier");
      sessionStorage.removeItem("oidc_redirect_uri");

      // ── 4. Échanger le code contre un JWT repod-rpm ──────────────────────────
      try {
        const data = await oidcCallback(code, stateParam, codeVerifier, redirectUri);
        signIn(data.access_token);
        navigate("/", { replace: true });
      } catch (err) {
        const detail = err?.response?.data?.detail || "Authentification SSO échouée.";
        setErrorMsg(detail);
        setStatus("error");
      }
    };

    run();
  }, []); // eslint-disable-line

  if (status === "loading") {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-gray-900 to-gray-800 gap-4">
        <svg className="animate-spin w-10 h-10 text-blue-400" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
        </svg>
        <p className="text-slate-300 text-sm">Finalisation de la connexion SSO…</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 to-gray-800 p-4">
      <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-sm text-center space-y-4">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-red-100">
          <svg className="w-7 h-7 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round"
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
          </svg>
        </div>
        <h2 className="text-lg font-bold text-gray-900">Échec de l'authentification SSO</h2>
        <p className="text-sm text-gray-600">{errorMsg}</p>
        <button
          onClick={() => navigate("/login", { replace: true })}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 rounded-lg text-sm transition-colors"
        >
          Retour à la connexion
        </button>
      </div>
    </div>
  );
}
