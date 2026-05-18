import { createContext, useContext, useState, useEffect, useMemo } from "react";
import { setApiToken, clearApiToken } from "../api";

const AuthContext = createContext(null);

function parseJwt(token) {
  try {
    return JSON.parse(atob(token.split(".")[1]));
  } catch {
    return null;
  }
}

function isTokenValid(token) {
  if (!token) return false;
  const payload = parseJwt(token);
  if (!payload?.exp) return false;
  return payload.exp * 1000 > Date.now() + 10_000;
}

export function AuthProvider({ children }) {
  // Initialisation unique — ne lit localStorage qu'une seule fois au montage
  const [token, setToken] = useState(() => {
    const stored = localStorage.getItem("token");
    return isTokenValid(stored) ? stored : null;
  });

  // Nettoyage du localStorage uniquement au montage (pas à chaque rendu)
  useEffect(() => {
    const stored = localStorage.getItem("token");
    if (stored && !isTokenValid(stored)) {
      localStorage.removeItem("token");
    }
    // Synchronise l'intercepteur axios avec le token initial
    const valid = isTokenValid(stored) ? stored : null;
    if (valid) setApiToken(valid);
    else clearApiToken();
  }, []);

  const user = useMemo(() => {
    if (!token) return null;
    const payload = parseJwt(token);
    return payload ? { username: payload.sub, role: payload.role, fullName: payload.full_name } : null;
  }, [token]);

  const signIn = (newToken) => {
    localStorage.setItem("token", newToken);
    setApiToken(newToken);   // intercepteur axios mis à jour immédiatement
    setToken(newToken);
  };

  const signOut = () => {
    localStorage.removeItem("token");
    clearApiToken();
    setToken(null);
  };

  return (
    <AuthContext.Provider value={{ token, user, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
