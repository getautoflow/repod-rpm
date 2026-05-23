import axios from "axios";

// Vide par défaut → URLs relatives → nginx proxifie /api/ vers le backend.
// En dev local (npm start), définir REACT_APP_API_URL=http://localhost:8000 dans .env.local
const API_URL = process.env.REACT_APP_API_URL ?? "";
const V1      = "/api/v1";

const api = axios.create({ baseURL: API_URL });

// Token en mémoire — synchronisé par AuthContext via setApiToken/clearApiToken.
// Évite de dépendre de localStorage à chaque requête (peut être vidé entre renders).
let _apiToken = localStorage.getItem("token") || null;
export const setApiToken   = (t) => { _apiToken = t; };
export const clearApiToken = ()  => { _apiToken = null; };

// Injecte le token JWT sur chaque requête
api.interceptors.request.use((config) => {
  const token = _apiToken || localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Redirige vers /login en cas de 401 uniquement si l'utilisateur était authentifié.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && localStorage.getItem("token")) {
      localStorage.removeItem("token");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export const login = (username, password) =>
  api.post(`${V1}/auth/token`, { username, password });

export const requestPasswordReset = (username) =>
  api.post(`${V1}/auth/forgot-password`, { username }).then((r) => r.data);

export const resetPasswordWithToken = (token, newPassword) =>
  api.post(`${V1}/auth/reset-password`, { token, new_password: newPassword }).then((r) => r.data);

export const listPackages = () =>
  api.get(`${V1}/packages/`).then((r) => r.data);

// Artifacts — liste enrichie avec métadonnées (paginée)
export const listArtifacts = (page = 1, perPage = 50, search = null, distribution = null) => {
  const params = new URLSearchParams({ page, per_page: perPage });
  if (search)       params.append("search",       search);
  if (distribution) params.append("distribution", distribution);
  return api.get(`${V1}/artifacts/?${params}`).then((r) => r.data);
};

export const getArtifact = (name) =>
  api.get(`${V1}/artifacts/${name}`).then((r) => r.data);

export const resolveDependencies = (name) =>
  api.get(`${V1}/artifacts/${name}/dependencies`).then((r) => r.data);

export const installArtifact = (name, target = "localhost") =>
  api.post(`${V1}/artifacts/${name}/install`, { target }).then((r) => r.data);

export const deleteArtifact = (name, version = null) => {
  const url = version ? `${V1}/artifacts/${name}/${version}` : `${V1}/artifacts/${name}`;
  return api.delete(url).then((r) => r.data);
};

export const syncIndex = () =>
  api.post(`${V1}/artifacts/admin/sync-index`).then((r) => r.data);

export const installPackage = (name) =>
  api.post(`${V1}/packages/install/`, { name }).then((r) => r.data);

export const uploadPackage = (file, distribution = "almalinux8") => {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("distribution", distribution);
  return api.post(`${V1}/upload/`, formData).then((r) => r.data);
};

// ─── Import depuis internet ───────────────────────────────────────────────────

export const searchImportPackages = (q, limit = 20, source_id = null) => {
  const params = new URLSearchParams({ q, limit });
  if (source_id) params.append("source_id", source_id);
  return api.get(`${V1}/import/search?${params}`).then((r) => r.data);
};

export const resolveImportDeps = (packageName) =>
  api.get(`${V1}/import/resolve/${encodeURIComponent(packageName)}`).then((r) => r.data);

export const getImportSyncStatus = () =>
  api.get(`${V1}/import/sync-status`).then((r) => r.data);

export const getImportGroups = () =>
  api.get(`${V1}/import/groups`).then((r) => r.data);

export const deleteImportGroup = (name) =>
  api.delete(`${V1}/import/groups/${encodeURIComponent(name)}`).then((r) => r.data);

// ─── Sécurité / ClamAV ───────────────────────────────────────────────────────

export const getClamavStatus = () =>
  api.get(`${V1}/security/clamav/status`).then((r) => r.data);

export const getApiBaseUrl = () => API_URL;
// Alias utilisé par HealthPage pour construire l'URL /metrics
export const getBaseUrl    = () => API_URL;

// ─── Sécurité / CVE ──────────────────────────────────────────────────────────

export const getPackagesPosture = (distribution = null) => {
  const params = distribution ? `?distribution=${encodeURIComponent(distribution)}` : "";
  return api.get(`${V1}/security/packages-posture${params}`).then((r) => r.data);
};

export const getVulnerabilities = (filters = {}) => {
  const params = new URLSearchParams();
  if (filters.severity)     params.append("severity",     filters.severity);
  if (filters.fix_state)    params.append("fix_state",    filters.fix_state);
  if (filters.distribution) params.append("distribution", filters.distribution);
  if (filters.page)         params.append("page",         filters.page);
  if (filters.per_page)     params.append("per_page",     filters.per_page);
  const qs = params.toString();
  return api.get(`${V1}/security/vulnerabilities${qs ? "?" + qs : ""}`).then((r) => r.data);
};

export const getPackageCve = (name, version, arch = "x86_64") =>
  api.get(`${V1}/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/cve?arch=${arch}`)
    .then((r) => r.data);

export const quarantinePackage = (name, version, arch = "x86_64") =>
  api.post(`${V1}/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/quarantine?arch=${arch}`)
    .then((r) => r.data);

export const getReviewQueue = (page = 1, perPage = 50) => {
  const params = new URLSearchParams({ page, per_page: perPage });
  return api.get(`${V1}/security/review-queue?${params}`).then((r) => r.data);
};

export const submitDecision = (name, version, payload) =>
  api.post(
    `${V1}/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/decide`,
    payload
  ).then((r) => r.data);

export const checkSla = () =>
  api.post(`${V1}/security/check-sla`).then((r) => r.data);

export const getSecurityReport = () =>
  api.get(`${V1}/security/report`).then((r) => r.data);

// ─── Dashboard ───────────────────────────────────────────────────────────────

export const getDashboardStats = () =>
  api.get(`${V1}/dashboard/stats`).then((r) => r.data);

// ─── Distributions ───────────────────────────────────────────────────────────

export const getDistributions = () =>
  api.get(`${V1}/distributions/`).then((r) => r.data);

export const getDistribPackages = (codename) =>
  api.get(`${V1}/distributions/${codename}/packages`).then((r) => r.data);

export const promotePackage = (pkg, fromDist, toDist) =>
  api.post(`${V1}/distributions/promote`, { package: pkg, from_dist: fromDist, to_dist: toDist }).then((r) => r.data);

export const migrateDistrib = (fromDist, toDist) =>
  api.post(`${V1}/distributions/migrate`, { from_dist: fromDist, to_dist: toDist }).then((r) => r.data);

export const initDistributions = () =>
  api.post(`${V1}/distributions/init`).then((r) => r.data);

// ─── Gestion des utilisateurs ─────────────────────────────────────────────────

export const getRoles = () =>
  api.get(`${V1}/auth/roles`).then((r) => r.data);

export const listUsers = () =>
  api.get(`${V1}/auth/users`).then((r) => r.data);

export const createUser = (payload) =>
  api.post(`${V1}/auth/users`, payload).then((r) => r.data);

export const updateUser = (username, payload) =>
  api.patch(`${V1}/auth/users/${encodeURIComponent(username)}`, payload).then((r) => r.data);

export const deleteUser = (username) =>
  api.delete(`${V1}/auth/users/${encodeURIComponent(username)}`).then((r) => r.data);

export const resetUserPassword = (username, newPassword) =>
  api.post(`${V1}/auth/users/${encodeURIComponent(username)}/reset-password`, { new_password: newPassword }).then((r) => r.data);

export const changeOwnPassword = (currentPassword, newPassword) =>
  api.post(`${V1}/auth/change-password`, { current_password: currentPassword, new_password: newPassword }).then((r) => r.data);

export const getMeInfo = () =>
  api.get(`${V1}/auth/me`).then((r) => r.data);

// ─── MFA TOTP ────────────────────────────────────────────────────────────────

export const mfaSetup = () =>
  api.post(`${V1}/auth/mfa/setup`).then((r) => r.data);

export const mfaConfirm = (totp_code) =>
  api.post(`${V1}/auth/mfa/confirm`, { totp_code }).then((r) => r.data);

export const mfaAuthenticate = (mfa_token, totp_code) =>
  api.post(`${V1}/auth/mfa/authenticate`, { mfa_token, totp_code }).then((r) => r.data);

export const mfaDisable = (totp_code) =>
  api.post(`${V1}/auth/mfa/disable`, { totp_code }).then((r) => r.data);

// ─── SSO OIDC ─────────────────────────────────────────────────────────────────

export const getOidcPublicConfig = () =>
  api.get(`${V1}/auth/oidc/public-config`).then((r) => r.data);

export const oidcAuthorize = (code_challenge, state, redirect_uri = "") =>
  api.post(`${V1}/auth/oidc/authorize`, { code_challenge, state, redirect_uri }).then((r) => r.data);

export const oidcCallback = (code, state, code_verifier, redirect_uri = "") =>
  api.post(`${V1}/auth/oidc/callback`, { code, state, code_verifier, redirect_uri }).then((r) => r.data);

export const oidcTestDiscovery = (discovery_url) =>
  api.post(`${V1}/auth/oidc/test-discovery`, { discovery_url }).then((r) => r.data);

// ─── Paramètres ──────────────────────────────────────────────────────────────

export const getSettings = () =>
  api.get(`${V1}/settings/`).then((r) => r.data);

export const patchSettings = (partial) =>
  api.patch(`${V1}/settings/`, partial).then((r) => r.data);

export const testWebhook = () =>
  api.post(`${V1}/settings/test-webhook`).then((r) => r.data);

export const getNextSync = () =>
  api.get(`${V1}/settings/next-sync`).then((r) => r.data);

export const getSyncSchedule = () =>
  api.get(`${V1}/import/sync-schedule`).then((r) => r.data);

// ─── Audit ────────────────────────────────────────────────────────────────────
export const getAuditLogs = (params = {}) => {
  const qs = new URLSearchParams();
  if (params.page)     qs.set("page",     params.page);
  if (params.per_page) qs.set("per_page", params.per_page);
  if (params.package)  qs.set("package",  params.package);
  if (params.action)   qs.set("action",   params.action);
  if (params.result)   qs.set("result",   params.result);
  if (params.q)        qs.set("q",        params.q);
  return api.get(`${V1}/artifacts/audit/logs?${qs}`).then((r) => r.data);
};

// ─── API Tokens ───────────────────────────────────────────────────────────────
export const listApiTokens = () =>
  api.get(`${V1}/auth/api-tokens`).then((r) => r.data);

export const createApiToken = (payload) =>
  api.post(`${V1}/auth/api-tokens`, payload).then((r) => r.data);

export const revokeApiToken = (tokenId) =>
  api.delete(`${V1}/auth/api-tokens/${tokenId}`).then((r) => r.data);

// ─── GPG ──────────────────────────────────────────────────────────────────────
export const getGpgInfo = () =>
  api.get(`${V1}/settings/gpg`).then((r) => r.data);

export const generateGpgKey = () =>
  api.post(`${V1}/settings/gpg/generate`).then((r) => r.data);

export const testEmail = (toOverride = null) =>
  api.post(`${V1}/settings/test-email`, { to_override: toOverride }).then((r) => r.data);

export const testLdap = () =>
  api.post(`${V1}/settings/test-ldap`).then((r) => r.data);

export const runRetention = () =>
  api.post(`${V1}/settings/run-retention`).then((r) => r.data);

// ─── Health (reste à la racine — pas de préfixe /api/v1) ─────────────────────
export const getHealth = () =>
  api.get("/health").then((r) => r.data);

// ─── SBOM ─────────────────────────────────────────────────────────────────────

export const getSbomPreview = (format = "cyclonedx", distribution = null) => {
  const params = new URLSearchParams({ format });
  if (distribution) params.append("distribution", distribution);
  return api.get(`${V1}/sbom/preview?${params}`).then((r) => r.data);
};

export const getSbomExportUrl = (format = "cyclonedx", distribution = null) => {
  const params = new URLSearchParams({ format });
  if (distribution) params.append("distribution", distribution);
  return `${API_URL}${V1}/sbom/export?${params}`;
};

export const getSbomPackageUrl = (name, version, format = "cyclonedx", arch = "x86_64") => {
  const params = new URLSearchParams({ format, arch });
  return `${API_URL}${V1}/sbom/${encodeURIComponent(name)}/${encodeURIComponent(version)}?${params}`;
};

export const getSarifExportUrl = (distribution = null, arch = "x86_64") => {
  const params = new URLSearchParams({ arch });
  if (distribution) params.append("distribution", distribution);
  return `${API_URL}${V1}/sbom/sarif?${params}`;
};

export const getSarifPackageUrl = (name, version, arch = "x86_64") => {
  const params = new URLSearchParams({ arch });
  return `${API_URL}${V1}/sbom/${encodeURIComponent(name)}/${encodeURIComponent(version)}/sarif?${params}`;
};

// ─── Statistiques de téléchargements ─────────────────────────────────────────
export const getDownloadStats = (days = 30) =>
  api.get(`${V1}/downloads/stats?days=${days}`).then((r) => r.data);

// ─── Dashboard history ────────────────────────────────────────────────────────
export const getDashboardHistory = (days = 30) =>
  api.get(`${V1}/dashboard/history?days=${days}`).then((r) => r.data);

// ─── Package decision ─────────────────────────────────────────────────────────
export const getPackageDecision = (name, version, arch = "x86_64") =>
  api.get(`${V1}/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/decision?arch=${arch}`)
    .then((r) => r.data);

export const rescanPackage = (name, version, arch = "x86_64") =>
  api.post(`${V1}/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/rescan?arch=${arch}`)
    .then((r) => r.data);
