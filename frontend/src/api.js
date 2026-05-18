import axios from "axios";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

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
// Si pas de token (ex: mauvais identifiants sur la page de login), on laisse le
// composant gérer l'erreur lui-même — sinon la page recharge avant l'affichage
// du message d'erreur et l'utilisateur croit être "déconnecté à la seconde".
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
  api.post("/auth/token", { username, password });

export const requestPasswordReset = (username) =>
  api.post("/auth/forgot-password", { username }).then((r) => r.data);

export const resetPasswordWithToken = (token, newPassword) =>
  api.post("/auth/reset-password", { token, new_password: newPassword }).then((r) => r.data);

export const listPackages = () =>
  api.get("/packages/").then((r) => r.data);

// Artifacts — liste enrichie avec métadonnées
export const listArtifacts = () =>
  api.get("/artifacts/").then((r) => r.data);

export const getArtifact = (name) =>
  api.get(`/artifacts/${name}`).then((r) => r.data);

export const resolveDependencies = (name) =>
  api.get(`/artifacts/${name}/dependencies`).then((r) => r.data);

export const installArtifact = (name, target = "localhost") =>
  api.post(`/artifacts/${name}/install`, { target }).then((r) => r.data);

export const deleteArtifact = (name, version = null) => {
  const url = version ? `/artifacts/${name}/${version}` : `/artifacts/${name}`;
  return api.delete(url).then((r) => r.data);
};

// getAuditLogs défini plus bas avec filtres complets

export const syncIndex = () =>
  api.post("/artifacts/admin/sync-index").then((r) => r.data);

export const installPackage = (name) =>
  api.post("/packages/install/", { name }).then((r) => r.data);

export const uploadPackage = (file, distribution = "almalinux8") => {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("distribution", distribution);
  return api.post("/upload/", formData).then((r) => r.data);
};

// ─── Import depuis internet ───────────────────────────────────────────────────

export const searchImportPackages = (q, limit = 20, source_id = null) => {
  const params = new URLSearchParams({ q, limit });
  if (source_id) params.append("source_id", source_id);
  return api.get(`/import/search?${params}`).then((r) => r.data);
};

export const resolveImportDeps = (packageName) =>
  api.get(`/import/resolve/${encodeURIComponent(packageName)}`).then((r) => r.data);

export const getImportSyncStatus = () =>
  api.get("/import/sync-status").then((r) => r.data);

export const getImportGroups = () =>
  api.get("/import/groups").then((r) => r.data);

export const deleteImportGroup = (name) =>
  api.delete(`/import/groups/${encodeURIComponent(name)}`).then((r) => r.data);

// ─── Sécurité / ClamAV ───────────────────────────────────────────────────────

export const getClamavStatus = () =>
  api.get("/security/clamav/status").then((r) => r.data);

export const getApiBaseUrl = () => API_URL;

// ─── Sécurité / CVE ──────────────────────────────────────────────────────────

export const getPackagesPosture = (distribution = null) => {
  const params = distribution ? `?distribution=${encodeURIComponent(distribution)}` : "";
  return api.get(`/security/packages-posture${params}`).then((r) => r.data);
};

export const getVulnerabilities = (filters = {}) => {
  const params = new URLSearchParams();
  if (filters.severity) params.append("severity", filters.severity);
  if (filters.fix_state) params.append("fix_state", filters.fix_state);
  if (filters.distribution) params.append("distribution", filters.distribution);
  const qs = params.toString();
  return api.get(`/security/vulnerabilities${qs ? "?" + qs : ""}`).then((r) => r.data);
};

export const getPackageCve = (name, version, arch = "x86_64") =>
  api.get(`/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/cve?arch=${arch}`)
    .then((r) => r.data);

export const quarantinePackage = (name, version, arch = "x86_64") =>
  api.post(`/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/quarantine?arch=${arch}`)
    .then((r) => r.data);

export const getReviewQueue = () =>
  api.get("/security/review-queue").then((r) => r.data);

export const submitDecision = (name, version, payload) =>
  api.post(
    `/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/decide`,
    payload
  ).then((r) => r.data);

export const checkSla = () =>
  api.post("/security/check-sla").then((r) => r.data);

export const getSecurityReport = () =>
  api.get("/security/report").then((r) => r.data);

// ─── Dashboard ───────────────────────────────────────────────────────────────

export const getDashboardStats = () =>
  api.get("/dashboard/stats").then((r) => r.data);

// ─── Distributions ───────────────────────────────────────────────────────────

export const getDistributions = () =>
  api.get("/distributions/").then((r) => r.data);

export const getDistribPackages = (codename) =>
  api.get(`/distributions/${codename}/packages`).then((r) => r.data);

export const promotePackage = (pkg, fromDist, toDist) =>
  api.post("/distributions/promote", { package: pkg, from_dist: fromDist, to_dist: toDist }).then((r) => r.data);

export const migrateDistrib = (fromDist, toDist) =>
  api.post("/distributions/migrate", { from_dist: fromDist, to_dist: toDist }).then((r) => r.data);

export const initDistributions = () =>
  api.post("/distributions/init").then((r) => r.data);

// ─── Paramètres ──────────────────────────────────────────────────────────────

// ─── Gestion des utilisateurs ─────────────────────────────────────────────────

export const getRoles = () =>
  api.get("/auth/roles").then((r) => r.data);

export const listUsers = () =>
  api.get("/auth/users").then((r) => r.data);

export const createUser = (payload) =>
  api.post("/auth/users", payload).then((r) => r.data);

export const updateUser = (username, payload) =>
  api.patch(`/auth/users/${encodeURIComponent(username)}`, payload).then((r) => r.data);

export const deleteUser = (username) =>
  api.delete(`/auth/users/${encodeURIComponent(username)}`).then((r) => r.data);

export const resetUserPassword = (username, newPassword) =>
  api.post(`/auth/users/${encodeURIComponent(username)}/reset-password`, { new_password: newPassword }).then((r) => r.data);

export const changeOwnPassword = (currentPassword, newPassword) =>
  api.post("/auth/change-password", { current_password: currentPassword, new_password: newPassword }).then((r) => r.data);

// ─── Paramètres ──────────────────────────────────────────────────────────────

export const getSettings = () =>
  api.get("/settings/").then((r) => r.data);

export const patchSettings = (partial) =>
  api.patch("/settings/", partial).then((r) => r.data);

export const testWebhook = () =>
  api.post("/settings/test-webhook").then((r) => r.data);

export const getNextSync = () =>
  api.get("/settings/next-sync").then((r) => r.data);

export const getSyncSchedule = () =>
  api.get("/import/sync-schedule").then((r) => r.data);

// ─── Audit ────────────────────────────────────────────────────────────────────
export const getAuditLogs = (params = {}) => {
  const qs = new URLSearchParams();
  if (params.limit)   qs.set("limit", params.limit);
  if (params.package) qs.set("package", params.package);
  if (params.action)  qs.set("action", params.action);
  if (params.result)  qs.set("result", params.result);
  return api.get(`/artifacts/audit/logs?${qs}`).then((r) => r.data);
};

// ─── API Tokens ───────────────────────────────────────────────────────────────
export const listApiTokens = () =>
  api.get("/auth/api-tokens").then((r) => r.data);

export const createApiToken = (payload) =>
  api.post("/auth/api-tokens", payload).then((r) => r.data);

export const revokeApiToken = (tokenId) =>
  api.delete(`/auth/api-tokens/${tokenId}`).then((r) => r.data);

// ─── GPG ──────────────────────────────────────────────────────────────────────
export const getGpgInfo = () =>
  api.get("/settings/gpg").then((r) => r.data);

export const generateGpgKey = () =>
  api.post("/settings/gpg/generate").then((r) => r.data);

export const testEmail = (toOverride = null) =>
  api.post("/settings/test-email", { to_override: toOverride }).then((r) => r.data);

export const testLdap = () =>
  api.post("/settings/test-ldap").then((r) => r.data);

export const runRetention = () =>
  api.post("/settings/run-retention").then((r) => r.data);

// ─── Health ───────────────────────────────────────────────────────────────────
export const getHealth = () =>
  api.get("/health").then((r) => r.data);

// ─── SBOM ─────────────────────────────────────────────────────────────────────

export const getSbomPreview = (format = "cyclonedx", distribution = null) => {
  const params = new URLSearchParams({ format });
  if (distribution) params.append("distribution", distribution);
  return api.get(`/sbom/preview?${params}`).then((r) => r.data);
};

export const getSbomExportUrl = (format = "cyclonedx", distribution = null) => {
  const params = new URLSearchParams({ format });
  if (distribution) params.append("distribution", distribution);
  return `${API_URL}/sbom/export?${params}`;
};

export const getSbomPackageUrl = (name, version, format = "cyclonedx", arch = "x86_64") => {
  const params = new URLSearchParams({ format, arch });
  return `${API_URL}/sbom/${encodeURIComponent(name)}/${encodeURIComponent(version)}?${params}`;
};

// ─── Statistiques de téléchargements ─────────────────────────────────────────
export const getDownloadStats = (days = 30) =>
  api.get(`/downloads/stats?days=${days}`).then((r) => r.data);

// ─── Dashboard history ────────────────────────────────────────────────────────
export const getDashboardHistory = (days = 30) =>
  api.get(`/dashboard/history?days=${days}`).then((r) => r.data);

// ─── Package decision ─────────────────────────────────────────────────────────
export const getPackageDecision = (name, version, arch = "x86_64") =>
  api.get(`/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/decision?arch=${arch}`)
    .then((r) => r.data);

export const rescanPackage = (name, version, arch = "x86_64") =>
  api.post(`/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/rescan?arch=${arch}`)
    .then((r) => r.data);
