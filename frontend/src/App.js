import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import LoginPage from "./pages/LoginPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";
import OidcCallbackPage from "./pages/OidcCallbackPage";
import HealthPage from "./pages/HealthPage";
import DownloadStatsPage from "./pages/DownloadStatsPage";
import SbomPage from "./pages/SbomPage";
import SsoPage from "./pages/SsoPage";
import DashboardLayout from "./layouts/DashboardLayout";
import PackageList from "./components/PackageList";
import UploadForm from "./components/UploadForm";
import ClientSetupPage from "./pages/ClientSetupPage";
import ImportPage from "./pages/ImportPage";
import SecurityPage from "./pages/SecurityPage";
import DashboardPage from "./pages/DashboardPage";
import DistributionsPage from "./pages/DistributionsPage";
import SettingsPage from "./pages/SettingsPage";
import UsersPage from "./pages/UsersPage";
import SecurityReportPage from "./pages/SecurityReportPage";
import AuditPage from "./pages/AuditPage";

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster position="top-right" toastOptions={{ duration: 4000 }} />
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          <Route path="/oidc-callback" element={<OidcCallbackPage />} />
          <Route path="/security/report" element={
            <ProtectedRoute><SecurityReportPage /></ProtectedRoute>
          } />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <DashboardLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<DashboardPage />} />
            <Route path="packages" element={<PackageList />} />
            <Route path="upload" element={<UploadForm />} />
            <Route path="setup" element={<ClientSetupPage />} />
            <Route path="import" element={<ImportPage />} />
            <Route path="security" element={<SecurityPage />} />
            <Route path="distributions" element={<DistributionsPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="users"     element={<UsersPage />} />
            <Route path="audit"     element={<AuditPage />} />
            <Route path="health"    element={<HealthPage />} />
            <Route path="downloads" element={<DownloadStatsPage />} />
            <Route path="sbom"      element={<SbomPage />} />
            <Route path="sso"       element={<SsoPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
