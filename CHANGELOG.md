# Changelog — Repod RPM Community Edition

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org/).

---

## [1.0.0] — 2026-05-24

### Added
- **RPM repository hosting** — AlmaLinux 8/9, Rocky Linux 8/9, CentOS Stream 9, Oracle Linux 8, Fedora 42, openSUSE Leap 15.6, openSUSE Tumbleweed (9 distributions)
- **Multi-architecture support** — x86_64, aarch64, noarch, i686
- **Package upload** — REST API (`POST /upload/`) and drag-and-drop web UI; `.rpm` validated with `rpm -qip` before acceptance
- **Antivirus scan** — ClamAV on every uploaded package; quarantine on positive detection
- **CVE analysis** — Grype with CVSS v3 scoring; per-package vulnerability report
- **EPSS enrichment** — exploit-probability scores from FIRST.org (24 h local cache)
- **CISA KEV cross-reference** — flags vulnerabilities actively exploited in the wild
- **GPG auto-signing** — detached signature on `repomd.xml.asc`; key generated on first start
- **CISO approval queue** — dual-control workflow; packages held until explicit approval (Enterprise)
- **Immutable audit trail** — JSONL append-only log; JSON and CSV export
- **RBAC** — 5 roles (admin, maintainer, developer, viewer, readonly) with per-distribution scoping
- **LDAP / Active Directory** — integration via `ldap3`
- **OIDC / SSO** — OpenID Connect with PKCE
- **MFA / TOTP** — authenticator-app second factor
- **SBOM export** — SPDX 2.3 and CycloneDX 1.5
- **SARIF 2.1.0 export** — compatible with GitHub Code Scanning and SonarQube
- **NIS2 Article 21 compliance mode** — enforces dual-control, audit trail, and SBOM on every upload
- **Email & webhook notifications** — on new uploads, CVE threshold crossings, and CISO decisions
- **Air-gap support** — fully offline after initial CVE database pull
- **Full web dashboard** — React + Tailwind; package table, KPI cards, review queue, CVE report, audit log
- **Health endpoints** — `/health`, `/health/live`, `/health/ready` (no auth required)
- **LVM production storage** — `scripts/setup-storage.sh` provisions 14 logical volumes for distros + infra

### Security
- Authentication required on all API endpoints except health probes
- JWT secret validated at startup — hard failure in production mode if default value detected
- Rate limiting on authentication endpoints (configurable via `AUTH_RATELIMIT_PER_MINUTE`)
- No telemetry — no data leaves your infrastructure
- `.gnupg` and `backend.env` excluded from version control via `.gitignore`

---

<!-- next release notes go above this line -->
