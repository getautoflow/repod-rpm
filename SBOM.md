# SBOM Summary — repod-rpm

Generated: 2026-05-23  
Tool: [Syft](https://github.com/anchore/syft) v1.44.0  
Format: CycloneDX JSON  
Files: see `*.sbom.cdx.json` in this repository

## Backend image (`repod-rpm-backend.sbom.cdx.json`)

- **554** named packages (4528 total entries including file paths)

### GPL v2 / Copyleft components

| Name | Version | Note |
|------|---------|------|
| `clamav` | 1.4.3+dfsg-1 | Antivirus engine — clamd socket |
| `clamav-base` | 1.4.3+dfsg-1 | Antivirus engine — clamd socket |
| `clamav-daemon` | 1.4.3+dfsg-1 | Antivirus engine — clamd socket |
| `clamav-freshclam` | 1.4.3+dfsg-1 | Antivirus engine — clamd socket |
| `createrepo-c` | 1.2.0-2+b1 | RPM repo indexing — exec |
| `libclamav12` | 1.4.3+dfsg-1 | Antivirus engine — clamd socket |
| `libcreaterepo-c1` | 1.2.0-2+b1 | RPM repo indexing — exec |
| `libdrpm0` | 0.5.2-2 | RPM tooling |
| `librpm-sequoia-1` | 1.8.0-2 | RPM library (dynamic) |
| `librpm10` | 4.20.1+dfsg-3 | RPM library (dynamic) |
| `librpmbuild10` | 4.20.1+dfsg-3 | RPM library (dynamic) |
| `librpmio10` | 4.20.1+dfsg-3 | RPM library (dynamic) |
| `librpmsign10` | 4.20.1+dfsg-3 | RPM library (dynamic) |
| `rpm` | 4.20.1+dfsg-3 | RPM querying — exec |
| `rpm-common` | 4.20.1+dfsg-3 | RPM querying — exec |
| `rpm2cpio` | 4.20.1+dfsg-3 | RPM querying — exec |

### Permissive-license highlights

| Name | Version | License | Role |
|------|---------|---------|------|
| `github.com/anchore/grype` | v0.112.0 | Apache 2.0 | CVE scanner |
| `github.com/anchore/syft` | v1.44.0 | Apache 2.0 | SBOM generator |
| `fastapi` | 0.136.1 | MIT | Backend framework |
| `python` | 3.10.20 | PSF | Runtime |

## Frontend image (`repod-rpm-frontend.sbom.cdx.json`)

- **72** named packages (1052 total entries including file paths)

### Permissive-license highlights

| Name | Version | License | Role |
|------|---------|---------|------|
| `nginx` | 1.31.1-r1 | BSD | Web server |

---

> GPL v2 components are invoked as **independent processes** (subprocess exec or Unix socket).
> They are not statically or dynamically linked against repod's Apache 2.0 code.
> Source code is available at the upstream repositories listed in [NOTICES](./NOTICES).