# Grafana Example

Example of graphize-appsec reachability analysis on Grafana.

## Why Grafana?

Reachability analysis becomes meaningful with **complex stateful web applications**. We chose Grafana because:

| Criteria | Grafana |
|----------|---------|
| Plugin architecture | ✅ Complex reachability paths |
| Historical CVEs | ✅ Auth bypass, SSRF, OAuth issues |
| Bug bounty | ✅ Active (Intigriti) |
| Production usage | ✅ Massive deployment base |
| Graph structure | ✅ Dashboard → datasource → query → backend |

## Quick Start

```bash
# Check prerequisites
graphize-appsec doctor

# Clone Grafana
git clone --depth 1 https://github.com/grafana/grafana.git
cd grafana

# Build code graph
graphize init
graphize add .
graphize analyze

# Generate SBOM
syft . -o cyclonedx-json > sbom.json

# Scan for vulnerabilities
grype sbom:sbom.json -o json > vulns.json

# Run reachability analysis
graphize-appsec vex enrich --sbom sbom.json --vulns vulns.json -v
```

## Sample Data

This directory contains sample data for testing without running full scans:

- `vulns-sample.json` - 8 real Grafana CVEs
- `sbom-sample.json` - Sample SBOM structure

## Test Data

`testdata/mock-grafana/` contains a minimal Go app simulating Grafana's structure:

```
testdata/mock-grafana/
├── main.go              # HTTP server
├── auth/auth.go         # Login, OAuth handlers
├── datasource/proxy.go  # Datasource proxy (SSRF patterns)
└── .graphize/           # Pre-generated code graph
```

Use this for quick testing without cloning full Grafana.

## Notable CVEs for Testing

| CVE | Type | Reachability Test |
|-----|------|-------------------|
| CVE-2023-6152 | Email auth bypass | REACH-003 (API exposure) |
| CVE-2023-3128 | Azure AD bypass | Plugin reachability |
| CVE-2023-2801 | SSRF in datasource | REACH-002 (code paths) |
| CVE-2022-31107 | OAuth takeover | Auth flow analysis |
| CVE-2021-43798 | Directory traversal | REACH-003 (API exposure) |

## References

- [Grafana Security](https://grafana.com/security/)
- [Grafana Bug Bounty](https://grafana.com/blog/introducing-the-grafana-labs-bug-bounty-program/)
- [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/)
