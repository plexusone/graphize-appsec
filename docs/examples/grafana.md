# Grafana Example

This example demonstrates graphize-appsec reachability analysis on Grafana, a complex stateful web application.

## Why Grafana?

Reachability analysis becomes meaningful with **complex stateful web applications**. We chose Grafana because:

| Criteria | Grafana |
|----------|---------|
| Plugin architecture | Complex reachability paths |
| Historical CVEs | Auth bypass, SSRF, OAuth issues |
| Bug bounty | Active (Intigriti) |
| Production usage | Massive deployment base |
| Graph structure | Dashboard -> datasource -> query -> backend |

## Quick Start

### Full Analysis (Real Grafana)

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

### Quick Test (Mock Data)

For testing without cloning the full Grafana repository, use the mock data included in the `graphize-appsec` repository:

```bash
# Clone graphize-appsec
git clone https://github.com/plexusone/graphize-appsec.git
cd graphize-appsec/examples/grafana/testdata/mock-grafana

# Run analysis
graphize-appsec vex enrich \
  --sbom sbom.json \
  --vulns vulns.json \
  --verbose
```

## Test Data

### Sample Vulnerabilities

The `vulns-sample.json` file contains 8 real Grafana CVEs for testing:

| CVE | Severity | Type |
|-----|----------|------|
| CVE-2023-6152 | Medium | Email auth bypass |
| CVE-2023-3128 | Critical | Azure AD bypass |
| CVE-2023-2801 | High | SSRF in datasource |
| CVE-2022-31107 | Critical | OAuth takeover |
| CVE-2021-43798 | Critical | Directory traversal |
| CVE-2022-29170 | High | Privilege escalation |
| CVE-2023-22462 | Medium | XSS |
| GHSA-cvm3-pp2j-chr3 | Critical | Auth bypass |

### Mock Grafana Project

The `testdata/mock-grafana/` directory contains a minimal Go application simulating Grafana's structure:

```
testdata/mock-grafana/
├── main.go              # HTTP server
├── auth/auth.go         # Login, OAuth handlers
├── datasource/proxy.go  # Datasource proxy (SSRF patterns)
├── sbom.json            # Sample CycloneDX SBOM
├── vulns.json           # Sample vulnerability list
└── .graphize/           # Pre-generated code graph
```

Use this for quick testing without cloning the full Grafana repository.

## Notable CVEs for Testing

These CVEs demonstrate different reachability test results:

| CVE | Type | Key Test |
|-----|------|----------|
| CVE-2023-6152 | Email auth bypass | REACH-003 (API exposure) |
| CVE-2023-3128 | Azure AD bypass | Plugin reachability |
| CVE-2023-2801 | SSRF in datasource | REACH-002 (code paths) |
| CVE-2022-31107 | OAuth takeover | Auth flow analysis |
| CVE-2021-43798 | Directory traversal | REACH-003 (API exposure) |

## Example Output

Running the analysis on the mock project produces output like:

```
Reading SBOM from sbom.json
Analyzing 8 vulnerabilities
Loaded graph with 12 nodes and 8 edges
Analyzing CVE-2022-31107 (grafana)...
  Decision: pass (score: 2.0)
Analyzing CVE-2022-29170 (grafana)...
  Decision: pass (score: 3.0)
Analyzing CVE-2023-22462 (grafana)...
  Decision: pass (score: 0.9)
Analyzing GHSA-cvm3-pp2j-chr3 (github.com/grafana/grafana)...
  Decision: pass (score: 1.3)
Analyzing CVE-2021-43798 (grafana)...
  Decision: pass (score: 3.0)
Analyzing CVE-2023-6152 (grafana)...
  Decision: pass (score: 0.9)
Analyzing CVE-2023-3128 (grafana)...
  Decision: pass (score: 3.0)
Analyzing CVE-2023-2801 (grafana)...
  Decision: pass (score: 2.0)

VEX Enrichment Summary
======================
Original vulnerabilities:  0
Added vulnerabilities:     8
Updated vulnerabilities:   0
Total vulnerabilities:     8

VEX Analysis Results:
  Not Affected:  8
  Exploitable:   0
  In Triage:     0

Output written to: sbom-vex.json
```

## Understanding the Results

The mock project shows most vulnerabilities as "not affected" because:

1. **REACH-001 fails**: The mock doesn't actually import the vulnerable Grafana packages
2. **REACH-002 fails**: No call paths exist to vulnerable code
3. **Low scores**: Without real code paths, the weighted score stays below the 4.0 threshold

For realistic results, run against the actual Grafana codebase where:

- Package imports exist (REACH-001 passes)
- Call paths to vulnerable functions exist (REACH-002 passes)
- API endpoints reach vulnerable code (REACH-003 passes)

## References

- [Grafana Security](https://grafana.com/security/)
- [Grafana Bug Bounty](https://grafana.com/blog/introducing-the-grafana-labs-bug-bounty-program/)
- [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/)
