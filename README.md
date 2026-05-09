# Graphize-AppSec

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Guide][docs-mkdocs-svg]][docs-mkdocs-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/plexusone/graphize-appsec/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/plexusone/graphize-appsec/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/plexusone/graphize-appsec/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/plexusone/graphize-appsec/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/plexusone/graphize-appsec/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/plexusone/graphize-appsec/actions/workflows/go-sast-codeql.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/plexusone/graphize-appsec
 [goreport-url]: https://goreportcard.com/report/github.com/plexusone/graphize-appsec
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/plexusone/graphize-appsec
 [docs-godoc-url]: https://pkg.go.dev/github.com/plexusone/graphize-appsec
 [docs-mkdocs-svg]: https://img.shields.io/badge/docs-mkdocs-blue.svg
 [docs-mkdocs-url]: https://plexusone.github.io/graphize-appsec
 [viz-svg]: https://img.shields.io/badge/Go-visualizaton-blue.svg
 [viz-url]: https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=plexusone%2Fgraphize-appsec
 [loc-svg]: https://tokei.rs/b1/github/plexusone/graphize-appsec
 [repo-url]: https://github.com/plexusone/graphize-appsec
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/plexusone/graphize-appsec/blob/main/LICENSE

Security reachability analysis using [graphize](https://github.com/plexusone/graphize) code knowledge graphs.

Answers the question: **"Is this vulnerability actually exploitable in my deployment?"**

## Overview

Graphize-AppSec performs reachability analysis to reduce vulnerability noise by 90%+. Instead of alerting on every CVE in your dependency tree, it determines which vulnerabilities are actually reachable from your code's entry points.

This is **whitebox analysis** - it requires source code access to build precise call graphs and trace execution paths. Unlike blackbox scanning (which only sees external behavior), whitebox analysis can definitively prove when vulnerable code is unreachable.

```
SBOM Scanner Output     graphize-appsec          Actionable Results
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ 847 CVEs found   │ -> │ Reachability     │ -> │ 12 exploitable   │
│ (97% false pos)  │    │ Analysis         │    │ 835 not affected │
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

## Features

- 🔬 **16 Reachability Tests** - Systematic assessment across Reachable, Exploitable, and Damage categories
- 📋 **VEX Generation** - CycloneDX VEX statements for non-exploitable vulnerabilities
- 📦 **SBOM Enrichment** - Enrich existing SBOMs with exploitability context
- 🕸️ **Graph-Based Analysis** - Leverages graphize's code knowledge graph for path finding
- 📊 **Structured Reports** - Machine-readable reports via structured-evaluation

## Installation

```bash
go install github.com/plexusone/graphize-appsec/cmd/graphize-appsec@latest
```

## Quick Start

```bash
# 1. Build code graph with graphize
graphize init
graphize add .
graphize analyze

# 2. Generate SBOM (using Syft, Trivy, or similar)
syft . -o cyclonedx-json > sbom.json

# 3. Get vulnerability list (using Grype or similar)
grype sbom:sbom.json -o json > vulns.json

# 4. Enrich SBOM with reachability analysis
graphize-appsec vex enrich \
  --sbom sbom.json \
  --vulns vulns.json \
  --output sbom-vex.json
```

## Reachability Tests

### Category: Reachable (7 tests)

| ID | Test | Question |
|----|------|----------|
| REACH-001 | Dependency Imported | Is vulnerable package in dependency graph? |
| REACH-002 | Dependency Used | Is vulnerable code actually called? |
| REACH-003 | Exposed by API | Is vuln reachable from public API? |
| REACH-004 | Direct Dependency | Is this direct (not transitive)? |
| REACH-005 | Public Repository | Is vuln in public repo? |
| REACH-006 | Application Layer | Is vuln in app layer (not infra)? |
| REACH-007 | Cloud Deployed | Is container with vuln running? |

### Category: Exploitable (6 tests)

| ID | Test | Question |
|----|------|----------|
| EXPLOIT-001 | Weak Cryptography | Does path involve weak crypto? |
| EXPLOIT-002 | Community Buzz | Active exploitation discussion? |
| EXPLOIT-003 | Extensive Patching | Multiple patch iterations? |
| EXPLOIT-004 | Multiple Public Exploits | Public exploits available? |
| EXPLOIT-005 | EPSS Low Risk | EPSS score < 0.1? |
| EXPLOIT-006 | AI Unexploitable | AI analysis says unexploitable? |

### Category: Damage (3 tests)

| ID | Test | Question |
|----|------|----------|
| DAMAGE-001 | Critical Business Priority | Affects critical systems? |
| DAMAGE-002 | Login Management | Affects auth/login? |
| DAMAGE-003 | CVSS High Severity | CVSS >= 7.0? |

## VEX Output

For vulnerabilities determined to be non-exploitable, graphize-appsec generates VEX statements:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "No call path from public API to vulnerable JNDI lookup function.",
        "response": ["will_not_fix"]
      }
    }
  ]
}
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   graphize-appsec                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │ Reachable   │  │ Exploitable │  │   Damage    │  │
│  │  (7 tests)  │  │  (6 tests)  │  │  (3 tests)  │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │
│         └────────────────┼────────────────┘         │
│                          ▼                          │
│                  ┌───────────────┐                  │
│                  │  VEX/Report   │                  │
│                  │   Generator   │                  │
│                  └───────────────┘                  │
└─────────────────────────┬───────────────────────────┘
                          │
            ┌─────────────┴─────────────┐
            ▼                           ▼
    ┌───────────────┐           ┌───────────────┐
    │   graphize    │           │    graphfs    │
    │ (code graph)  │           │  (traversal)  │
    └───────────────┘           └───────────────┘
```

## CLI Commands

```bash
# Check environment prerequisites
graphize-appsec doctor

# Assess a specific vulnerability
graphize-appsec assess CVE-2021-44228

# List available reachability tests
graphize-appsec test list

# Generate VEX from SBOM + vulnerabilities
graphize-appsec vex enrich --sbom sbom.json --vulns vulns.json

# Generate standalone VEX document
graphize-appsec vex generate --vulns vulns.json
```

## Dependencies

| Package | Purpose |
|---------|---------|
| [graphize](https://github.com/plexusone/graphize) | Produces code knowledge graph |
| [graphfs](https://github.com/plexusone/graphfs) | Graph storage and traversal |
| [structured-evaluation](https://github.com/plexusone/structured-evaluation) | Report generation |
| [cyclonedx-go](https://github.com/CycloneDX/cyclonedx-go) | VEX/SBOM format |

## Documentation

**[Full Documentation](https://plexusone.github.io/graphize-appsec)** | [Getting Started](https://plexusone.github.io/graphize-appsec/getting-started/) | [CLI Reference](https://plexusone.github.io/graphize-appsec/cli/reference/)

- [Getting Started Guide](docs/getting-started.md) - Installation and quick workflow
- [CLI Reference](docs/cli/reference.md) - All commands, flags, and examples
- [Reachability Tests Reference](docs/reference/reachability-tests.md) - All 16 tests documented
- [VEX Output Reference](docs/reference/vex-output.md) - CycloneDX VEX format
- [SBOM Governance Best Practices](docs/guides/sbom-governance.md)
- [Parser Landscape](docs/architecture/parser-landscape.md)
- [Design Documents](docs/design/core/)

## Related Projects

- [graphize](https://github.com/plexusone/graphize) - Code knowledge graph builder
- [graphize-grafana](https://github.com/plexusone/graphize-grafana) - Example implementation

## License

MIT
