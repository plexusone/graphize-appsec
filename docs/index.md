# Graphize-AppSec

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

- **16 Reachability Tests** - Systematic assessment across Reachable, Exploitable, and Damage categories
- **VEX Generation** - CycloneDX VEX statements for non-exploitable vulnerabilities
- **SBOM Enrichment** - Enrich existing SBOMs with exploitability context
- **Graph-Based Analysis** - Leverages graphize's code knowledge graph for path finding
- **Structured Reports** - Machine-readable reports via structured-evaluation

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

See the [Getting Started](getting-started.md) guide for detailed setup instructions.

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

## Dependencies

| Package | Purpose |
|---------|---------|
| [graphize](https://github.com/plexusone/graphize) | Produces code knowledge graph |
| [graphfs](https://github.com/plexusone/graphfs) | Graph storage and traversal |
| [structured-evaluation](https://github.com/plexusone/structured-evaluation) | Report generation |
| [cyclonedx-go](https://github.com/CycloneDX/cyclonedx-go) | VEX/SBOM format |

## Documentation

- [Getting Started](getting-started.md) - Installation and first run
- [CLI Reference](cli/reference.md) - All commands and options
- [Reachability Tests](reference/reachability-tests.md) - The 16 tests explained
- [VEX Output](reference/vex-output.md) - VEX format and properties
- [SBOM Governance](guides/sbom-governance.md) - Best practices guide

## Related Projects

- [graphize](https://github.com/plexusone/graphize) - Code knowledge graph builder
- [graphize-grafana](https://github.com/plexusone/graphize-grafana) - Example implementation
