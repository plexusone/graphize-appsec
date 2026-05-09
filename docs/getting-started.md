# Getting Started

This guide walks you through installing graphize-appsec and running your first reachability analysis.

## Prerequisites

### Required

- **Go 1.23+** - For installation and building
- **graphize** - Code knowledge graph generation

### Recommended

- **syft** - SBOM generation (Anchore)
- **grype** - Vulnerability scanning (Anchore)
- **trivy** - Alternative SBOM/vulnerability scanner (Aqua Security)

## Installation

### Install graphize-appsec

```bash
go install github.com/plexusone/graphize-appsec/cmd/graphize-appsec@latest
```

### Install graphize (required)

```bash
go install github.com/plexusone/graphize/cmd/graphize@latest
```

### Install SBOM Tools (recommended)

=== "Homebrew (macOS/Linux)"

    ```bash
    brew install syft grype
    ```

=== "Go Install"

    ```bash
    go install github.com/anchore/syft/cmd/syft@latest
    go install github.com/anchore/grype/cmd/grype@latest
    ```

## Verify Installation

Run the doctor command to check your environment:

```bash
graphize-appsec doctor
```

Expected output:

```
graphize-appsec environment check
==================================

Tools:
  ✓ graphize        v0.3.0
  ✓ syft            syft 1.18.1
  ✓ grype           grype 0.86.1
  ○ trivy           not found (optional)

Current directory:
  ○ .graphize/      not found
                    Run: graphize init && graphize add . && graphize analyze

✓  Environment looks good!
```

## Quick Workflow

### 1. Build the Code Graph

First, initialize graphize and analyze your codebase:

```bash
# Initialize graph database
graphize init

# Track the current repository
graphize add .

# Extract AST-based graph
graphize analyze
```

### 2. Generate SBOM

Use Syft to generate a CycloneDX SBOM:

```bash
syft . -o cyclonedx-json > sbom.json
```

### 3. Scan for Vulnerabilities

Use Grype to scan the SBOM for vulnerabilities:

```bash
grype sbom:sbom.json -o json > vulns.json
```

### 4. Run Reachability Analysis

Enrich the SBOM with VEX analysis:

```bash
graphize-appsec vex enrich \
  --sbom sbom.json \
  --vulns vulns.json \
  --output sbom-vex.json \
  --verbose
```

### 5. Review Results

The enriched SBOM (`sbom-vex.json`) now contains VEX analysis for each vulnerability, showing:

- **not_affected** - Vulnerable code is not reachable
- **in_triage** - Needs manual review
- **exploitable** - Vulnerable code is reachable and exploitable

## Example: Grafana Analysis

For a complete worked example, see the [Grafana Example](examples/grafana.md). It demonstrates:

1. Analyzing a complex Go codebase
2. Understanding test results
3. Interpreting VEX output

Quick test with mock data:

```bash
# Clone graphize-appsec
git clone https://github.com/plexusone/graphize-appsec.git
cd graphize-appsec

# Use the mock Grafana project
cd examples/grafana/testdata/mock-grafana

# Run analysis
graphize-appsec vex enrich \
  --sbom sbom.json \
  --vulns vulns.json \
  --verbose
```

## What's Next?

- [CLI Reference](cli/reference.md) - Learn all available commands and options
- [Reachability Tests](reference/reachability-tests.md) - Understand the 16 tests
- [VEX Output](reference/vex-output.md) - Learn about VEX format and properties
- [SBOM Governance](guides/sbom-governance.md) - Best practices for SBOM workflows
