# CLI Reference

Complete reference for all graphize-appsec commands.

## Global Flags

These flags are available on all commands:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--graph` | `-g` | `.graphize` | Path to graphize graph directory |
| `--format` | `-f` | `detailed` | Output format: `json`, `detailed`, `summary` |
| `--verbose` | `-v` | `false` | Enable verbose output |

## Commands

### graphize-appsec

Root command for the CLI.

```bash
graphize-appsec [command] [flags]
```

```
graphize-appsec performs reachability analysis
using graphize's code knowledge graph. It answers the question:
"Is this vulnerability actually exploitable in my deployment?"

The tool runs a series of tests across three categories:
  - Reachable: Is the vulnerable code actually reachable?
  - Exploitable: Is the vulnerability exploitable in practice?
  - Damage: What is the potential damage if exploited?

Each test returns a Y/N result with evidence and confidence level.
```

---

### assess

Assess a vulnerability for reachability and exploitability.

```bash
graphize-appsec assess <vulnerability-id> [flags]
```

Runs all reachability tests and generates a structured report showing:

- Whether each test passed or failed
- Confidence level of each result
- Evidence and attack paths found
- Overall decision (PASS/CONDITIONAL/FAIL)

#### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--package` | `-p` | | Affected package name or purl |
| `--function` | | | Affected function ID |
| `--category` | `-c` | | Categories to test: `reachable`, `exploitable`, `damage` |

#### Examples

```bash
# Assess a CVE
graphize-appsec assess CVE-2021-44228

# Assess with specific package
graphize-appsec assess CVE-2021-44228 --package log4j-core

# Output as JSON
graphize-appsec assess CVE-2021-44228 --format json

# Only run reachable tests
graphize-appsec assess CVE-2021-44228 --category reachable

# Run multiple categories
graphize-appsec assess CVE-2021-44228 --category reachable,exploitable
```

#### Output Formats

**Detailed (default)**

```
=======================================================================
 Security Reachability Assessment: CVE-2021-44228
=======================================================================

Category Scores:
-----------------------------------------------------------------------
  reachable      : 5.2/10 (weight: 40%)  3/7 reachability tests indicate exposure
  exploitable    : 2.1/10 (weight: 35%)  1/6 exploitability tests indicate risk
  damage         : 7.5/10 (weight: 25%)  2/3 damage indicators present

REACHABLE Tests:
-----------------------------------------------------------------------
  [Y] REACH-001  Dependency Imported     (conf: 100%)
              Package log4j-core is imported in the codebase
  [N] REACH-002  Dependency Used         (conf: 85%)
              No call path found to vulnerable code from 5 entry points
...

=======================================================================
 Decision: CONDITIONAL  |  Score: 4.5/10  |  Duration: 125ms
=======================================================================
```

**Summary**

```
CVE-2021-44228: CONDITIONAL (score: 4.5/10)
Tests: 8 passed, 8 failed, 0 errors
```

**JSON**

```json
{
  "results": [...],
  "by_category": {...},
  "category_scores": {...},
  "pass_count": 8,
  "fail_count": 8
}
```

---

### doctor

Check environment prerequisites for graphize-appsec.

```bash
graphize-appsec doctor
```

Checks that all required and recommended tools are installed:

- **Required**: graphize (code knowledge graph generation)
- **Recommended**: syft, grype, trivy (SBOM and vulnerability scanning)

Also checks if the current directory has a `.graphize/` directory.

#### Example Output

```
graphize-appsec environment check
==================================

Tools:
  ✓ graphize        v0.3.0
  ✓ syft            syft 1.18.1
  ✓ grype           grype 0.86.1
  ○ trivy           not found (optional)
    Install: brew install trivy  # or: go install github.com/aquasecurity/trivy/cmd/trivy@latest

Current directory:
  ✓ .graphize/      found
  ✓ manifest.json   found

✓  Environment looks good!
```

---

### vex

Parent command for VEX-related operations.

```bash
graphize-appsec vex [command] [flags]
```

VEX documents communicate whether vulnerabilities are actually exploitable
in a specific deployment context. graphize-appsec uses code knowledge graphs
to determine reachability and produces standards-compliant VEX output.

#### Common Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--tool-name` | `graphize-appsec` | Tool name for VEX metadata |
| `--tool-version` | `0.1.0` | Tool version for VEX metadata |
| `--tool-vendor` | `PlexusOne` | Tool vendor for VEX metadata |

---

### vex enrich

Enrich an SBOM with VEX analysis from reachability tests.

```bash
graphize-appsec vex enrich [flags]
```

This command:

1. Reads an existing CycloneDX SBOM
2. Reads vulnerability scan results (from grype, trivy, etc.)
3. Runs reachability tests against the code knowledge graph
4. Adds VEX analysis to the SBOM showing which vulns are actually exploitable
5. Outputs the enriched SBOM

#### Flags

| Flag | Short | Required | Default | Description |
|------|-------|----------|---------|-------------|
| `--sbom` | `-s` | Yes | | Path to input CycloneDX SBOM |
| `--vulns` | `-V` | No | | Path to vulnerability scan results (JSON) |
| `--output` | `-o` | No | `<sbom>-vex.json` | Output path |

#### Examples

```bash
# Basic enrichment
graphize-appsec vex enrich --sbom sbom.json --vulns vulns.json

# Output to specific file
graphize-appsec vex enrich --sbom sbom.json --vulns vulns.json -o enriched-sbom.json

# With custom tool metadata
graphize-appsec vex enrich --sbom sbom.json --vulns vulns.json \
  --tool-name "my-scanner" --tool-version "1.0.0"

# Verbose output
graphize-appsec vex enrich --sbom sbom.json --vulns vulns.json -v
```

#### Example Output

```
Reading SBOM from sbom.json
Analyzing 8 vulnerabilities
Loaded graph with 245 nodes and 512 edges
Analyzing CVE-2022-31107 (grafana)...
  Decision: pass (score: 2.0)
Analyzing CVE-2023-6152 (grafana)...
  Decision: pass (score: 0.9)
...

VEX Enrichment Summary
======================
Original vulnerabilities:  0
Added vulnerabilities:     8
Updated vulnerabilities:   0
Total vulnerabilities:     8

VEX Analysis Results:
  Not Affected:  6
  Exploitable:   1
  In Triage:     1

Output written to: sbom-vex.json
```

---

### vex generate

Generate a standalone VEX document from reachability analysis.

```bash
graphize-appsec vex generate [CVE-IDs...] [flags]
```

Creates a VEX-only BOM (no components, just vulnerabilities with analysis)
that can be used alongside an existing SBOM for vulnerability communication.

#### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--vulns` | `-V` | | Path to vulnerability scan results (JSON) |
| `--output` | `-o` | stdout | Output path |

#### Examples

```bash
# Generate VEX from vulnerability list
graphize-appsec vex generate --vulns vulns.json -o vex.json

# Generate VEX for specific CVEs
graphize-appsec vex generate CVE-2023-1234 CVE-2023-5678 -o vex.json

# Output to stdout
graphize-appsec vex generate --vulns vulns.json
```

---

### test list

List available reachability tests.

```bash
graphize-appsec test list [flags]
```

Displays all registered reachability tests organized by category.

#### Examples

```bash
# List all tests
graphize-appsec test list

# List with descriptions
graphize-appsec test list -v
```

#### Example Output

```
Available Tests: 16

reachable:
  REACH-001     Dependency Imported
  REACH-002     Dependency Used
  REACH-003     Exposed by API
  REACH-004     Direct Dependency
  REACH-005     Public Repository
  REACH-006     Application Layer
  REACH-007     Cloud Deployed

exploitable:
  EXPLOIT-001   Weak Cryptography
  EXPLOIT-002   Community Buzz
  EXPLOIT-003   Extensive Patching
  EXPLOIT-004   Multiple Public Exploits
  EXPLOIT-005   EPSS Low Exploit Risk
  EXPLOIT-006   AI Unexploitable

damage:
  DAMAGE-001    Critical Business Priority
  DAMAGE-002    Login Management
  DAMAGE-003    CVSS High Severity

Summary:
  reachable      : 7 tests
  exploitable    : 6 tests
  damage         : 3 tests
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (failed to run, invalid input, etc.) |

## Environment Variables

graphize-appsec respects standard Go environment variables. There are currently no tool-specific environment variables.
