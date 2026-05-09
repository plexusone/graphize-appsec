# Product Requirements Document (PRD)

## graphize-appsec: Security Reachability Analysis

**Version:** 0.1.0
**Status:** Draft
**Date:** 2025-05-08

---

## Overview

graphize-appsec is a security analysis tool that performs reachability analysis using graphize's code knowledge graph. It answers: "Is this vulnerability actually exploitable in my deployment?"

---

## Architecture Context

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY ANALYSIS LAYER                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    graphize-appsec                          ││
│  │  • Reachability tests (16 tests)                           ││
│  │  • Vulnerability correlation (CVE/EPSS/KEV)                ││
│  │  • VEX generation                                          ││
│  │  • structured-evaluation reports                           ││
│  │  • MCP tools for AI assistance                             ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CODE ANALYSIS LAYER                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   graphize   │  │graphize-groovy│ │ (future)     │          │
│  │  (Go, Java,  │  │  (Groovy,    │  │ graphize-rust│          │
│  │   TS, Swift) │  │   Grails)    │  │              │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      GRAPH STORAGE LAYER                        │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                       graphfs                               ││
│  │  • Nodes, Edges, Confidence                                ││
│  │  • BFS/DFS traversal                                       ││
│  │  • Git-friendly storage                                    ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

---

## Functional Requirements

### FR-1: Reachability Test Framework

The system SHALL implement 16 reachability tests organized into 3 categories:

#### Category: Reachable (7 tests)

| ID | Test | Description | Graph Query |
|----|------|-------------|-------------|
| REACH-001 | Dependency Imported | Is vulnerable package in dependency graph? | Node exists: `pkg_{vuln_package}` |
| REACH-002 | Dependency Used | Is vulnerable code actually called? | Path exists: `entrypoint → ... → vuln_func` |
| REACH-003 | Exposed by API | Is vuln reachable from public API? | Path: `api_endpoint → ... → vuln_func` |
| REACH-004 | Direct Dependency | Is this direct (not transitive)? | Depth from root = 1 |
| REACH-005 | Public Repository | Is vuln in public repo? | Node attr: `visibility: public` |
| REACH-006 | Application Layer | Is vuln in app layer (not infra)? | Node type filtering |
| REACH-007 | Cloud Deployed | Is container with vuln running? | Edge: `deployment → container` with `status: running` |

#### Category: Exploitable (6 tests)

| ID | Test | Description | Data Source |
|----|------|-------------|-------------|
| EXPLOIT-001 | Weak Cryptography | Does path involve weak crypto? | Graph analysis |
| EXPLOIT-002 | Community Buzz | Active exploitation discussion? | External API |
| EXPLOIT-003 | Extensive Patching | Multiple patch iterations? | CVE history |
| EXPLOIT-004 | Multiple Public Exploits | Public exploits available? | Exploit-DB/Metasploit |
| EXPLOIT-005 | EPSS Low Risk | EPSS < 0.1? (inverted) | EPSS API |
| EXPLOIT-006 | AI Unexploitable | AI simulation unexploitable? | LLM analysis |

#### Category: Damage (3 tests)

| ID | Test | Description | Data Source |
|----|------|-------------|-------------|
| DAMAGE-001 | Critical Business Priority | Affects critical systems? | Config/metadata |
| DAMAGE-002 | Login Management | Affects auth/login? | Graph node attrs |
| DAMAGE-003 | CVSS High Severity | CVSS >= 7.0? | NVD/CVE DB |

### FR-2: Structured Evaluation Reports

The system SHALL generate reports using `structured-evaluation` framework:

```go
type SecurityReport struct {
    Metadata    ReportMetadata
    Vulnerability VulnerabilityInfo
    Categories  []CategoryScore    // reachable, exploitable, damage
    Tests       []TestResult       // 16 individual test results
    Decision    Decision           // PASS/CONDITIONAL/FAIL
    VEX         *VEXStatement      // Generated if applicable
    AttackPaths []AttackPath       // If reachable
}

type TestResult struct {
    ID          string             // REACH-001, EXPLOIT-002, etc.
    Name        string             // Human-readable name
    Result      bool               // Y/N
    Confidence  float64            // 0.0-1.0
    Severity    Severity           // Based on result
    Evidence    string             // What was found
    Details     map[string]any     // Additional context
}
```

### FR-3: VEX Generation

The system SHALL generate VEX statements in CycloneDX and OpenVEX formats:

```json
{
  "vulnerability": "CVE-2021-44228",
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "impact_statement": "The vulnerable logging function is not reachable from any public API endpoint.",
  "action_statement": "No action required.",
  "evidence": {
    "tests_passed": ["REACH-002", "REACH-003"],
    "attack_paths_found": 0
  }
}
```

### FR-4: CLI Interface

```bash
# Assess specific vulnerability
graphize-appsec assess <CVE-ID> [--graph .graphize] [--format json|detailed]

# Run all reachability tests
graphize-appsec test [--category reachable,exploitable,damage] [--vuln-id CVE-ID]

# Generate VEX for SBOM
graphize-appsec vex generate --sbom sbom.json --output vex.json

# Find attack paths
graphize-appsec paths --from internet --to <vuln-func-id>

# CI/CD gate
graphize-appsec gate --fail-on critical [--format junit]
```

### FR-5: MCP Tools

| Tool | Description |
|------|-------------|
| `assess_vulnerability` | Run all 16 tests for a CVE |
| `find_attack_paths` | Trace paths from entry point to vuln |
| `explain_reachability` | AI-assisted explanation |
| `generate_vex` | Create VEX statement |
| `list_vulnerabilities` | List all vulns with reachability status |

### FR-6: Vulnerability Intelligence Integration

The system SHALL integrate with:

- **OSV** (Open Source Vulnerabilities) - Primary CVE source
- **NVD** (National Vulnerability Database) - CVSS scores
- **EPSS** (Exploit Prediction Scoring System) - Exploitation probability
- **CISA KEV** (Known Exploited Vulnerabilities) - Active exploitation

---

## Non-Functional Requirements

### NFR-1: Performance

- Analyze 100K LOC repository in <5 minutes
- Individual vulnerability assessment in <10 seconds
- Support incremental analysis (only changed files)

### NFR-2: Extensibility

- Plugin architecture for custom reachability tests
- Support external language analyzers via graphize provider pattern
- Configurable severity thresholds

### NFR-3: Auditability

- All test results include evidence and reasoning
- Reports are reproducible given same inputs
- Git-friendly output formats

---

## Dependencies

| Dependency | Purpose |
|------------|---------|
| `github.com/plexusone/graphize` | Code knowledge graph |
| `github.com/plexusone/graphfs` | Graph storage/traversal |
| `github.com/plexusone/structured-evaluation` | Report framework |
| `github.com/google/osv-scanner` | Vulnerability database |

---

## Out of Scope (v0.1)

- Runtime telemetry integration (eBPF, OpenTelemetry)
- Cross-service reachability (microservice communication)
- Automated remediation
- SAST rule integration
