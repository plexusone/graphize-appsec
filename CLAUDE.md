# CLAUDE.md

Instructions for Claude Code when working on graphize-appsec.

## Project Overview

graphize-appsec is a security analysis tool that performs reachability analysis using graphize's code knowledge graph. It answers: "Is this vulnerability actually exploitable in my deployment?"

## Architecture

```
graphize-appsec (this project)
    │
    ├── Uses graphize for code knowledge graph
    ├── Uses graphfs for graph storage/traversal
    └── Uses structured-evaluation for reports
```

## Build & Test

```bash
# Build
go build ./...

# Test
go test -v ./...

# Run CLI
go run ./cmd/graphize-appsec <command>
```

## Package Structure

```
pkg/
├── reachability/       # Test framework
│   ├── test.go         # Test interface
│   ├── runner.go       # Test orchestrator
│   ├── context.go      # Evaluation context
│   ├── reachable/      # Reachable category tests
│   ├── exploitable/    # Exploitable category tests
│   └── damage/         # Damage category tests
├── vuln/               # Vulnerability intelligence
├── vex/                # VEX generation
├── report/             # structured-evaluation integration
├── graph/              # Graph query utilities
└── mcp/                # MCP server tools
```

## Reachability Tests

### Category: Reachable (7 tests)

| ID | Test | Description |
|----|------|-------------|
| REACH-001 | Dependency Imported | Is vulnerable package in dependency graph? |
| REACH-002 | Dependency Used | Is vulnerable code actually called? |
| REACH-003 | Exposed by API | Is vuln reachable from public API? |
| REACH-004 | Direct Dependency | Is this direct (not transitive)? |
| REACH-005 | Public Repository | Is vuln in public repo? |
| REACH-006 | Application Layer | Is vuln in app layer (not infra)? |
| REACH-007 | Cloud Deployed | Is container with vuln running? |

### Category: Exploitable (6 tests)

| ID | Test | Description |
|----|------|-------------|
| EXPLOIT-001 | Weak Cryptography | Does path involve weak crypto? |
| EXPLOIT-002 | Community Buzz | Active exploitation discussion? |
| EXPLOIT-003 | Extensive Patching | Multiple patch iterations? |
| EXPLOIT-004 | Multiple Public Exploits | Public exploits available? |
| EXPLOIT-005 | EPSS Low Risk | EPSS < 0.1? (inverted - Y = safe) |
| EXPLOIT-006 | AI Unexploitable | AI simulation unexploitable? |

### Category: Damage (3 tests)

| ID | Test | Description |
|----|------|-------------|
| DAMAGE-001 | Critical Business Priority | Affects critical systems? |
| DAMAGE-002 | Login Management | Affects auth/login? |
| DAMAGE-003 | CVSS High Severity | CVSS >= 7.0? |

## Test Result Convention

Each test returns:

- **Pass**: Boolean (Y/N) - whether the condition is TRUE
- **Confidence**: 0.0-1.0 - certainty of the result
- **Severity**: Based on what the result means for security
- **Evidence**: Human-readable explanation

For "risk exists" tests (REACH-001, REACH-002, etc.):

- Pass=true means risk EXISTS (vulnerability is reachable)
- Pass=false means risk does NOT exist (safe)

For "risk mitigated" tests (EXPLOIT-005, EXPLOIT-006):

- Pass=true means risk is MITIGATED (EPSS low, AI says unexploitable)
- Pass=false means risk is NOT mitigated

## CLI Commands

```bash
# Assess specific vulnerability
graphize-appsec assess <CVE-ID> [--graph .graphize]

# Run specific tests
graphize-appsec test [--category reachable,exploitable]

# Generate VEX
graphize-appsec vex generate --sbom sbom.json

# CI/CD gate
graphize-appsec gate --fail-on critical
```

## Dependencies

- graphize: Code knowledge graph building
- graphfs: Graph storage and traversal (BFS, DFS, paths)
- structured-evaluation: Report generation framework

## Design Documents

See `docs/design/core/` for:

- MRD.md - Market requirements
- PRD.md - Product requirements
- TRD.md - Technical architecture
- PLAN.md - Implementation plan
- TASKS.md - Task breakdown
