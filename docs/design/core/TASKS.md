# Task Breakdown

## graphize-appsec: Detailed Task List

**Version:** 0.1.0
**Status:** Draft
**Date:** 2025-05-08

---

## Legend

- **Priority:** P0 (critical), P1 (high), P2 (medium), P3 (low)
- **Status:** ⬜ Not started, 🟡 In progress, ✅ Done, ❌ Blocked

---

## Phase 0: graphize Enhancements

### 0.1 External Analyzer Interface

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| G-001 | Define `ExternalExtractor` interface | P0 | ⬜ | In graphize repo |
| G-002 | Implement JSON-over-stdio protocol | P0 | ⬜ | For subprocess communication |
| G-003 | Add external extractor config loading | P1 | ⬜ | YAML config file |
| G-004 | Update `MultiExtractor` to use external | P0 | ⬜ | Integration point |
| G-005 | Document external analyzer protocol | P1 | ⬜ | For graphize-groovy |

### 0.2 Security Node Attributes

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| G-010 | Define standard security attributes | P0 | ⬜ | `is_entrypoint`, `requires_auth`, etc. |
| G-011 | Update Go extractor for entry points | P1 | ⬜ | Detect `main`, HTTP handlers |
| G-012 | Update Java extractor for Spring handlers | P1 | ⬜ | `@RequestMapping`, etc. |
| G-013 | Add framework layer detection | P1 | ⬜ | controller, service, repository |

### 0.3 SBOM Adapter

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| G-020 | Define `SBOMAdapter` interface | P0 | ⬜ | |
| G-021 | Implement CycloneDX adapter | P0 | ⬜ | JSON and XML |
| G-022 | Implement SPDX adapter | P2 | ⬜ | JSON only |
| G-023 | Add purl normalization | P1 | ⬜ | Canonical package IDs |
| G-024 | Correlate SBOM with code graph | P1 | ⬜ | Match imports to packages |

### 0.4 Kubernetes Adapter

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| G-030 | Define `K8sAdapter` interface | P1 | ⬜ | |
| G-031 | Implement deployment discovery | P1 | ⬜ | List pods, deployments |
| G-032 | Implement ingress mapping | P1 | ⬜ | Internet exposure |
| G-033 | Correlate containers with graph | P2 | ⬜ | Image → package mapping |

---

## Phase 1: Core Framework

### 1.1 Project Setup

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| A-001 | Create go.mod | P0 | ⬜ | Dependencies on graphize, graphfs, structured-evaluation |
| A-002 | Create package structure | P0 | ⬜ | Per TRD layout |
| A-003 | Set up GitHub Actions CI | P1 | ⬜ | Lint, test, build |
| A-004 | Create README.md | P1 | ⬜ | |
| A-005 | Create CLAUDE.md | P1 | ⬜ | Project-specific instructions |

### 1.2 Test Framework

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| A-010 | Define `Test` interface | P0 | ⬜ | `pkg/reachability/test.go` |
| A-011 | Define `TestResult` struct | P0 | ⬜ | Y/N + evidence |
| A-012 | Define `EvalContext` struct | P0 | ⬜ | Graph + vuln + config |
| A-013 | Define `Category` type | P0 | ⬜ | reachable, exploitable, damage |
| A-014 | Implement test registry | P0 | ⬜ | Register/lookup tests |
| A-015 | Implement `TestRunner` | P0 | ⬜ | Orchestrate test execution |
| A-016 | Add test runner unit tests | P1 | ⬜ | |

### 1.3 Graph Query Layer

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| A-020 | Create graph query wrapper | P0 | ⬜ | `pkg/graph/query.go` |
| A-021 | Implement node filtering | P0 | ⬜ | By type, attrs |
| A-022 | Implement path reconstruction | P0 | ⬜ | From TraversalResult |
| A-023 | Implement entry point detection | P0 | ⬜ | Main, handlers, etc. |
| A-024 | Add attack path type | P1 | ⬜ | Structured path representation |
| A-025 | Add graph query tests | P1 | ⬜ | Mock graphs |

---

## Phase 2: Reachability Tests

### 2.1 Category: Reachable

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| R-001 | REACH-001: Dependency Imported | P0 | ⬜ | Check if package in graph |
| R-002 | REACH-002: Dependency Used | P0 | ⬜ | BFS from entry to vuln |
| R-003 | REACH-003: Exposed by API | P0 | ⬜ | Path from API handler |
| R-004 | REACH-004: Direct Dependency | P1 | ⬜ | Depth = 1 from root |
| R-005 | REACH-005: Public Repository | P2 | ⬜ | Node attr check |
| R-006 | REACH-006: Application Layer | P2 | ⬜ | Not infra package |
| R-007 | REACH-007: Cloud Deployed | P1 | ⬜ | K8s deployment status |
| R-008 | Unit tests for reachable tests | P1 | ⬜ | |

### 2.2 Category: Exploitable

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| E-001 | EXPLOIT-001: Weak Cryptography | P2 | ⬜ | Check crypto calls in path |
| E-002 | EXPLOIT-002: Community Buzz | P2 | ⬜ | External API check |
| E-003 | EXPLOIT-003: Extensive Patching | P2 | ⬜ | CVE history |
| E-004 | EXPLOIT-004: Multiple Public Exploits | P1 | ⬜ | Exploit-DB check |
| E-005 | EXPLOIT-005: EPSS Low Risk | P0 | ⬜ | EPSS API |
| E-006 | EXPLOIT-006: AI Unexploitable | P3 | ⬜ | LLM analysis |
| E-007 | Unit tests for exploitable tests | P1 | ⬜ | |

### 2.3 Category: Damage

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| D-001 | DAMAGE-001: Critical Business Priority | P1 | ⬜ | Config lookup |
| D-002 | DAMAGE-002: Login Management | P1 | ⬜ | Auth function detection |
| D-003 | DAMAGE-003: CVSS High Severity | P0 | ⬜ | NVD lookup |
| D-004 | Unit tests for damage tests | P1 | ⬜ | |

---

## Phase 3: Vulnerability Intelligence

### 3.1 Client Interface

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| V-001 | Define `VulnerabilityClient` interface | P0 | ⬜ | |
| V-002 | Define `Vulnerability` struct | P0 | ⬜ | |
| V-003 | Define `CVSSScore` struct | P0 | ⬜ | |
| V-004 | Define `EPSSScore` struct | P0 | ⬜ | |

### 3.2 OSV Client

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| V-010 | Implement OSV API client | P0 | ⬜ | |
| V-011 | Implement package → vuln lookup | P0 | ⬜ | |
| V-012 | Add OSV response parsing | P0 | ⬜ | |
| V-013 | Add OSV client tests | P1 | ⬜ | Mock server |

### 3.3 NVD Client

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| V-020 | Implement NVD API client | P1 | ⬜ | |
| V-021 | Add CVSS score retrieval | P1 | ⬜ | |
| V-022 | Add rate limiting | P1 | ⬜ | |
| V-023 | Add NVD client tests | P1 | ⬜ | |

### 3.4 EPSS Client

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| V-030 | Implement EPSS API client | P0 | ⬜ | |
| V-031 | Add score parsing | P0 | ⬜ | |
| V-032 | Add EPSS client tests | P1 | ⬜ | |

### 3.5 CISA KEV Client

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| V-040 | Implement KEV client | P1 | ⬜ | |
| V-041 | Add daily refresh logic | P2 | ⬜ | |
| V-042 | Add KEV client tests | P1 | ⬜ | |

### 3.6 Caching

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| V-050 | Implement vuln cache | P1 | ⬜ | File-based |
| V-051 | Add TTL management | P1 | ⬜ | |
| V-052 | Add cache tests | P2 | ⬜ | |

---

## Phase 4: Report Generation

### 4.1 Security Report

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| RP-001 | Define `SecurityReport` struct | P0 | ⬜ | |
| RP-002 | Implement category scoring | P0 | ⬜ | Weighted aggregation |
| RP-003 | Implement decision logic | P0 | ⬜ | PASS/CONDITIONAL/FAIL |
| RP-004 | Add attack path extraction | P1 | ⬜ | |

### 4.2 structured-evaluation Integration

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| RP-010 | Map tests to CategoryScore | P0 | ⬜ | |
| RP-011 | Map findings to Finding | P0 | ⬜ | |
| RP-012 | Implement ToEvaluationReport() | P0 | ⬜ | |
| RP-013 | Add report generation tests | P1 | ⬜ | |

### 4.3 Output Formats

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| RP-020 | Implement JSON output | P0 | ⬜ | |
| RP-021 | Implement detailed terminal output | P1 | ⬜ | |
| RP-022 | Implement JUnit XML output | P2 | ⬜ | For CI |

---

## Phase 5: VEX Generation

### 5.1 VEX Model

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| VX-001 | Define `VEXStatement` struct | P0 | ⬜ | |
| VX-002 | Define justification types | P0 | ⬜ | not_affected reasons |
| VX-003 | Implement justification logic | P0 | ⬜ | From test results |

### 5.2 Output Formats

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| VX-010 | Implement CycloneDX VEX output | P0 | ⬜ | |
| VX-011 | Implement OpenVEX output | P2 | ⬜ | |
| VX-012 | Add VEX generation tests | P1 | ⬜ | |

---

## Phase 6: CLI & MCP

### 6.1 CLI Commands

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| CLI-001 | Create root command | P0 | ⬜ | |
| CLI-002 | Create `assess` command | P0 | ⬜ | Main entry point |
| CLI-003 | Create `test` command | P1 | ⬜ | Run specific tests |
| CLI-004 | Create `vex` command | P1 | ⬜ | Generate VEX |
| CLI-005 | Create `paths` command | P2 | ⬜ | Find attack paths |
| CLI-006 | Create `gate` command | P1 | ⬜ | CI/CD gate |
| CLI-007 | Create `serve` command | P1 | ⬜ | MCP server |
| CLI-008 | Add CLI tests | P1 | ⬜ | |

### 6.2 MCP Server

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| MCP-001 | Set up MCP server | P0 | ⬜ | |
| MCP-002 | Implement `assess_vulnerability` tool | P0 | ⬜ | |
| MCP-003 | Implement `find_attack_paths` tool | P1 | ⬜ | |
| MCP-004 | Implement `generate_vex` tool | P1 | ⬜ | |
| MCP-005 | Implement `explain_reachability` tool | P2 | ⬜ | |
| MCP-006 | Add MCP tests | P1 | ⬜ | |

---

## Phase 7: Documentation & Polish

| ID | Task | Priority | Status | Notes |
|----|------|----------|--------|-------|
| DOC-001 | Write user documentation | P0 | ⬜ | |
| DOC-002 | Write API documentation | P1 | ⬜ | |
| DOC-003 | Create example workflows | P1 | ⬜ | |
| DOC-004 | Write integration guide | P2 | ⬜ | CI/CD, MCP |
| DOC-005 | Add CHANGELOG.md | P1 | ⬜ | |
| DOC-006 | Create release v0.1.0 | P0 | ⬜ | |

---

## Task Statistics

| Phase | Total | P0 | P1 | P2 | P3 |
|-------|-------|----|----|----|----|
| Phase 0 (graphize) | 17 | 8 | 7 | 2 | 0 |
| Phase 1 | 16 | 11 | 5 | 0 | 0 |
| Phase 2 | 19 | 6 | 10 | 2 | 1 |
| Phase 3 | 18 | 7 | 9 | 2 | 0 |
| Phase 4 | 10 | 6 | 3 | 1 | 0 |
| Phase 5 | 6 | 4 | 1 | 1 | 0 |
| Phase 6 | 14 | 5 | 7 | 2 | 0 |
| Phase 7 | 6 | 2 | 3 | 1 | 0 |
| **Total** | **106** | **49** | **45** | **11** | **1** |

---

## Sprint Allocation (2-week sprints)

### Sprint 1 (Weeks 1-2)
- Phase 0: G-001 through G-013
- Phase 1: A-001 through A-025

### Sprint 2 (Weeks 3-4)
- Phase 2: R-001 through D-004
- Start Phase 3: V-001 through V-004

### Sprint 3 (Weeks 5-6)
- Phase 3: V-010 through V-052
- Phase 4: RP-001 through RP-022

### Sprint 4 (Weeks 7-8)
- Phase 5: VX-001 through VX-012
- Phase 6: CLI-001 through MCP-006

### Sprint 5 (Week 9)
- Phase 7: DOC-001 through DOC-006
- Release preparation
