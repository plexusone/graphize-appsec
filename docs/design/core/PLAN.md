# Implementation Plan

## graphize-appsec: Phased Development Plan

**Version:** 0.1.0
**Status:** Draft
**Date:** 2025-05-08

---

## Overview

This document outlines the phased implementation plan for graphize-appsec, including dependencies on graphize enhancements.

---

## Phase 0: graphize Enhancements (Prerequisites)

Before graphize-appsec development, graphize needs interface enhancements to better support external analyzers like graphize-groovy.

### 0.1 External Analyzer Interface Enhancement

**Current State:**
- Extractors must be compiled into graphize binary via blank imports
- No runtime discovery of external analyzers
- Priority system exists but only for compile-time registration

**Enhancements Needed:**

```go
// pkg/provider/external.go (NEW)

// ExternalExtractor wraps an external analyzer process
type ExternalExtractor struct {
    Name       string
    Command    string   // Path to external analyzer binary
    Args       []string
    Extensions []string
}

// Register external extractors from config
func RegisterExternal(config ExternalExtractorConfig) error

// Config file format
type ExternalExtractorConfig struct {
    Name       string   `yaml:"name"`
    Command    string   `yaml:"command"`
    Args       []string `yaml:"args"`
    Extensions []string `yaml:"extensions"`
    Language   string   `yaml:"language"`
    Priority   int      `yaml:"priority"`
}
```

**Communication Protocol:**

```
# External analyzer receives on stdin:
{
  "action": "extract",
  "path": "/path/to/file.groovy",
  "base_dir": "/project/root"
}

# External analyzer returns on stdout:
{
  "nodes": [...],
  "edges": [...],
  "framework": {...}
}
```

### 0.2 Enhanced Node Attributes for Security

Add standard attributes for security analysis:

```go
// pkg/provider/attrs.go (NEW)

const (
    // Entry point markers
    AttrIsEntrypoint    = "is_entrypoint"
    AttrIsHandler       = "is_handler"
    AttrHTTPMethod      = "http_method"
    AttrHTTPPath        = "http_path"

    // Security-relevant markers
    AttrRequiresAuth    = "requires_auth"
    AttrAuthLevel       = "auth_level"
    AttrIsSink          = "is_sink"           // SQL, command, etc.
    AttrIsSource        = "is_source"         // User input
    AttrSensitiveData   = "sensitive_data"

    // Framework markers
    AttrFrameworkLayer  = "framework_layer"   // controller, service, etc.
    AttrFrameworkName   = "framework_name"

    // Deployment markers
    AttrVisibility      = "visibility"        // public, internal
    AttrEnvironment     = "environment"       // prod, staging, dev
)
```

### 0.3 SBOM Adapter Interface

```go
// pkg/adapter/sbom/adapter.go (NEW)

type SBOMAdapter interface {
    // Parse SBOM and add to graph
    Ingest(sbomPath string, g *graph.Graph) error

    // Supported formats
    Formats() []string  // ["cyclonedx", "spdx"]
}

// Built-in CycloneDX adapter
type CycloneDXAdapter struct{}

func (a *CycloneDXAdapter) Ingest(sbomPath string, g *graph.Graph) error {
    // Parse CycloneDX JSON/XML
    // Create package nodes with purls
    // Create depends_on edges
    // Correlate with existing code nodes
}
```

### 0.4 Kubernetes Topology Adapter

```go
// pkg/adapter/k8s/adapter.go (NEW)

type K8sAdapter interface {
    // Discover deployments and add to graph
    Discover(ctx context.Context, g *graph.Graph) error

    // Watch for changes (optional)
    Watch(ctx context.Context, updates chan<- GraphUpdate) error
}
```

---

## Phase 1: Core Framework (Week 1-2)

### 1.1 Project Scaffolding

- [ ] Initialize go.mod with dependencies
- [ ] Create package structure per TRD
- [ ] Set up CI/CD (GitHub Actions)
- [ ] Add README.md

### 1.2 Test Framework

- [ ] Define `Test` interface
- [ ] Implement `TestResult` type
- [ ] Create `EvalContext` structure
- [ ] Build `TestRunner` orchestrator
- [ ] Implement test registry

### 1.3 Graph Query Layer

- [ ] Wrapper around graphfs traversal
- [ ] Node filtering utilities
- [ ] Attack path reconstruction
- [ ] Entry point detection

---

## Phase 2: Reachability Tests (Week 3-4)

### 2.1 Category: Reachable

| Test | Priority | Complexity |
|------|----------|------------|
| REACH-001: Dependency Imported | P0 | Low |
| REACH-002: Dependency Used | P0 | Medium |
| REACH-003: Exposed by API | P0 | Medium |
| REACH-004: Direct Dependency | P1 | Low |
| REACH-005: Public Repository | P2 | Low |
| REACH-006: Application Layer | P2 | Low |
| REACH-007: Cloud Deployed | P1 | High |

### 2.2 Category: Exploitable

| Test | Priority | Complexity |
|------|----------|------------|
| EXPLOIT-001: Weak Cryptography | P2 | Medium |
| EXPLOIT-002: Community Buzz | P2 | Medium |
| EXPLOIT-003: Extensive Patching | P2 | Low |
| EXPLOIT-004: Multiple Public Exploits | P1 | Medium |
| EXPLOIT-005: EPSS Low Risk | P0 | Low |
| EXPLOIT-006: AI Unexploitable | P3 | High |

### 2.3 Category: Damage

| Test | Priority | Complexity |
|------|----------|------------|
| DAMAGE-001: Critical Business Priority | P1 | Low |
| DAMAGE-002: Login Management | P1 | Medium |
| DAMAGE-003: CVSS High Severity | P0 | Low |

---

## Phase 3: Vulnerability Intelligence (Week 5)

### 3.1 OSV Client

- [ ] Implement OSV API client
- [ ] Package → vulnerability lookup
- [ ] Caching layer

### 3.2 NVD Client

- [ ] Implement NVD API client
- [ ] CVSS score retrieval
- [ ] Rate limiting

### 3.3 EPSS Client

- [ ] Implement EPSS API client
- [ ] Score caching

### 3.4 CISA KEV Client

- [ ] Implement KEV list client
- [ ] Daily refresh

---

## Phase 4: Report Generation (Week 6)

### 4.1 structured-evaluation Integration

- [ ] Create `SecurityReport` type
- [ ] Map tests to `CategoryScore`
- [ ] Map findings to `Finding`
- [ ] Implement decision logic

### 4.2 Output Formats

- [ ] JSON output
- [ ] Detailed terminal output
- [ ] JUnit XML (for CI)

---

## Phase 5: VEX Generation (Week 7)

### 5.1 VEX Model

- [ ] Define VEX statement types
- [ ] Implement justification logic

### 5.2 Output Formats

- [ ] CycloneDX VEX
- [ ] OpenVEX

---

## Phase 6: CLI & MCP (Week 8)

### 6.1 CLI Commands

- [ ] `assess` command
- [ ] `test` command
- [ ] `vex` command
- [ ] `paths` command
- [ ] `gate` command

### 6.2 MCP Server

- [ ] `assess_vulnerability` tool
- [ ] `find_attack_paths` tool
- [ ] `generate_vex` tool
- [ ] `explain_reachability` tool

---

## Phase 7: Documentation & Polish (Week 9)

- [ ] User documentation
- [ ] API documentation
- [ ] Example workflows
- [ ] Integration guides

---

## Dependencies

### External Dependencies

| Dependency | Purpose | Version |
|------------|---------|---------|
| `github.com/plexusone/graphize` | Code knowledge graph | v0.2.x |
| `github.com/plexusone/graphfs` | Graph storage | v0.2.x |
| `github.com/plexusone/structured-evaluation` | Report framework | v0.3.x |
| `github.com/spf13/cobra` | CLI framework | latest |
| `github.com/google/osv-scanner` | OSV client | latest |

### graphize Dependencies (Phase 0)

| Enhancement | Blocking For |
|-------------|--------------|
| External analyzer interface | graphize-groovy integration |
| Security node attributes | REACH-003, DAMAGE-002 |
| SBOM adapter | REACH-001, REACH-004 |
| K8s adapter | REACH-007 |

---

## Milestones

| Milestone | Target | Deliverable |
|-----------|--------|-------------|
| M1: Foundation | Week 2 | Test framework, graph query layer |
| M2: Core Tests | Week 4 | 10 reachability tests working |
| M3: Vuln Intel | Week 5 | OSV/NVD/EPSS integration |
| M4: Reports | Week 6 | structured-evaluation reports |
| M5: VEX | Week 7 | CycloneDX VEX generation |
| M6: CLI/MCP | Week 8 | Full CLI and MCP tools |
| M7: Release | Week 9 | v0.1.0 release |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| graphize enhancements delayed | High | Start with tests that don't need K8s/SBOM |
| OSV/NVD API rate limits | Medium | Implement aggressive caching |
| False positive rate too high | High | Tune confidence thresholds, add tests |
| Performance on large graphs | Medium | Optimize traversal, add caching |

---

## Success Criteria

### MVP (v0.1.0)

- [ ] 10+ reachability tests implemented
- [ ] OSV vulnerability lookup working
- [ ] structured-evaluation reports generated
- [ ] CycloneDX VEX output
- [ ] CLI with `assess` and `gate` commands
- [ ] MCP `assess_vulnerability` tool

### v0.2.0

- [ ] All 16 tests implemented
- [ ] Kubernetes deployment awareness
- [ ] SBOM correlation
- [ ] AI-assisted unexploitability
