# Technical Requirements Document (TRD)

## graphize-appsec: Technical Architecture

**Version:** 0.1.0
**Status:** Draft
**Date:** 2025-05-08

---

## System Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           graphize-appsec                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │    CLI      │  │  MCP Server │  │   Report    │  │     VEX     │   │
│  │  (Cobra)    │  │  (stdio)    │  │  Generator  │  │  Generator  │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
│         │                │                │                │           │
│         └────────────────┴────────────────┴────────────────┘           │
│                                   │                                     │
│                          ┌────────▼────────┐                           │
│                          │  Test Runner    │                           │
│                          │  (orchestrator) │                           │
│                          └────────┬────────┘                           │
│                                   │                                     │
│         ┌─────────────────────────┼─────────────────────────┐          │
│         │                         │                         │          │
│  ┌──────▼──────┐  ┌───────────────▼───────────────┐  ┌──────▼──────┐  │
│  │ Reachability│  │       Exploitability          │  │   Damage    │  │
│  │   Tests     │  │          Tests                │  │   Tests     │  │
│  │  (7 tests)  │  │        (6 tests)              │  │  (3 tests)  │  │
│  └──────┬──────┘  └───────────────┬───────────────┘  └──────┬──────┘  │
│         │                         │                         │          │
│         └─────────────────────────┼─────────────────────────┘          │
│                                   │                                     │
│  ┌────────────────────────────────▼────────────────────────────────┐   │
│  │                      Graph Query Layer                          │   │
│  │  • BFS/DFS traversal    • Path finding    • Node filtering     │   │
│  └────────────────────────────────┬────────────────────────────────┘   │
│                                   │                                     │
│  ┌────────────────────────────────▼────────────────────────────────┐   │
│  │                   Vulnerability Intelligence                    │   │
│  │  • OSV client    • NVD client    • EPSS client    • KEV client │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
             ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
             │  graphize   │ │  graphfs  │ │ structured│
             │  (graph)    │ │ (storage) │ │-evaluation│
             └─────────────┘ └───────────┘ └───────────┘
```

---

## Package Structure

```
github.com/plexusone/graphize-appsec/
├── cmd/
│   └── graphize-appsec/
│       └── main.go                 # CLI entry point
│
├── pkg/
│   ├── reachability/               # Reachability test framework
│   │   ├── test.go                 # Test interface & types
│   │   ├── registry.go             # Test registry
│   │   ├── runner.go               # Test execution engine
│   │   ├── context.go              # Evaluation context
│   │   │
│   │   ├── reachable/              # Category: Reachable
│   │   │   ├── dependency_imported.go
│   │   │   ├── dependency_used.go
│   │   │   ├── exposed_by_api.go
│   │   │   ├── direct_dependency.go
│   │   │   ├── public_repository.go
│   │   │   ├── application_layer.go
│   │   │   └── cloud_deployed.go
│   │   │
│   │   ├── exploitable/            # Category: Exploitable
│   │   │   ├── weak_cryptography.go
│   │   │   ├── community_buzz.go
│   │   │   ├── extensive_patching.go
│   │   │   ├── multiple_exploits.go
│   │   │   ├── epss_risk.go
│   │   │   └── ai_unexploitable.go
│   │   │
│   │   └── damage/                 # Category: Damage
│   │       ├── critical_business.go
│   │       ├── login_management.go
│   │       └── cvss_severity.go
│   │
│   ├── vuln/                       # Vulnerability intelligence
│   │   ├── client.go               # Unified vuln client interface
│   │   ├── osv.go                  # OSV database client
│   │   ├── nvd.go                  # NVD client
│   │   ├── epss.go                 # EPSS scoring
│   │   ├── kev.go                  # CISA KEV
│   │   └── cache.go                # Local caching
│   │
│   ├── vex/                        # VEX generation
│   │   ├── statement.go            # VEX data model
│   │   ├── cyclonedx.go            # CycloneDX VEX format
│   │   ├── openvex.go              # OpenVEX format
│   │   └── generator.go            # Generation logic
│   │
│   ├── report/                     # Report generation
│   │   ├── security.go             # SecurityReport type
│   │   ├── evaluation.go           # structured-evaluation integration
│   │   └── render.go               # Output formatting
│   │
│   ├── graph/                      # Graph query utilities
│   │   ├── query.go                # Wrapper around graphfs traversal
│   │   ├── filter.go               # Node/edge filtering
│   │   └── path.go                 # Attack path construction
│   │
│   └── mcp/                        # MCP server & tools
│       ├── server.go               # MCP server setup
│       ├── tools.go                # Tool definitions
│       └── handlers.go             # Tool handlers
│
├── internal/
│   └── cmd/                        # CLI commands
│       ├── root.go
│       ├── assess.go
│       ├── test.go
│       ├── vex.go
│       ├── paths.go
│       ├── gate.go
│       └── serve.go
│
├── docs/
│   └── design/
│       └── core/
│           ├── MRD.md
│           ├── PRD.md
│           ├── TRD.md              # This document
│           ├── PLAN.md
│           └── TASKS.md
│
└── go.mod
```

---

## Core Interfaces

### Test Interface

```go
// pkg/reachability/test.go

// Category represents a test category
type Category string

const (
    CategoryReachable   Category = "reachable"
    CategoryExploitable Category = "exploitable"
    CategoryDamage      Category = "damage"
)

// Test defines a reachability test
type Test interface {
    // Metadata
    ID() string
    Name() string
    Description() string
    Category() Category

    // Execution
    Evaluate(ctx *EvalContext) (*TestResult, error)
}

// TestResult holds the outcome of a test
type TestResult struct {
    ID          string
    Name        string
    Category    Category
    Pass        bool                // Y/N result
    Confidence  float64             // 0.0-1.0
    Severity    evaluation.Severity // Severity if test indicates risk
    Evidence    string              // Human-readable evidence
    Details     map[string]any      // Structured details
    Duration    time.Duration
}

// EvalContext provides data needed for test evaluation
type EvalContext struct {
    // Graph access
    Graph       *graph.Graph
    Traverser   *query.Traverser

    // Vulnerability info
    VulnID      string              // CVE-XXXX-XXXXX
    VulnInfo    *vuln.Vulnerability // Full vuln details
    AffectedPkg string              // Package containing vuln
    AffectedFunc string             // Function containing vuln (if known)

    // Runtime context (optional)
    Deployments []*DeploymentInfo

    // Configuration
    Config      *Config
}
```

### Vulnerability Client Interface

```go
// pkg/vuln/client.go

type VulnerabilityClient interface {
    // Lookup vulnerability details
    Get(ctx context.Context, vulnID string) (*Vulnerability, error)

    // Find vulnerabilities affecting a package
    ByPackage(ctx context.Context, purl string) ([]*Vulnerability, error)

    // Get EPSS score
    EPSSScore(ctx context.Context, vulnID string) (float64, error)

    // Check if in CISA KEV
    IsKnownExploited(ctx context.Context, vulnID string) (bool, error)
}

type Vulnerability struct {
    ID              string
    Aliases         []string          // CVE, GHSA, etc.
    Summary         string
    Details         string
    Severity        Severity
    CVSS            *CVSSScore
    EPSS            *EPSSScore
    AffectedPackages []AffectedPackage
    References      []Reference
    Published       time.Time
    Modified        time.Time
}
```

### Report Interface

```go
// pkg/report/security.go

type SecurityReport struct {
    // Metadata
    Metadata        ReportMetadata
    GeneratedAt     time.Time

    // Subject
    Vulnerability   VulnerabilityInfo
    Repository      RepositoryInfo

    // Test Results (using structured-evaluation)
    Categories      []evaluation.CategoryScore  // 3 categories
    Tests           []TestResult                // 16 test results

    // Aggregated Results
    WeightedScore   float64
    Decision        evaluation.Decision
    DecisionRationale string

    // Attack Analysis
    AttackPaths     []AttackPath
    BlastRadius     *BlastRadiusInfo

    // Output
    VEX             *vex.Statement              // If not affected
    NextSteps       *evaluation.NextSteps
    Summary         string
}
```

---

## Data Flow

### Vulnerability Assessment Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Input                                       │
│  • CVE ID (e.g., CVE-2021-44228)                                   │
│  • Graph path (.graphize/)                                         │
│  • Optional: deployment info                                        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    1. Load Context                                  │
│  • Load graph from graphize                                        │
│  • Fetch vulnerability details from OSV/NVD                        │
│  • Identify affected package(s) and function(s)                    │
│  • Build EvalContext                                               │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    2. Run Reachability Tests                        │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │ Reachable   │  │ Exploitable │  │   Damage    │                │
│  │  (7 tests)  │  │  (6 tests)  │  │  (3 tests)  │                │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                │
│         │                │                │                        │
│         └────────────────┴────────────────┘                        │
│                          │                                          │
│                   TestResult[]                                      │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    3. Aggregate Results                             │
│  • Calculate category scores (weighted)                            │
│  • Determine overall decision (PASS/CONDITIONAL/FAIL)              │
│  • If reachable: trace attack paths                                │
│  • If not reachable: generate VEX statement                        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    4. Generate Report                               │
│  • Create SecurityReport using structured-evaluation               │
│  • Render in requested format (json, detailed, junit)              │
│  • Write VEX file if applicable                                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Graph Query Patterns

### Test: Dependency Used (REACH-002)

```go
func (t *DependencyUsedTest) Evaluate(ctx *EvalContext) (*TestResult, error) {
    // Find all entry points (main functions, API handlers, etc.)
    entryPoints := ctx.Graph.NodesWhere(func(n *graph.Node) bool {
        return n.Attrs["is_entrypoint"] == "true" ||
               n.Type == "api_endpoint" ||
               (n.Type == "function" && n.Attrs["name"] == "main")
    })

    // For each entry point, check if vuln function is reachable
    for _, ep := range entryPoints {
        result := ctx.Traverser.BFS(ep.ID, query.Outgoing, -1, []string{"calls"})

        if depth, found := result.Depth[ctx.AffectedFunc]; found {
            // Reconstruct the call path
            path := reconstructPath(result, ctx.AffectedFunc)

            return &TestResult{
                ID:         t.ID(),
                Pass:       true,  // Dependency IS used (risk exists)
                Confidence: 1.0,
                Severity:   evaluation.SeverityHigh,
                Evidence:   fmt.Sprintf("Reachable from %s in %d calls", ep.ID, depth),
                Details: map[string]any{
                    "entry_point": ep.ID,
                    "call_depth":  depth,
                    "call_path":   path,
                },
            }, nil
        }
    }

    return &TestResult{
        ID:         t.ID(),
        Pass:       false,  // Dependency NOT used (safe)
        Confidence: 0.9,    // High but not 100% (dynamic calls possible)
        Severity:   evaluation.SeverityInfo,
        Evidence:   "No call path found from any entry point",
    }, nil
}
```

### Test: Exposed by API (REACH-003)

```go
func (t *ExposedByAPITest) Evaluate(ctx *EvalContext) (*TestResult, error) {
    // Find API endpoints
    apiNodes := ctx.Graph.NodesWhere(func(n *graph.Node) bool {
        return n.Type == "api_endpoint" ||
               n.Attrs["is_handler"] == "true" ||
               n.Attrs["framework_layer"] == "controller"
    })

    if len(apiNodes) == 0 {
        return &TestResult{
            Pass:       false,
            Confidence: 0.7,  // Maybe no API detected
            Evidence:   "No API endpoints found in graph",
        }, nil
    }

    // Check reachability from each API
    for _, api := range apiNodes {
        path := ctx.Traverser.FindPath(api.ID, ctx.AffectedFunc, nil)
        if len(path.Visited) > 0 {
            return &TestResult{
                Pass:       true,
                Confidence: 1.0,
                Severity:   evaluation.SeverityHigh,
                Evidence:   fmt.Sprintf("API %s can reach %s", api.Label, ctx.AffectedFunc),
                Details: map[string]any{
                    "api_endpoint": api.ID,
                    "method":       api.Attrs["http_method"],
                    "path":         api.Attrs["http_path"],
                    "attack_path":  path.Visited,
                },
            }, nil
        }
    }

    return &TestResult{
        Pass:       false,
        Confidence: 0.95,
        Severity:   evaluation.SeverityLow,
        Evidence:   fmt.Sprintf("No API path to %s found", ctx.AffectedFunc),
    }, nil
}
```

---

## Integration Points

### graphize Integration

```go
import (
    "github.com/plexusone/graphize/pkg/extract"
    "github.com/plexusone/graphize/provider"
    "github.com/plexusone/graphfs/pkg/graph"
    "github.com/plexusone/graphfs/pkg/query"
    "github.com/plexusone/graphfs/pkg/store"
)

func LoadGraph(graphPath string) (*graph.Graph, error) {
    fs := store.NewFSStore(graphPath)
    return fs.LoadGraph()
}
```

### structured-evaluation Integration

```go
import (
    "github.com/plexusone/structured-evaluation/evaluation"
)

func (r *SecurityReport) ToEvaluationReport() *evaluation.EvaluationReport {
    report := evaluation.NewEvaluationReport("security-reachability", r.Vulnerability.ID)

    // Add category scores
    report.AddCategory(evaluation.NewCategoryScore(
        "reachable", 0.40, r.Categories[0].Score, r.Categories[0].Justification,
    ))
    report.AddCategory(evaluation.NewCategoryScore(
        "exploitable", 0.35, r.Categories[1].Score, r.Categories[1].Justification,
    ))
    report.AddCategory(evaluation.NewCategoryScore(
        "damage", 0.25, r.Categories[2].Score, r.Categories[2].Justification,
    ))

    // Convert test results to findings
    for _, test := range r.Tests {
        if test.Pass && test.Severity >= evaluation.SeverityMedium {
            report.AddFinding(evaluation.Finding{
                ID:          test.ID,
                Category:    string(test.Category),
                Severity:    test.Severity,
                Title:       test.Name,
                Description: test.Evidence,
            })
        }
    }

    report.PassCriteria = evaluation.StrictPassCriteria()
    report.Finalize("graphize-appsec assess")

    return report
}
```

---

## Configuration

```yaml
# graphize-appsec.yaml

# Test configuration
tests:
  # Category weights for scoring
  weights:
    reachable: 0.40
    exploitable: 0.35
    damage: 0.25

  # Thresholds
  thresholds:
    min_confidence: 0.5
    high_severity_cvss: 7.0
    epss_high_risk: 0.1

# Vulnerability intelligence
vuln:
  osv:
    enabled: true
  nvd:
    enabled: true
    api_key: ${NVD_API_KEY}
  epss:
    enabled: true
  kev:
    enabled: true

  # Cache settings
  cache:
    enabled: true
    ttl: 24h
    path: ~/.cache/graphize-appsec

# VEX generation
vex:
  format: cyclonedx  # or openvex
  author: "graphize-appsec"

# Report settings
report:
  format: detailed  # json, detailed, junit
```

---

## Error Handling

All errors follow the pattern from CLAUDE.md:

1. **Panic**: Programming errors, invariant violations
2. **Return**: Propagate to caller when possible
3. **Log**: When error cannot be returned
4. **Report**: Guide human when other options exhausted

```go
func (r *Runner) RunTests(ctx *EvalContext) ([]TestResult, error) {
    results := make([]TestResult, 0, len(r.tests))

    for _, test := range r.tests {
        result, err := test.Evaluate(ctx)
        if err != nil {
            // Log but continue with other tests
            logger := slogutil.LoggerFromContext(ctx.Context)
            logger.Warn("test failed", "test_id", test.ID(), "error", err)

            results = append(results, TestResult{
                ID:         test.ID(),
                Pass:       false,
                Confidence: 0.0,
                Severity:   evaluation.SeverityInfo,
                Evidence:   fmt.Sprintf("Test error: %v", err),
            })
            continue
        }
        results = append(results, *result)
    }

    return results, nil
}
```

---

## Testing Strategy

### Unit Tests

- Each reachability test has unit tests with mock graphs
- Vulnerability client mocks for offline testing
- Report generation tests

### Integration Tests

- End-to-end assessment against sample repositories
- VEX generation validation
- MCP tool testing

### Test Data

```
testdata/
├── graphs/
│   ├── simple/           # Basic call graph
│   ├── transitive/       # Transitive dependency chain
│   ├── api_exposed/      # API → vulnerable function
│   └── isolated/         # No path to vulnerability
├── vulns/
│   └── test_vulns.json   # Mock vulnerability data
└── expected/
    └── reports/          # Expected report outputs
```
