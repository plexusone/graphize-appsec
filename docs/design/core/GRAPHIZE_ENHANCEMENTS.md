# graphize Interface Enhancements

## Required Changes for External Analyzer Support

**Version:** 0.1.0
**Status:** Draft
**Date:** 2025-05-08
**Target:** graphize repository

---

## Overview

This document specifies interface enhancements needed in graphize to support:

1. **External analyzers** like graphize-groovy (subprocess-based)
2. **Security analysis** via graphize-appsec
3. **SBOM correlation** for vulnerability assessment
4. **Runtime topology** (Kubernetes deployments)

---

## 1. External Analyzer Interface

### Problem

Currently, language extractors must be compiled into the graphize binary via blank imports:

```go
// cmd/graphize/cmd/analyze.go
import (
    _ "github.com/plexusone/graphize/pkg/extract/golang"
    _ "github.com/plexusone/graphize/pkg/extract/java"
    // Must add new analyzers here
)
```

This prevents true plugin architecture where external analyzers like graphize-groovy can be added without recompiling graphize.

### Solution: Subprocess Protocol

Add support for external analyzers that communicate via JSON-over-stdio.

#### New Types

```go
// pkg/provider/external.go

// ExternalExtractor wraps an external analyzer subprocess
type ExternalExtractor struct {
    name       string
    language   string
    extensions []string
    command    string
    args       []string
    timeout    time.Duration
}

// ExternalExtractorConfig defines an external analyzer
type ExternalExtractorConfig struct {
    Name       string        `yaml:"name"`
    Language   string        `yaml:"language"`
    Extensions []string      `yaml:"extensions"`
    Command    string        `yaml:"command"`
    Args       []string      `yaml:"args"`
    Timeout    string        `yaml:"timeout"`  // e.g., "30s"
    Priority   int           `yaml:"priority"` // Default: PriorityCustom
}

// Implements LanguageExtractor interface
func (e *ExternalExtractor) Language() string { return e.language }
func (e *ExternalExtractor) Extensions() []string { return e.extensions }
func (e *ExternalExtractor) CanExtract(path string) bool { ... }
func (e *ExternalExtractor) ExtractFile(path, baseDir string) ([]*graph.Node, []*graph.Edge, error) { ... }
func (e *ExternalExtractor) DetectFramework(path string) *FrameworkInfo { ... }
```

#### Communication Protocol

**Request (stdin to subprocess):**

```json
{
  "action": "extract",
  "path": "/absolute/path/to/file.groovy",
  "base_dir": "/project/root"
}
```

```json
{
  "action": "detect_framework",
  "path": "/absolute/path/to/file.groovy"
}
```

**Response (stdout from subprocess):**

```json
{
  "nodes": [
    {
      "id": "groovy_class_UserController",
      "type": "class",
      "label": "UserController",
      "attrs": {
        "source_file": "UserController.groovy",
        "framework_layer": "controller"
      }
    }
  ],
  "edges": [
    {
      "from": "groovy_class_UserController",
      "to": "groovy_method_UserController.index",
      "type": "contains",
      "confidence": "EXTRACTED"
    }
  ],
  "framework": {
    "name": "grails",
    "version": "6.0",
    "layer": "controller"
  }
}
```

**Error Response:**

```json
{
  "error": "parse error: unexpected token at line 42"
}
```

#### Configuration

```yaml
# .graphize/config.yaml or graphize.yaml

external_extractors:
  - name: graphize-groovy
    language: groovy
    extensions: [".groovy", ".gvy", ".gy", ".gsh"]
    command: graphize-groovy
    args: ["extract", "--json"]
    timeout: 30s
    priority: 100

  - name: graphize-rust
    language: rust
    extensions: [".rs"]
    command: /path/to/graphize-rust
    args: []
    timeout: 60s
```

#### Loading External Extractors

```go
// pkg/provider/loader.go

func LoadExternalExtractors(configPath string) error {
    config, err := loadConfig(configPath)
    if err != nil {
        return err
    }

    for _, ext := range config.ExternalExtractors {
        extractor, err := NewExternalExtractor(ext)
        if err != nil {
            return fmt.Errorf("loading %s: %w", ext.Name, err)
        }
        Register(func() LanguageExtractor { return extractor }, ext.Priority)
    }
    return nil
}
```

---

## 2. Security Node Attributes

### Problem

Security analysis (graphize-appsec) needs consistent attributes to identify:

- Entry points (main functions, HTTP handlers)
- Authentication requirements
- Data sinks (SQL, command execution)
- Framework layers (controller, service, repository)

### Solution: Standard Attribute Constants

```go
// pkg/provider/attrs.go

// Entry Point Markers
const (
    AttrIsEntrypoint = "is_entrypoint"  // "true" if function is entry point
    AttrIsHandler    = "is_handler"      // "true" if HTTP/RPC handler
    AttrHTTPMethod   = "http_method"     // "GET", "POST", etc.
    AttrHTTPPath     = "http_path"       // "/api/users", etc.
    AttrRPCMethod    = "rpc_method"      // gRPC method name
)

// Security Markers
const (
    AttrRequiresAuth   = "requires_auth"   // "true" if requires authentication
    AttrAuthLevel      = "auth_level"      // "public", "user", "admin"
    AttrIsSink         = "is_sink"         // "sql", "command", "file", etc.
    AttrIsSource       = "is_source"       // "user_input", "request_body", etc.
    AttrSensitiveData  = "sensitive_data"  // "true" if handles PII/secrets
)

// Framework Markers
const (
    AttrFrameworkName  = "framework_name"  // "spring", "grails", "express"
    AttrFrameworkLayer = "framework_layer" // "controller", "service", "repository"
    AttrAnnotations    = "annotations"     // Comma-separated: "@Controller,@RequestMapping"
)

// Deployment Markers
const (
    AttrVisibility  = "visibility"   // "public", "internal", "private"
    AttrEnvironment = "environment"  // "prod", "staging", "dev"
)
```

### Extractor Updates Required

#### Go Extractor

```go
// pkg/extract/golang/extractor.go

func (e *GoExtractor) ExtractFile(path, baseDir string) ([]*graph.Node, []*graph.Edge, error) {
    // ... existing extraction ...

    // Mark main function as entry point
    if funcDecl.Name.Name == "main" {
        node.Attrs[AttrIsEntrypoint] = "true"
    }

    // Detect HTTP handlers (net/http, gin, echo, etc.)
    if isHTTPHandler(funcDecl) {
        node.Attrs[AttrIsHandler] = "true"
        node.Attrs[AttrHTTPMethod] = detectHTTPMethod(funcDecl)
        node.Attrs[AttrHTTPPath] = detectHTTPPath(funcDecl)
    }

    // Detect sinks
    if isSQLSink(funcDecl) {
        node.Attrs[AttrIsSink] = "sql"
    }
}
```

#### Java Extractor

```go
// pkg/extract/java/extractor.go

func (e *JavaExtractor) ExtractFile(path, baseDir string) ([]*graph.Node, []*graph.Edge, error) {
    // ... existing extraction ...

    // Spring annotations
    if hasAnnotation(classDecl, "@RestController", "@Controller") {
        node.Attrs[AttrFrameworkLayer] = "controller"
        node.Attrs[AttrFrameworkName] = "spring"
    }

    if hasAnnotation(methodDecl, "@RequestMapping", "@GetMapping", "@PostMapping") {
        node.Attrs[AttrIsHandler] = "true"
        node.Attrs[AttrHTTPMethod] = extractHTTPMethod(methodDecl)
        node.Attrs[AttrHTTPPath] = extractHTTPPath(methodDecl)
    }

    if hasAnnotation(methodDecl, "@PreAuthorize", "@Secured") {
        node.Attrs[AttrRequiresAuth] = "true"
    }
}
```

---

## 3. Adapter Interface

### Problem

graphize needs to ingest non-code data:

- **SBOM**: CycloneDX/SPDX dependency information
- **Kubernetes**: Deployment topology, pod status
- **CI/CD**: Pipeline provenance

### Solution: Adapter Interface

```go
// pkg/adapter/adapter.go

// Adapter ingests external data into the graph
type Adapter interface {
    // Name returns the adapter identifier
    Name() string

    // Ingest adds data to the graph
    Ingest(ctx context.Context, g *graph.Graph, opts IngestOptions) error
}

type IngestOptions struct {
    Source     string            // Path, URL, or identifier
    Config     map[string]string // Adapter-specific config
    MergeMode  MergeMode         // How to handle existing nodes
}

type MergeMode int
const (
    MergeModeAppend  MergeMode = iota // Add new, skip existing
    MergeModeReplace                   // Replace existing nodes
    MergeModeUpdate                    // Update attrs on existing
)
```

### SBOM Adapter

```go
// pkg/adapter/sbom/cyclonedx.go

type CycloneDXAdapter struct{}

func (a *CycloneDXAdapter) Name() string { return "cyclonedx" }

func (a *CycloneDXAdapter) Ingest(ctx context.Context, g *graph.Graph, opts IngestOptions) error {
    sbom, err := cyclonedx.ParseBOM(opts.Source)
    if err != nil {
        return err
    }

    for _, component := range sbom.Components {
        node := &graph.Node{
            ID:    "pkg_" + component.PURL,
            Type:  graph.NodeTypePackage,
            Label: component.Name,
            Attrs: map[string]string{
                "purl":     component.PURL,
                "version":  component.Version,
                "license":  extractLicense(component),
                "supplier": component.Supplier,
            },
        }
        g.AddNode(node)

        // Add depends_on edges
        for _, dep := range component.Dependencies {
            edge := &graph.Edge{
                From:       node.ID,
                To:         "pkg_" + dep.Ref,
                Type:       graph.EdgeTypeDependsOn,
                Confidence: graph.ConfidenceExtracted,
            }
            g.AddEdge(edge)
        }
    }

    // Correlate with existing code nodes
    return a.correlateWithCode(g)
}

func (a *CycloneDXAdapter) correlateWithCode(g *graph.Graph) error {
    // Match SBOM packages to import statements
    // Create edges: code_import → sbom_package
}
```

### Kubernetes Adapter

```go
// pkg/adapter/k8s/adapter.go

type K8sAdapter struct {
    client kubernetes.Interface
}

func (a *K8sAdapter) Name() string { return "kubernetes" }

func (a *K8sAdapter) Ingest(ctx context.Context, g *graph.Graph, opts IngestOptions) error {
    namespace := opts.Config["namespace"]
    if namespace == "" {
        namespace = "default"
    }

    // Get deployments
    deployments, err := a.client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
    if err != nil {
        return err
    }

    for _, dep := range deployments.Items {
        node := &graph.Node{
            ID:    "k8s_deployment_" + dep.Name,
            Type:  "deployment",
            Label: dep.Name,
            Attrs: map[string]string{
                "namespace":  dep.Namespace,
                "replicas":   strconv.Itoa(int(*dep.Spec.Replicas)),
                "image":      dep.Spec.Template.Spec.Containers[0].Image,
                "status":     deploymentStatus(&dep),
            },
        }
        g.AddNode(node)
    }

    // Get ingresses for internet exposure
    ingresses, err := a.client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
    // ... add ingress nodes and edges

    return nil
}
```

### Adapter Registry

```go
// pkg/adapter/registry.go

var adapters = make(map[string]Adapter)

func RegisterAdapter(a Adapter) {
    adapters[a.Name()] = a
}

func GetAdapter(name string) (Adapter, bool) {
    a, ok := adapters[name]
    return a, ok
}

func init() {
    RegisterAdapter(&sbom.CycloneDXAdapter{})
    RegisterAdapter(&sbom.SPDXAdapter{})
    RegisterAdapter(&k8s.K8sAdapter{})
}
```

---

## 4. CLI Enhancements

### New Commands

```bash
# Import SBOM into graph
graphize import sbom --format cyclonedx --input sbom.json

# Import Kubernetes topology
graphize import k8s --namespace production --context prod-cluster

# Configure external extractors
graphize config set external.groovy.command graphize-groovy
graphize config set external.groovy.extensions ".groovy,.gvy"

# List available extractors
graphize extractors list
# Output:
# NAME          TYPE       EXTENSIONS           PRIORITY
# golang        built-in   .go                  0
# java          built-in   .java                0
# groovy        external   .groovy,.gvy,.gy     100
```

### Configuration File

```yaml
# .graphize/config.yaml

# External analyzer configuration
external_extractors:
  - name: graphize-groovy
    language: groovy
    extensions: [".groovy", ".gvy", ".gy", ".gsh"]
    command: graphize-groovy
    args: ["extract"]
    timeout: 30s
    priority: 100

# Adapter configuration
adapters:
  kubernetes:
    enabled: true
    context: prod-cluster
    namespace: default

# Security attribute extraction
security:
  detect_entry_points: true
  detect_sinks: true
  detect_auth: true
```

---

## 5. Impact on graphize-groovy

With these enhancements, graphize-groovy can be used in two ways:

### Option A: Compiled-In (Current)

```go
// In graphize binary
import _ "github.com/plexusone/graphize-groovy"
```

### Option B: External Process (New)

```yaml
# .graphize/config.yaml
external_extractors:
  - name: graphize-groovy
    command: graphize-groovy
    args: ["extract", "--json"]
```

graphize-groovy would need a new CLI mode:

```go
// cmd/graphize-groovy/main.go

func main() {
    if len(os.Args) > 1 && os.Args[1] == "extract" {
        // JSON-over-stdio mode for external integration
        runExternalMode()
    } else {
        // Standalone mode
        runStandalone()
    }
}

func runExternalMode() {
    decoder := json.NewDecoder(os.Stdin)
    encoder := json.NewEncoder(os.Stdout)

    for {
        var req ExternalRequest
        if err := decoder.Decode(&req); err != nil {
            if err == io.EOF {
                return
            }
            encoder.Encode(ErrorResponse{Error: err.Error()})
            continue
        }

        switch req.Action {
        case "extract":
            nodes, edges, err := extractor.ExtractFile(req.Path, req.BaseDir)
            if err != nil {
                encoder.Encode(ErrorResponse{Error: err.Error()})
                continue
            }
            encoder.Encode(ExtractResponse{Nodes: nodes, Edges: edges})

        case "detect_framework":
            fw := extractor.DetectFramework(req.Path)
            encoder.Encode(FrameworkResponse{Framework: fw})
        }
    }
}
```

---

## 6. Migration Path

### Phase 1: Add Attribute Constants (Backward Compatible)

- Add `pkg/provider/attrs.go` with standard constants
- Update extractors to set these attributes
- No breaking changes

### Phase 2: Add Adapter Interface (Backward Compatible)

- Add `pkg/adapter/` package
- Implement CycloneDX adapter
- Add `graphize import` command
- No breaking changes

### Phase 3: Add External Extractor Support (Backward Compatible)

- Add `pkg/provider/external.go`
- Add config file loading
- External extractors are optional
- No breaking changes

### Phase 4: Update graphize-groovy (Optional)

- Add `extract --json` mode for external use
- Compiled-in mode still works
- Users choose integration method

---

## 7. Testing

### External Extractor Tests

```go
func TestExternalExtractor_Extract(t *testing.T) {
    // Create mock subprocess
    mockCmd := exec.Command("echo", `{"nodes":[],"edges":[]}`)

    ext := &ExternalExtractor{
        name:       "test",
        language:   "test",
        extensions: []string{".test"},
        command:    mockCmd.Path,
        args:       mockCmd.Args[1:],
    }

    nodes, edges, err := ext.ExtractFile("/path/to/test.test", "/path/to")
    require.NoError(t, err)
    require.Empty(t, nodes)
    require.Empty(t, edges)
}
```

### Adapter Tests

```go
func TestCycloneDXAdapter_Ingest(t *testing.T) {
    g := graph.NewGraph()
    adapter := &CycloneDXAdapter{}

    err := adapter.Ingest(context.Background(), g, IngestOptions{
        Source: "testdata/sbom.json",
    })
    require.NoError(t, err)

    // Verify package nodes created
    node := g.GetNode("pkg_pkg:npm/lodash@4.17.21")
    require.NotNil(t, node)
    require.Equal(t, "lodash", node.Label)
}
```

---

## Summary

| Enhancement | Priority | Breaking Change | Effort |
|-------------|----------|-----------------|--------|
| Security attributes | P0 | No | Low |
| Adapter interface | P0 | No | Medium |
| External extractor protocol | P1 | No | Medium |
| SBOM adapter | P1 | No | Medium |
| K8s adapter | P2 | No | High |
| Config file support | P1 | No | Low |

These enhancements enable:

1. **graphize-groovy** to integrate without recompiling graphize
2. **graphize-appsec** to perform security analysis
3. **SBOM correlation** for vulnerability assessment
4. **Runtime context** for deployment-aware analysis
