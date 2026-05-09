# Parser and Analysis Tool Landscape

Technical comparison of parsing approaches for security reachability analysis.

## Why Parser Choice Matters

Security-grade reachability analysis requires:

1. **Type resolution** - Know the actual types being called
2. **Call graph construction** - Trace execution paths
3. **Semantic understanding** - Understand framework patterns
4. **Cross-package analysis** - Follow imports and dependencies

Not all parsers provide these capabilities.

## Tree-sitter: Strengths and Limitations

[Tree-sitter](https://tree-sitter.github.io/tree-sitter/) is widely used for multi-language parsing.

### What Tree-sitter IS Good For

- Fast incremental parsing
- Syntax trees (CST, not semantic AST)
- Editor tooling and syntax highlighting
- Code navigation
- Language-agnostic structural queries

### What Tree-sitter is NOT Good For

- Type resolution
- Call graph construction
- Semantic reachability
- Framework understanding
- Vulnerability analysis

**Key insight**: Tree-sitter is a front-end parser, not an analysis engine.

For security reachability:

> Tree-sitter alone cannot determine if a vulnerable function is actually called.

## Language-Specific Analysis Tools

Serious reachability analysis requires compiler-level APIs:

### Go

**Recommended**: `go/ast` + `go/types` + `golang.org/x/tools/go/ssa`

Go is exceptionally well-suited for reachability because:

- Static typing with minimal reflection
- First-class analysis tooling in stdlib
- `go/callgraph` for call graph construction
- `go/ssa` for SSA-form analysis
- Standardized module system

Tools like `govulncheck` achieve high precision due to these capabilities.

### Java

**Recommended**: Eclipse JDT, Soot, WALA

| Tool | Use Case |
|------|----------|
| Eclipse JDT | AST + compiler frontend |
| Soot | Bytecode analysis, call graphs |
| WALA | Points-to analysis, slicing |
| Spoon | AST transformation |

Java bytecode analysis (via Soot) often provides better precision than source analysis.

### TypeScript / JavaScript

**Recommended**: TypeScript Compiler API

The TypeScript compiler API provides:

- Full type information
- Symbol resolution
- Call graph extraction
- Module resolution

For JavaScript without types, analysis precision degrades significantly.

### Python

**Challenge**: Dynamic typing limits static analysis precision.

| Tool | Capability |
|------|------------|
| `ast` module | Basic AST (stdlib) |
| mypy internals | Type inference |
| Pyright | Type checking |

Python reachability often requires runtime analysis or conservative approximation.

### C / C++

**Recommended**: Clang/LLVM LibTooling

Clang AST is arguably best-in-class for C/C++:

- Rich semantic information
- Used by CodeQL, many SAST tools
- LLVM IR for deeper analysis

### Rust

**Recommended**: `rustc` internals, MIR

| Level | Use Case |
|-------|----------|
| `syn` crate | AST parsing |
| HIR | High-level IR |
| MIR | Mid-level IR (comparable to Go SSA) |

MIR provides the best precision for Rust reachability.

### C# / .NET

**Recommended**: Roslyn Compiler APIs

Roslyn provides:

- Full semantic model
- Symbol resolution
- Flow analysis
- Refactoring engines

One of the strongest analysis ecosystems outside of Go.

## Recommended Architecture

For a multi-language reachability system:

### Layer 1: Parsing

Use language-specific parsers, not a universal parser:

```
Go      → go/parser
Java    → JDT / javac
TS      → TypeScript compiler
Python  → ast + type stubs
C/C++   → Clang
```

### Layer 2: Semantic Enrichment

- Type resolution
- Import graph construction
- Symbol linking
- Framework pattern detection

### Layer 3: IR Construction

- Call graph
- Control flow graph
- Data flow graph
- Dependency graph

### Layer 4: Reachability Engine

- Graph traversal (BFS/DFS)
- Path finding
- Taint analysis
- Vulnerability mapping

## graphize Approach

graphize uses this hybrid architecture:

| Language | Parser | Semantic Analysis |
|----------|--------|-------------------|
| Go | `go/ast` | `go/types`, `SemanticExtractor` |
| Java | Tree-sitter | Spring annotation detection |
| TypeScript | Tree-sitter | Import resolution |
| Swift | Tree-sitter | Protocol detection |

**Go** gets full semantic analysis via `go/types` and the `SemanticExtractor`.

**Other languages** use Tree-sitter for structure with framework-specific heuristics for semantic understanding.

## Why Go is Special

Go provides uniquely strong guarantees for static analysis:

1. **Simple language** - Limited metaprogramming, predictable call structure
2. **Stdlib analysis tools** - `go/ast`, `go/types`, `go/callgraph`, `go/ssa`
3. **Module system** - Reproducible builds, clear dependencies
4. **Interface semantics** - Explicit interface implementation

This makes Go one of the easiest languages for:

- SBOM accuracy
- Reachability precision
- Dependency graph correctness

## Implications for graphize-appsec

Given parser limitations:

| Language | Reachability Confidence |
|----------|------------------------|
| Go | High (type-resolved call graphs) |
| Java (Spring) | Medium-High (annotation patterns) |
| TypeScript | Medium (structural analysis) |
| Python | Low-Medium (dynamic typing) |

For languages without strong semantic analysis, graphize-appsec should:

1. Report lower confidence scores
2. Flag for manual review
3. Use conservative (over-approximate) analysis

## References

- [Tree-sitter Documentation](https://tree-sitter.github.io/tree-sitter/)
- [Go Static Analysis Guide](https://github.com/golang/go/wiki/Static-Analysis)
- [Soot Framework](https://soot-oss.github.io/soot/)
- [Roslyn Overview](https://docs.microsoft.com/en-us/dotnet/csharp/roslyn-sdk/)
