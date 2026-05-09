# Market Requirements Document (MRD)

## graphize-appsec: Security Reachability Analysis Platform

**Version:** 0.1.0
**Status:** Draft
**Date:** 2025-05-08

---

## Executive Summary

graphize-appsec is a security analysis tool that leverages graphize's code knowledge graph to perform reachability analysis, vulnerability assessment, and VEX (Vulnerability Exploitability eXchange) generation.

---

## Market Context

### Problem Statement

Enterprise software organizations face critical challenges with vulnerability management:

1. **False Positive Overload**: Raw SBOM scanning generates thousands of CVE alerts, 97%+ of which are not exploitable in the actual deployment context
2. **Manual Triage Burden**: Security teams spend days manually assessing each vulnerability's reachability
3. **Customer Escalations**: Publishing raw SBOMs causes customer panic over non-exploitable vulnerabilities
4. **Lack of Context**: Existing tools report "vulnerability exists" without answering "is it reachable and exploitable?"

### Market Gap

Commercial reachability analysis solutions have limitations:

- No customer-extensible plugin SDK for custom languages (Groovy/Grails, proprietary DSLs)
- Closed-source algorithms prevent customization
- Expensive enterprise licensing
- Limited transparency into reachability reasoning

### Opportunity

Build an open, extensible reachability analysis platform on top of graphize that:

- Leverages graphize's existing code knowledge graph
- Provides transparent, auditable reachability tests
- Supports custom language analyzers via graphize-groovy pattern
- Generates structured evaluation reports via structured-evaluation
- Enables AI-assisted exploitability reasoning via MCP tools

---

## Target Users

### Primary: Application Security Engineers

- Triage vulnerability findings
- Generate VEX statements for customer communication
- Assess blast radius of new CVEs
- Prioritize remediation efforts

### Secondary: Security Architects

- Define reachability policies
- Configure severity thresholds
- Integrate with CI/CD pipelines
- Audit security posture across repositories

### Tertiary: Development Teams

- Understand vulnerability impact on their code
- Receive actionable remediation guidance
- Track security debt

---

## Use Cases

### UC-1: Vulnerability Reachability Assessment

**Actor:** Security Engineer
**Goal:** Determine if CVE-2021-44228 is exploitable in production

**Flow:**
1. Run `graphize analyze` to build code knowledge graph
2. Run `graphize-appsec assess CVE-2021-44228`
3. System runs 16 reachability tests (Reachable, Exploitable, Damage)
4. System generates structured evaluation report with Y/N per test
5. Security engineer reviews attack paths and evidence
6. System generates VEX statement if not exploitable

### UC-2: SBOM Security Enrichment

**Actor:** Release Engineer
**Goal:** Publish customer-facing SBOM with exploitability context

**Flow:**
1. Generate SBOM via Syft/cdxgen
2. Run `graphize-appsec enrich --sbom sbom.json`
3. System correlates SBOM components with code graph
4. System runs reachability analysis per vulnerability
5. System generates VEX statements for non-exploitable issues
6. Output: Enriched SBOM + VEX document

### UC-3: CI/CD Security Gate

**Actor:** CI Pipeline
**Goal:** Block releases with exploitable critical vulnerabilities

**Flow:**
1. Pipeline triggers `graphize-appsec gate --fail-on critical`
2. System runs reachability tests on all findings
3. Returns exit code 0 (pass) or 1 (fail)
4. Publishes structured report as pipeline artifact

### UC-4: AI-Assisted Triage

**Actor:** Security Engineer using Claude
**Goal:** Investigate complex vulnerability with AI assistance

**Flow:**
1. Connect graphize-appsec MCP server to Claude
2. Ask: "Is CVE-2021-44228 exploitable in our production deployment?"
3. AI uses `assess_vulnerability` tool to run reachability tests
4. AI uses `find_attack_paths` to trace entry points
5. AI synthesizes findings into human-readable explanation
6. AI generates VEX statement with evidence

---

## Key Differentiators

| Feature | graphize-appsec |
|---------|-----------------|
| Reachability analysis | ✅ |
| Custom language support | ✅ (via graphize plugins) |
| VEX generation | ✅ |
| Open source | ✅ |
| AI-assisted triage | ✅ (MCP) |
| Runtime context | ✅ (K8s adapter) |
| Transparent algorithms | ✅ |
| structured-evaluation reports | ✅ |

---

## Success Metrics

| Metric | Target |
|--------|--------|
| False positive reduction | >90% of CVEs correctly identified as non-exploitable |
| Triage time reduction | 80% faster than manual analysis |
| VEX generation accuracy | >95% correct exploitability determination |
| Language coverage | Go, Java, TypeScript, Groovy/Grails |
| CI/CD integration | <5 minute analysis for 100K LOC repository |

---

## Constraints

1. **Dependency on graphize**: Requires graphize code knowledge graph as foundation
2. **Static analysis limits**: Cannot detect runtime-only code paths
3. **CVE database dependency**: Requires external vulnerability intelligence (OSV, NVD)
4. **Language support**: Limited to languages with graphize extractors

---

## References

- [structured-evaluation](https://github.com/plexusone/structured-evaluation) - Report framework
- [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/) - VEX specification
