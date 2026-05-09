# Reachability Tests Reference

graphize-appsec runs 16 tests across three categories to determine if a vulnerability is actually exploitable in your deployment.

## Overview

### Categories

| Category | Tests | Weight | Purpose |
|----------|-------|--------|---------|
| Reachable | 7 | 40% | Is the vulnerable code actually reachable? |
| Exploitable | 6 | 35% | Is the vulnerability exploitable in practice? |
| Damage | 3 | 25% | What is the potential damage if exploited? |

### Scoring System

Each test produces:

- **Pass/Fail (Y/N)** - Whether the condition is true
- **Confidence (0.0-1.0)** - Certainty of the result
- **Severity** - Security severity based on the result
- **Evidence** - Human-readable explanation

Category scores are calculated as weighted averages (0-10 scale), then combined into an overall weighted score:

```
Overall Score = (Reachable × 0.40) + (Exploitable × 0.35) + (Damage × 0.25)
```

### Decision Thresholds

| Score | Decision | Meaning |
|-------|----------|---------|
| < 4.0 | PASS | Vulnerability is not exploitable |
| 4.0-6.9 | CONDITIONAL | Needs manual review |
| >= 7.0 | FAIL | Vulnerability is exploitable |

---

## Category: Reachable

Tests whether the vulnerable code is actually reachable from your application.

### REACH-001: Dependency Imported

**ID:** `REACH-001`
**Name:** Dependency Imported
**Description:** Checks if the vulnerable package is imported in the codebase

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Package IS imported | Risk exists |
| Fail (N) | Package NOT imported | No risk - vulnerability does not apply |

**How it works:** Searches the code graph for package or module nodes matching the affected package name.

**Confidence levels:**

- 1.0 - Package found in graph
- 0.95 - Package not found (high confidence it's absent)
- 0.5 - No affected package specified (incomplete data)

---

### REACH-002: Dependency Used

**ID:** `REACH-002`
**Name:** Dependency Used
**Description:** Checks if the vulnerable code is actually called from entry points

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Call path exists to vulnerable code | High risk |
| Fail (N) | No call path found | Low risk - code is unreachable |

**How it works:** Performs graph traversal from entry points (HTTP handlers, main functions, etc.) to affected functions, following `calls` edges.

**Confidence levels:**

- 1.0 - Call path found
- 0.85 - No path found (accounts for potential dynamic calls)
- 0.3 - No targets identified

---

### REACH-003: Exposed by API

**ID:** `REACH-003`
**Name:** Exposed by API
**Description:** Checks if vulnerable code is reachable from a public API endpoint

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | API endpoint can reach vulnerable code | Critical risk (public if no auth) |
| Fail (N) | No API path to vulnerable code | Lower risk |

**How it works:** Identifies HTTP handler functions (via annotations, framework patterns, or graph attributes) and traces paths to affected code.

**Evidence includes:**

- API endpoint path and HTTP method
- Whether authentication is required
- Call depth to vulnerable code

**Confidence levels:**

- 1.0 - API path found
- 0.9 - No API path found
- 0.6 - No API endpoints detected (may not use detected frameworks)

---

### REACH-004: Direct Dependency

**ID:** `REACH-004`
**Name:** Direct Dependency
**Description:** Checks if the vulnerable package is a direct dependency (not transitive)

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Direct dependency | Higher risk - you control this |
| Fail (N) | Transitive dependency | Lower risk - harder to reach |

**How it works:** Examines dependency graph depth. Direct dependencies are typically easier to exploit as they're more likely to be invoked directly.

---

### REACH-005: Public Repository

**ID:** `REACH-005`
**Name:** Public Repository
**Description:** Checks if the vulnerability is in a public repository

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Public repository | Higher exposure |
| Fail (N) | Private/internal repository | Lower exposure |

**How it works:** Checks repository visibility metadata. Public repositories may have more eyes on exploitation attempts.

---

### REACH-006: Application Layer

**ID:** `REACH-006`
**Name:** Application Layer
**Description:** Checks if the vulnerability is in the application layer (not infrastructure)

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Application layer code | More directly exploitable |
| Fail (N) | Infrastructure layer code | Requires additional access |

**How it works:** Matches package names against infrastructure patterns:

- `k8s.io/`, `kubernetes/`
- `docker/`, `containerd/`
- `prometheus/`, `grafana/`
- `terraform`, `ansible`, `helm`
- `istio`, `envoy`

Infrastructure-layer vulnerabilities typically require cluster or system access to exploit.

---

### REACH-007: Cloud Deployed

**ID:** `REACH-007`
**Name:** Cloud Deployed
**Description:** Checks if the container with the vulnerability is actually running

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Container is deployed | Active risk |
| Fail (N) | Not deployed or unknown | No active risk |

**How it works:** Integrates with deployment metadata (Kubernetes manifests, Docker Compose, etc.) to verify the vulnerable component is actually running.

---

## Category: Exploitable

Tests whether the vulnerability is practically exploitable.

### EXPLOIT-001: Weak Cryptography

**ID:** `EXPLOIT-001`
**Name:** Weak Cryptography
**Description:** Checks if the execution path involves weak cryptographic functions

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Weak crypto in path | Crypto vulnerabilities more severe |
| Fail (N) | No weak crypto found | Standard risk |

**How it works:** Scans call paths for known weak crypto patterns (MD5, SHA1 for hashing, DES, RC4, etc.).

---

### EXPLOIT-002: Community Buzz

**ID:** `EXPLOIT-002`
**Name:** Community Buzz
**Description:** Checks for active exploitation discussion in security community

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Active discussion | Higher likelihood of exploitation |
| Fail (N) | No significant discussion | Lower immediate risk |

**How it works:** Checks threat intelligence feeds, Twitter/X mentions, security blogs, and exploit databases for recent activity.

---

### EXPLOIT-003: Extensive Patching

**ID:** `EXPLOIT-003`
**Name:** Extensive Patching
**Description:** Checks if the vulnerability has required multiple patch iterations

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Multiple patches issued | Complex issue, may have bypass |
| Fail (N) | Single patch or none | Standard patching |

**How it works:** Counts the number of related CVEs or patch versions for the same underlying issue.

---

### EXPLOIT-004: Multiple Public Exploits

**ID:** `EXPLOIT-004`
**Name:** Multiple Public Exploits
**Description:** Checks for availability of public exploits

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Public exploits available | High risk - easy to exploit |
| Fail (N) | No public exploits | Requires custom development |

**How it works:** Checks exploit databases (Exploit-DB, Metasploit, GitHub PoCs) for available exploit code.

---

### EXPLOIT-005: EPSS Low Risk

**ID:** `EXPLOIT-005`
**Name:** EPSS Low Exploit Risk
**Description:** Checks if EPSS (Exploit Prediction Scoring System) indicates low exploitation probability

!!! note "Inverted Semantics"
    This test has **inverted semantics**: Pass = SAFE, Fail = RISKY

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | EPSS < 10% | Low exploitation probability (GOOD) |
| Fail (N) | EPSS >= 10% | High exploitation probability (BAD) |

**How it works:** Compares the EPSS score against a configurable threshold (default 10%). EPSS predicts the probability of exploitation in the next 30 days.

**Confidence:** 0.9 when EPSS data is available, 0.3 when missing.

---

### EXPLOIT-006: AI Unexploitable

**ID:** `EXPLOIT-006`
**Name:** AI Unexploitable
**Description:** AI-powered simulation determines if exploitation is feasible

!!! note "Inverted Semantics"
    This test has **inverted semantics**: Pass = SAFE, Fail = RISKY

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | AI says unexploitable | Risk mitigated (GOOD) |
| Fail (N) | AI says exploitable or unknown | Risk exists (BAD) |

**How it works:** Integrates with AI/LLM analysis to simulate exploitation attempts. Considers:

- Code patterns and constraints
- Input validation
- Runtime protections
- Symbolic execution results

**Confidence:** Based on AI model confidence (0.2-1.0).

---

## Category: Damage

Tests the potential damage if the vulnerability is exploited.

### DAMAGE-001: Critical Business Priority

**ID:** `DAMAGE-001`
**Name:** Critical Business Priority
**Description:** Checks if the affected component is business-critical

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Critical system affected | High damage potential |
| Fail (N) | Non-critical system | Lower damage potential |

**How it works:** Checks component metadata and business criticality tags to determine if the affected code handles sensitive operations.

---

### DAMAGE-002: Login Management

**ID:** `DAMAGE-002`
**Name:** Login Management
**Description:** Checks if the vulnerability affects authentication or login functionality

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | Affects auth/login | Critical damage potential |
| Fail (N) | Does not affect auth | Standard damage potential |

**How it works:** Traces call paths to authentication-related code (login handlers, session management, token validation, OAuth flows).

---

### DAMAGE-003: CVSS High Severity

**ID:** `DAMAGE-003`
**Name:** CVSS High Severity
**Description:** Checks if CVSS score indicates high or critical severity

| Result | Meaning | Risk |
|--------|---------|------|
| Pass (Y) | CVSS >= 7.0 | High/Critical severity |
| Fail (N) | CVSS < 7.0 | Medium/Low severity |

**How it works:** Compares the CVSS base score against a configurable threshold (default 7.0).

**CVSS Severity Mapping:**

| Score | Category |
|-------|----------|
| 9.0+ | Critical |
| 7.0-8.9 | High |
| 4.0-6.9 | Medium |
| < 4.0 | Low |

**Confidence:** 1.0 when CVSS data is available, 0.3 when missing.

---

## Confidence Interpretation

| Level | Range | Meaning |
|-------|-------|---------|
| High | 0.8-1.0 | Strong evidence, deterministic result |
| Medium | 0.5-0.79 | Reasonable confidence, some uncertainty |
| Low | < 0.5 | Limited data, result should be verified manually |

Results with low confidence should trigger manual review. The system accounts for confidence when calculating category scores.
