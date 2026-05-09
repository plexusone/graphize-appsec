# VEX Output Format Reference

graphize-appsec generates VEX (Vulnerability Exploitability eXchange) documents in CycloneDX format.

## What is VEX?

VEX is a standardized format for communicating whether a vulnerability is actually exploitable in a specific deployment context. It allows organizations to share assessments about:

- Whether a vulnerability affects their products
- Why a vulnerability doesn't apply (justification)
- What response actions are being taken

VEX reduces alert fatigue by providing context that scanners cannot determine on their own.

## CycloneDX VEX Format

graphize-appsec outputs CycloneDX 1.6 format, which embeds VEX data directly in the SBOM's `vulnerabilities` array.

### Document Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-08T20:12:49Z",
    "tools": {
      "components": [{
        "type": "application",
        "name": "graphize-appsec",
        "version": "0.1.0",
        "supplier": { "name": "PlexusOne" }
      }]
    },
    "component": { ... },
    "properties": [{
      "name": "graphize-appsec:enriched_at",
      "value": "2026-05-08T20:12:49Z"
    }]
  },
  "components": [ ... ],
  "vulnerabilities": [ ... ]
}
```

## VEX States

Each vulnerability includes an `analysis.state` field indicating the exploitability assessment:

| State | Meaning | Typical Score |
|-------|---------|---------------|
| `not_affected` | Vulnerability does not apply to this deployment | < 4.0 |
| `in_triage` | Assessment is ongoing, needs manual review | 4.0-6.9 |
| `exploitable` | Vulnerability is exploitable in this context | >= 7.0 |

### State Mapping from Test Results

```
Overall Score < 4.0  → not_affected
Overall Score 4.0-6.9 → in_triage
Overall Score >= 7.0  → exploitable
```

## VEX Justifications

When `state` is `not_affected`, the `analysis.justification` field explains why:

| Justification | Meaning | Triggered By |
|---------------|---------|--------------|
| `code_not_present` | Vulnerable code is not in the codebase | REACH-001 fail |
| `code_not_reachable` | Vulnerable code exists but cannot be reached | REACH-002 or REACH-003 fail |
| `requires_environment` | Exploitation requires specific environment | REACH-007 fail |
| `protected_by_mitigating_control` | External controls prevent exploitation | EXPLOIT-005 pass |
| `protected_at_runtime` | Runtime protections prevent exploitation | EXPLOIT-006 pass |

### Justification Mapping from Tests

| Test ID | Result | Justification |
|---------|--------|---------------|
| REACH-001 | Fail (N) | `code_not_present` |
| REACH-002 | Fail (N) | `code_not_reachable` |
| REACH-003 | Fail (N) | `code_not_reachable` |
| REACH-007 | Fail (N) | `requires_environment` |
| EXPLOIT-005 | Pass (Y) | `protected_by_mitigating_control` |
| EXPLOIT-006 | Pass (Y) | `protected_at_runtime` |

## Response Actions

The `analysis.response` array indicates what action is being taken:

| Response | Meaning |
|----------|---------|
| `will_not_fix` | No fix needed (not affected) |
| `update` | Updating to patched version (exploitable) |
| `workaround_available` | Temporary mitigation exists (in triage) |

## Custom Properties

graphize-appsec adds detailed analysis data in the `properties` array using the `graphize-appsec:` namespace.

### Overall Assessment

| Property | Description | Example |
|----------|-------------|---------|
| `graphize-appsec:decision` | Overall decision (pass/conditional/fail) | `"pass"` |
| `graphize-appsec:weighted_score` | Combined weighted score (0-10) | `"2.00"` |

### Category Scores

For each category (reachable, exploitable, damage):

| Property | Description |
|----------|-------------|
| `graphize-appsec:category:{cat}:score` | Category score (0-10) |
| `graphize-appsec:category:{cat}:pass_count` | Number of passing tests |
| `graphize-appsec:category:{cat}:fail_count` | Number of failing tests |

### Individual Test Results

For each test:

| Property | Description |
|----------|-------------|
| `graphize-appsec:test:{ID}:result` | Test result (`Y` or `N`) |
| `graphize-appsec:test:{ID}:confidence` | Confidence level (0.0-1.0) |

## Sample Vulnerability Entry

```json
{
  "id": "CVE-2022-31107",
  "tools": {
    "components": [{
      "type": "application",
      "supplier": { "name": "PlexusOne" },
      "name": "graphize-appsec",
      "version": "0.1.0"
    }]
  },
  "analysis": {
    "state": "not_affected",
    "justification": "code_not_present",
    "response": ["will_not_fix"],
    "detail": "1/7 reachability tests indicate exposure. Package grafana is not found in the dependency graph.",
    "firstIssued": "2026-05-08T20:12:49Z",
    "lastUpdated": "2026-05-08T20:12:49Z"
  },
  "affects": [{
    "ref": "pkg:golang/github.com/grafana/grafana@10.2.0"
  }],
  "properties": [
    { "name": "graphize-appsec:decision", "value": "pass" },
    { "name": "graphize-appsec:weighted_score", "value": "2.00" },
    { "name": "graphize-appsec:category:reachable:score", "value": "1.77" },
    { "name": "graphize-appsec:category:reachable:pass_count", "value": "1" },
    { "name": "graphize-appsec:category:reachable:fail_count", "value": "6" },
    { "name": "graphize-appsec:category:exploitable:score", "value": "0.65" },
    { "name": "graphize-appsec:category:exploitable:pass_count", "value": "1" },
    { "name": "graphize-appsec:category:exploitable:fail_count", "value": "5" },
    { "name": "graphize-appsec:category:damage:score", "value": "4.26" },
    { "name": "graphize-appsec:category:damage:pass_count", "value": "1" },
    { "name": "graphize-appsec:category:damage:fail_count", "value": "2" },
    { "name": "graphize-appsec:test:REACH-001:result", "value": "N" },
    { "name": "graphize-appsec:test:REACH-001:confidence", "value": "0.95" },
    { "name": "graphize-appsec:test:REACH-002:result", "value": "N" },
    { "name": "graphize-appsec:test:REACH-002:confidence", "value": "0.30" },
    { "name": "graphize-appsec:test:EXPLOIT-005:result", "value": "Y" },
    { "name": "graphize-appsec:test:EXPLOIT-005:confidence", "value": "0.90" }
  ]
}
```

## Interpreting Results

### Quick Assessment

1. Check `analysis.state`:
   - `not_affected` = Safe, no action needed
   - `in_triage` = Review manually
   - `exploitable` = Requires remediation

2. For `not_affected`, check `analysis.justification` for why

3. For details, look at custom properties:
   - `graphize-appsec:weighted_score` shows overall risk (0-10)
   - Category scores show where risk comes from
   - Individual test results explain specific findings

### Filtering Results

Use `jq` to filter the VEX output:

```bash
# List all exploitable vulnerabilities
jq '.vulnerabilities[] | select(.analysis.state == "exploitable") | .id' sbom-vex.json

# List vulnerabilities needing triage
jq '.vulnerabilities[] | select(.analysis.state == "in_triage") | .id' sbom-vex.json

# Get score for a specific CVE
jq '.vulnerabilities[] | select(.id == "CVE-2022-31107") | .properties[] | select(.name == "graphize-appsec:weighted_score")' sbom-vex.json

# List high-scoring vulnerabilities (score >= 5)
jq '.vulnerabilities[] | select((.properties[] | select(.name == "graphize-appsec:weighted_score") | .value | tonumber) >= 5) | .id' sbom-vex.json
```

## Integration with Other Tools

### Consuming VEX in CI/CD

```bash
# Fail if any exploitable vulnerabilities
EXPLOITABLE=$(jq '[.vulnerabilities[] | select(.analysis.state == "exploitable")] | length' sbom-vex.json)
if [ "$EXPLOITABLE" -gt 0 ]; then
  echo "Found $EXPLOITABLE exploitable vulnerabilities"
  exit 1
fi
```

### Merging with Existing SBOMs

The `vex enrich` command automatically merges VEX data into existing SBOMs. For standalone VEX documents, use `vex generate`.

## References

- [CycloneDX VEX Specification](https://cyclonedx.org/capabilities/vex/)
- [CISA VEX Use Cases](https://www.cisa.gov/sites/default/files/publications/VEX_Use_Cases_April2022.pdf)
- [VEX Status Justifications](https://cyclonedx.org/docs/1.6/json/#vulnerabilities_items_analysis_justification)
