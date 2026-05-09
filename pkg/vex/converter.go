// Package vex provides CycloneDX VEX (Vulnerability Exploitability eXchange) output.
// It converts graphize-appsec reachability test results into standards-compliant
// CycloneDX vulnerability analysis suitable for SBOM enrichment.
package vex

import (
	"fmt"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

// Converter transforms reachability test results into CycloneDX VEX format.
type Converter struct {
	// ToolName is the name of the tool generating the VEX data.
	ToolName string

	// ToolVersion is the version of the tool.
	ToolVersion string

	// ToolVendor is the vendor of the tool.
	ToolVendor string
}

// NewConverter creates a new VEX converter with default settings.
func NewConverter() *Converter {
	return &Converter{
		ToolName:    "graphize-appsec",
		ToolVersion: "0.1.0",
		ToolVendor:  "PlexusOne",
	}
}

// ConvertResult converts a single reachability run result to a CycloneDX Vulnerability.
func (c *Converter) ConvertResult(vulnID string, result *reachability.RunResult, affectedRef string) *cdx.Vulnerability {
	state, justification := c.determineStateAndJustification(result)
	detail := c.generateDetail(result)
	responses := c.determineResponses(result, state)

	now := time.Now().UTC().Format(time.RFC3339)

	vuln := &cdx.Vulnerability{
		ID: vulnID,
		Analysis: &cdx.VulnerabilityAnalysis{
			State:         state,
			Justification: justification,
			Detail:        detail,
			FirstIssued:   now,
			LastUpdated:   now,
		},
		Tools: c.createToolsChoice(),
	}

	if len(responses) > 0 {
		vuln.Analysis.Response = &responses
	}

	// Add affected component reference
	if affectedRef != "" {
		vuln.Affects = &[]cdx.Affects{
			{Ref: affectedRef},
		}
	}

	// Add properties with detailed test results
	props := c.createProperties(result)
	if len(props) > 0 {
		vuln.Properties = &props
	}

	return vuln
}

// determineStateAndJustification maps test results to VEX state and justification.
func (c *Converter) determineStateAndJustification(result *reachability.RunResult) (cdx.ImpactAnalysisState, cdx.ImpactAnalysisJustification) {
	// Check category scores to determine overall state
	reachScore := result.CategoryScores[reachability.CategoryReachable]
	exploitScore := result.CategoryScores[reachability.CategoryExploitable]

	// If reachability tests indicate no exposure, it's not affected
	if reachScore != nil && reachScore.Score < 3.0 && reachScore.PassCount == 0 {
		return cdx.IASNotAffected, c.determineJustification(result)
	}

	// Check individual test results for specific justifications
	for _, testResult := range result.Results {
		// REACH-001: Dependency not imported
		if testResult.ID == "REACH-001" && !testResult.Pass {
			return cdx.IASNotAffected, cdx.IAJCodeNotPresent
		}

		// REACH-002: Dependency not used (code not reachable)
		if testResult.ID == "REACH-002" && !testResult.Pass {
			return cdx.IASNotAffected, cdx.IAJCodeNotReachable
		}
	}

	// If exploitability tests show low risk
	if exploitScore != nil && exploitScore.Score < 3.0 {
		// Check for specific mitigations
		for _, testResult := range result.Results {
			// EXPLOIT-005: EPSS Low Risk
			if testResult.ID == "EXPLOIT-005" && testResult.Pass {
				return cdx.IASNotAffected, cdx.IAJProtectedByMitigatingControl
			}
			// EXPLOIT-006: AI Unexploitable
			if testResult.ID == "EXPLOIT-006" && testResult.Pass {
				return cdx.IASNotAffected, cdx.IAJProtectedAtRuntime
			}
		}
	}

	// Determine if exploitable based on overall score
	totalScore := result.WeightedScore()
	switch {
	case totalScore >= 7.0:
		return cdx.IASExploitable, ""
	case totalScore >= 4.0:
		return cdx.IASInTriage, ""
	default:
		return cdx.IASNotAffected, c.determineJustification(result)
	}
}

// determineJustification finds the most appropriate justification from test results.
func (c *Converter) determineJustification(result *reachability.RunResult) cdx.ImpactAnalysisJustification {
	// Check each test result for justification hints
	for _, testResult := range result.Results {
		if testResult.Pass {
			continue // Only look at failing tests for justification
		}

		switch testResult.ID {
		case "REACH-001": // Dependency not imported
			return cdx.IAJCodeNotPresent
		case "REACH-002": // Dependency not used
			return cdx.IAJCodeNotReachable
		case "REACH-003": // Not exposed by API
			return cdx.IAJCodeNotReachable
		case "REACH-007": // Not deployed
			return cdx.IAJRequiresEnvironment
		}
	}

	// Default to code not reachable if no specific justification found
	return cdx.IAJCodeNotReachable
}

// determineResponses determines appropriate responses based on state.
func (c *Converter) determineResponses(result *reachability.RunResult, state cdx.ImpactAnalysisState) []cdx.ImpactAnalysisResponse {
	var responses []cdx.ImpactAnalysisResponse

	switch state {
	case cdx.IASNotAffected:
		responses = append(responses, cdx.IARWillNotFix)
	case cdx.IASExploitable:
		responses = append(responses, cdx.IARUpdate)
	case cdx.IASInTriage:
		// Check if there's a workaround
		if c.hasWorkaround(result) {
			responses = append(responses, cdx.IARWorkaroundAvailable)
		}
	}

	return responses
}

// hasWorkaround checks if test results indicate a workaround exists.
func (c *Converter) hasWorkaround(result *reachability.RunResult) bool {
	// Check for mitigating controls in test results
	for _, testResult := range result.Results {
		if details, ok := testResult.Details["has_workaround"].(bool); ok && details {
			return true
		}
	}
	return false
}

// generateDetail creates a human-readable detail string from test results.
func (c *Converter) generateDetail(result *reachability.RunResult) string {
	var detail string

	// Add category summaries
	for _, cat := range reachability.AllCategories() {
		if score, ok := result.CategoryScores[cat]; ok && score.Justification != "" {
			if detail != "" {
				detail += " "
			}
			detail += score.Justification + "."
		}
	}

	// Add key evidence from individual tests
	for _, testResult := range result.Results {
		if testResult.Evidence != "" && testResult.Confidence >= 0.8 {
			// Include high-confidence evidence
			if !testResult.Pass && testResult.Category == reachability.CategoryReachable {
				if detail != "" {
					detail += " "
				}
				detail += testResult.Evidence + "."
			}
		}
	}

	if detail == "" {
		decision := result.Decision()
		detail = fmt.Sprintf("Reachability analysis completed with decision: %s (score: %.1f/10)", decision, result.WeightedScore())
	}

	return detail
}

// createToolsChoice creates the tools metadata for the VEX.
func (c *Converter) createToolsChoice() *cdx.ToolsChoice {
	return &cdx.ToolsChoice{
		Components: &[]cdx.Component{
			{
				Type:    cdx.ComponentTypeApplication,
				Name:    c.ToolName,
				Version: c.ToolVersion,
				Supplier: &cdx.OrganizationalEntity{
					Name: c.ToolVendor,
				},
			},
		},
	}
}

// createProperties creates custom properties with detailed test results.
func (c *Converter) createProperties(result *reachability.RunResult) []cdx.Property {
	var props []cdx.Property

	// Add overall scores
	props = append(props, cdx.Property{
		Name:  "graphize-appsec:decision",
		Value: string(result.Decision()),
	})
	props = append(props, cdx.Property{
		Name:  "graphize-appsec:weighted_score",
		Value: fmt.Sprintf("%.2f", result.WeightedScore()),
	})

	// Add category scores
	for _, cat := range reachability.AllCategories() {
		if score, ok := result.CategoryScores[cat]; ok {
			props = append(props, cdx.Property{
				Name:  fmt.Sprintf("graphize-appsec:category:%s:score", cat),
				Value: fmt.Sprintf("%.2f", score.Score),
			})
			props = append(props, cdx.Property{
				Name:  fmt.Sprintf("graphize-appsec:category:%s:pass_count", cat),
				Value: fmt.Sprintf("%d", score.PassCount),
			})
			props = append(props, cdx.Property{
				Name:  fmt.Sprintf("graphize-appsec:category:%s:fail_count", cat),
				Value: fmt.Sprintf("%d", score.FailCount),
			})
		}
	}

	// Add individual test results
	for _, testResult := range result.Results {
		passStr := "N"
		if testResult.Pass {
			passStr = "Y"
		}
		props = append(props, cdx.Property{
			Name:  fmt.Sprintf("graphize-appsec:test:%s:result", testResult.ID),
			Value: passStr,
		})
		props = append(props, cdx.Property{
			Name:  fmt.Sprintf("graphize-appsec:test:%s:confidence", testResult.ID),
			Value: fmt.Sprintf("%.2f", testResult.Confidence),
		})
	}

	return props
}

// TestResultToJustification maps a specific test ID to a VEX justification.
func TestResultToJustification(testID string, pass bool) cdx.ImpactAnalysisJustification {
	// For tests where Pass=false means "safe"
	if !pass {
		switch testID {
		case "REACH-001":
			return cdx.IAJCodeNotPresent
		case "REACH-002", "REACH-003":
			return cdx.IAJCodeNotReachable
		case "REACH-007":
			return cdx.IAJRequiresEnvironment
		}
	}

	// For tests where Pass=true means "safe" (inverted semantics)
	if pass {
		switch testID {
		case "EXPLOIT-005": // EPSS Low Risk
			return cdx.IAJProtectedByMitigatingControl
		case "EXPLOIT-006": // AI Unexploitable
			return cdx.IAJProtectedAtRuntime
		}
	}

	return ""
}
