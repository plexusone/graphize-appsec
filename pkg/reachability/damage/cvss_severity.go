// Package damage implements damage assessment tests.
package damage

import (
	"fmt"

	"github.com/plexusone/structured-evaluation/evaluation"

	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func init() {
	reachability.Register(NewCVSSHighSeverityTest())
}

// CVSSHighSeverityTest checks if CVSS indicates high severity.
type CVSSHighSeverityTest struct {
	reachability.BaseTest
}

// NewCVSSHighSeverityTest creates a new test.
func NewCVSSHighSeverityTest() *CVSSHighSeverityTest {
	return &CVSSHighSeverityTest{
		BaseTest: reachability.NewBaseTest(
			"DAMAGE-003",
			"CVSS High Severity",
			"Checks if CVSS score indicates high or critical severity",
			reachability.CategoryDamage,
		),
	}
}

// Evaluate runs the test.
func (t *CVSSHighSeverityTest) Evaluate(ctx *reachability.EvalContext) (*reachability.TestResult, error) {
	threshold := ctx.Config.HighSeverityCVSS
	if threshold <= 0 {
		threshold = 7.0 // Default high severity threshold
	}

	// Check if we have CVSS score from vuln info
	if ctx.VulnInfo == nil || ctx.VulnInfo.CVSSScore <= 0 {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false,
			Confidence: 0.3,
			Severity:   evaluation.SeverityInfo,
			Evidence:   "CVSS score not available",
			Details: map[string]any{
				"reason": "no_cvss_data",
			},
		}, nil
	}

	cvssScore := ctx.VulnInfo.CVSSScore

	// Determine severity category
	var severityCategory string
	var evalSeverity evaluation.Severity

	switch {
	case cvssScore >= 9.0:
		severityCategory = "Critical"
		evalSeverity = evaluation.SeverityCritical
	case cvssScore >= 7.0:
		severityCategory = "High"
		evalSeverity = evaluation.SeverityHigh
	case cvssScore >= 4.0:
		severityCategory = "Medium"
		evalSeverity = evaluation.SeverityMedium
	default:
		severityCategory = "Low"
		evalSeverity = evaluation.SeverityLow
	}

	if cvssScore >= threshold {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       true, // High severity - damage potential exists
			Confidence: 1.0,
			Severity:   evalSeverity,
			Evidence:   fmt.Sprintf("CVSS score %.1f (%s) indicates high damage potential", cvssScore, severityCategory),
			Details: map[string]any{
				"cvss_score":        cvssScore,
				"cvss_vector":       ctx.VulnInfo.CVSSVector,
				"severity_category": severityCategory,
				"threshold":         threshold,
			},
		}, nil
	}

	return &reachability.TestResult{
		ID:         t.ID(),
		Name:       t.Name(),
		Category:   t.Category(),
		Pass:       false, // Low severity - limited damage potential
		Confidence: 1.0,
		Severity:   evalSeverity,
		Evidence:   fmt.Sprintf("CVSS score %.1f (%s) indicates limited damage potential", cvssScore, severityCategory),
		Details: map[string]any{
			"cvss_score":        cvssScore,
			"cvss_vector":       ctx.VulnInfo.CVSSVector,
			"severity_category": severityCategory,
			"threshold":         threshold,
		},
	}, nil
}
