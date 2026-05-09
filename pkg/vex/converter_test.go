package vex

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func TestNewConverter(t *testing.T) {
	c := NewConverter()

	if c.ToolName != "graphize-appsec" {
		t.Errorf("expected ToolName 'graphize-appsec', got %q", c.ToolName)
	}
	if c.ToolVersion != "0.1.0" {
		t.Errorf("expected ToolVersion '0.1.0', got %q", c.ToolVersion)
	}
	if c.ToolVendor != "PlexusOne" {
		t.Errorf("expected ToolVendor 'PlexusOne', got %q", c.ToolVendor)
	}
}

func TestConvertResult_NotAffected(t *testing.T) {
	c := NewConverter()

	// Create a result where the dependency is not imported (REACH-001 fails)
	result := &reachability.RunResult{
		Results: []*reachability.TestResult{
			{
				ID:         "REACH-001",
				Category:   reachability.CategoryReachable,
				Pass:       false,
				Confidence: 1.0,
				Evidence:   "Package not found in imports",
			},
		},
		CategoryScores: map[reachability.Category]*reachability.CategoryScore{
			reachability.CategoryReachable: {
				Score:     0.0,
				PassCount: 0,
				FailCount: 1,
			},
		},
	}

	vuln := c.ConvertResult("CVE-2024-12345", result, "pkg:golang/example.com/vulnerable@v1.0.0")

	if vuln.ID != "CVE-2024-12345" {
		t.Errorf("expected ID 'CVE-2024-12345', got %q", vuln.ID)
	}
	if vuln.Analysis == nil {
		t.Fatal("expected Analysis to be set")
	}
	if vuln.Analysis.State != cdx.IASNotAffected {
		t.Errorf("expected State 'not_affected', got %q", vuln.Analysis.State)
	}
	if vuln.Analysis.Justification != cdx.IAJCodeNotPresent {
		t.Errorf("expected Justification 'code_not_present', got %q", vuln.Analysis.Justification)
	}
	if vuln.Affects == nil || len(*vuln.Affects) == 0 {
		t.Error("expected Affects to be set")
	}
}

func TestConvertResult_CodeNotReachable(t *testing.T) {
	c := NewConverter()

	// Create a result where dependency is imported but not used (REACH-002 fails)
	result := &reachability.RunResult{
		Results: []*reachability.TestResult{
			{
				ID:         "REACH-001",
				Category:   reachability.CategoryReachable,
				Pass:       true,
				Confidence: 1.0,
			},
			{
				ID:         "REACH-002",
				Category:   reachability.CategoryReachable,
				Pass:       false,
				Confidence: 0.9,
				Evidence:   "No call paths to vulnerable function",
			},
		},
		CategoryScores: map[reachability.Category]*reachability.CategoryScore{
			reachability.CategoryReachable: {
				Score:     1.0,
				PassCount: 1,
				FailCount: 1,
			},
		},
	}

	vuln := c.ConvertResult("CVE-2024-12346", result, "")

	if vuln.Analysis.State != cdx.IASNotAffected {
		t.Errorf("expected State 'not_affected', got %q", vuln.Analysis.State)
	}
	if vuln.Analysis.Justification != cdx.IAJCodeNotReachable {
		t.Errorf("expected Justification 'code_not_reachable', got %q", vuln.Analysis.Justification)
	}
}

func TestConvertResult_Exploitable(t *testing.T) {
	c := NewConverter()

	// Create a result with high exploitability
	result := &reachability.RunResult{
		Results: []*reachability.TestResult{
			{
				ID:         "REACH-001",
				Category:   reachability.CategoryReachable,
				Pass:       true,
				Confidence: 1.0,
			},
			{
				ID:         "REACH-002",
				Category:   reachability.CategoryReachable,
				Pass:       true,
				Confidence: 1.0,
			},
			{
				ID:         "REACH-003",
				Category:   reachability.CategoryReachable,
				Pass:       true,
				Confidence: 1.0,
			},
			{
				ID:         "EXPLOIT-004",
				Category:   reachability.CategoryExploitable,
				Pass:       true,
				Confidence: 0.9,
			},
			{
				ID:         "DAMAGE-003",
				Category:   reachability.CategoryDamage,
				Pass:       true,
				Confidence: 1.0,
			},
		},
		CategoryScores: map[reachability.Category]*reachability.CategoryScore{
			reachability.CategoryReachable: {
				Score:         8.0,
				WeightedScore: 3.0,
				PassCount:     3,
				FailCount:     0,
			},
			reachability.CategoryExploitable: {
				Score:         7.0,
				WeightedScore: 2.5,
				PassCount:     1,
				FailCount:     0,
			},
			reachability.CategoryDamage: {
				Score:         8.0,
				WeightedScore: 2.0,
				PassCount:     1,
				FailCount:     0,
			},
		},
	}

	vuln := c.ConvertResult("CVE-2024-12347", result, "")

	if vuln.Analysis.State != cdx.IASExploitable {
		t.Errorf("expected State 'exploitable', got %q", vuln.Analysis.State)
	}
	if vuln.Analysis.Response == nil || len(*vuln.Analysis.Response) == 0 {
		t.Error("expected Response to be set for exploitable vuln")
	}
	if (*vuln.Analysis.Response)[0] != cdx.IARUpdate {
		t.Errorf("expected Response 'update', got %q", (*vuln.Analysis.Response)[0])
	}
}

func TestConvertResult_InTriage(t *testing.T) {
	c := NewConverter()

	// Create a result with moderate score (4.0 <= score < 7.0 = in_triage)
	result := &reachability.RunResult{
		Results: []*reachability.TestResult{
			{
				ID:         "REACH-001",
				Category:   reachability.CategoryReachable,
				Pass:       true,
				Confidence: 1.0,
			},
			{
				ID:         "REACH-002",
				Category:   reachability.CategoryReachable,
				Pass:       true,
				Confidence: 0.6,
			},
		},
		CategoryScores: map[reachability.Category]*reachability.CategoryScore{
			reachability.CategoryReachable: {
				Score:         5.0,
				WeightedScore: 5.0, // Total weighted score = 5.0, which is >= 4.0 and < 7.0
				PassCount:     2,
				FailCount:     0,
			},
		},
	}

	vuln := c.ConvertResult("CVE-2024-12348", result, "")

	if vuln.Analysis.State != cdx.IASInTriage {
		t.Errorf("expected State 'in_triage', got %q", vuln.Analysis.State)
	}
}

func TestConvertResult_ProtectedByEPSS(t *testing.T) {
	c := NewConverter()

	// Create a result where EPSS indicates low risk
	result := &reachability.RunResult{
		Results: []*reachability.TestResult{
			{
				ID:         "REACH-001",
				Category:   reachability.CategoryReachable,
				Pass:       true,
				Confidence: 1.0,
			},
			{
				ID:         "EXPLOIT-005", // EPSS Low Risk
				Category:   reachability.CategoryExploitable,
				Pass:       true, // Pass=true means EPSS is low (safe)
				Confidence: 1.0,
			},
		},
		CategoryScores: map[reachability.Category]*reachability.CategoryScore{
			reachability.CategoryReachable: {
				Score:     3.0,
				PassCount: 1,
				FailCount: 0,
			},
			reachability.CategoryExploitable: {
				Score:     2.0,
				PassCount: 1,
				FailCount: 0,
			},
		},
	}

	vuln := c.ConvertResult("CVE-2024-12349", result, "")

	if vuln.Analysis.State != cdx.IASNotAffected {
		t.Errorf("expected State 'not_affected', got %q", vuln.Analysis.State)
	}
	if vuln.Analysis.Justification != cdx.IAJProtectedByMitigatingControl {
		t.Errorf("expected Justification 'protected_by_mitigating_control', got %q", vuln.Analysis.Justification)
	}
}

func TestTestResultToJustification(t *testing.T) {
	tests := []struct {
		testID   string
		pass     bool
		expected cdx.ImpactAnalysisJustification
	}{
		{"REACH-001", false, cdx.IAJCodeNotPresent},
		{"REACH-002", false, cdx.IAJCodeNotReachable},
		{"REACH-003", false, cdx.IAJCodeNotReachable},
		{"REACH-007", false, cdx.IAJRequiresEnvironment},
		{"EXPLOIT-005", true, cdx.IAJProtectedByMitigatingControl},
		{"EXPLOIT-006", true, cdx.IAJProtectedAtRuntime},
		{"REACH-001", true, ""}, // No justification when present
		{"UNKNOWN", false, ""},  // Unknown test ID
	}

	for _, tc := range tests {
		t.Run(tc.testID, func(t *testing.T) {
			got := TestResultToJustification(tc.testID, tc.pass)
			if got != tc.expected {
				t.Errorf("TestResultToJustification(%q, %v) = %q, want %q",
					tc.testID, tc.pass, got, tc.expected)
			}
		})
	}
}

func TestCreateProperties(t *testing.T) {
	c := NewConverter()

	result := &reachability.RunResult{
		Results: []*reachability.TestResult{
			{
				ID:         "REACH-001",
				Category:   reachability.CategoryReachable,
				Pass:       true,
				Confidence: 0.95,
			},
		},
		CategoryScores: map[reachability.Category]*reachability.CategoryScore{
			reachability.CategoryReachable: {
				Score:     5.0,
				PassCount: 1,
				FailCount: 0,
			},
		},
	}

	props := c.createProperties(result)

	// Should have decision, weighted_score, category scores, and test results
	if len(props) < 4 {
		t.Errorf("expected at least 4 properties, got %d", len(props))
	}

	// Check for expected property names
	propNames := make(map[string]bool)
	for _, p := range props {
		propNames[p.Name] = true
	}

	expectedProps := []string{
		"graphize-appsec:decision",
		"graphize-appsec:weighted_score",
		"graphize-appsec:test:REACH-001:result",
		"graphize-appsec:test:REACH-001:confidence",
	}

	for _, name := range expectedProps {
		if !propNames[name] {
			t.Errorf("missing expected property: %s", name)
		}
	}
}
