package vex

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func TestNewSBOMEnricher(t *testing.T) {
	e := NewSBOMEnricher()
	if e == nil {
		t.Fatal("expected non-nil enricher")
	}
	if e.converter == nil {
		t.Fatal("expected converter to be initialized")
	}
}

func TestSetToolInfo(t *testing.T) {
	e := NewSBOMEnricher()
	e.SetToolInfo("test-tool", "1.0.0", "TestVendor")

	if e.converter.ToolName != "test-tool" {
		t.Errorf("expected ToolName 'test-tool', got %q", e.converter.ToolName)
	}
	if e.converter.ToolVersion != "1.0.0" {
		t.Errorf("expected ToolVersion '1.0.0', got %q", e.converter.ToolVersion)
	}
	if e.converter.ToolVendor != "TestVendor" {
		t.Errorf("expected ToolVendor 'TestVendor', got %q", e.converter.ToolVendor)
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		path     string
		expected cdx.BOMFileFormat
	}{
		{"sbom.json", cdx.BOMFileFormatJSON},
		{"sbom.xml", cdx.BOMFileFormatXML},
		{"sbom.XML", cdx.BOMFileFormatXML},
		{"sbom.cdx", cdx.BOMFileFormatJSON}, // Default
		{"/path/to/file.json", cdx.BOMFileFormatJSON},
		{"/path/to/file.xml", cdx.BOMFileFormatXML},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := detectFormat(tc.path)
			if got != tc.expected {
				t.Errorf("detectFormat(%q) = %v, want %v", tc.path, got, tc.expected)
			}
		})
	}
}

func TestDecodeSBOM(t *testing.T) {
	jsonSBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"version": 1,
		"components": [
			{
				"type": "library",
				"name": "test-component",
				"version": "1.0.0",
				"bom-ref": "pkg:golang/test-component@1.0.0"
			}
		]
	}`

	bom, err := DecodeSBOM(strings.NewReader(jsonSBOM), cdx.BOMFileFormatJSON)
	if err != nil {
		t.Fatalf("DecodeSBOM failed: %v", err)
	}

	if bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatal("expected components in BOM")
	}

	comp := (*bom.Components)[0]
	if comp.Name != "test-component" {
		t.Errorf("expected component name 'test-component', got %q", comp.Name)
	}
}

func TestEncodeSBOM(t *testing.T) {
	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{
		{
			Type:    cdx.ComponentTypeLibrary,
			Name:    "test-lib",
			Version: "2.0.0",
		},
	}

	var buf bytes.Buffer
	err := EncodeSBOM(bom, &buf, cdx.BOMFileFormatJSON)
	if err != nil {
		t.Fatalf("EncodeSBOM failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test-lib") {
		t.Error("expected output to contain component name")
	}
	if !strings.Contains(output, "2.0.0") {
		t.Error("expected output to contain version")
	}
}

func TestEnrich_NewVulnerability(t *testing.T) {
	e := NewSBOMEnricher()

	// Create SBOM with a component
	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{
		{
			Type:       cdx.ComponentTypeLibrary,
			Name:       "vulnerable-lib",
			Version:    "1.0.0",
			BOMRef:     "pkg:golang/vulnerable-lib@1.0.0",
			PackageURL: "pkg:golang/vulnerable-lib@1.0.0",
		},
	}

	// Create vulnerability result
	vulnResults := map[string]*reachability.RunResult{
		"CVE-2024-1111": {
			Results: []*reachability.TestResult{
				{
					ID:       "REACH-001",
					Category: reachability.CategoryReachable,
					Pass:     false,
					Details: map[string]any{
						"package": "vulnerable-lib",
					},
				},
			},
			CategoryScores: map[reachability.Category]*reachability.CategoryScore{
				reachability.CategoryReachable: {
					Score:     0.0,
					PassCount: 0,
					FailCount: 1,
				},
			},
		},
	}

	result, err := e.Enrich(bom, vulnResults)
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	if result.OriginalVulnCount != 0 {
		t.Errorf("expected OriginalVulnCount 0, got %d", result.OriginalVulnCount)
	}
	if result.AddedVulnCount != 1 {
		t.Errorf("expected AddedVulnCount 1, got %d", result.AddedVulnCount)
	}
	if result.EnrichedVulnCount != 1 {
		t.Errorf("expected EnrichedVulnCount 1, got %d", result.EnrichedVulnCount)
	}
	if result.NotAffectedCount != 1 {
		t.Errorf("expected NotAffectedCount 1, got %d", result.NotAffectedCount)
	}

	// Check the vulnerability was added
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) == 0 {
		t.Fatal("expected vulnerability to be added")
	}

	vuln := (*bom.Vulnerabilities)[0]
	if vuln.ID != "CVE-2024-1111" {
		t.Errorf("expected vuln ID 'CVE-2024-1111', got %q", vuln.ID)
	}
	if vuln.Analysis.State != cdx.IASNotAffected {
		t.Errorf("expected state 'not_affected', got %q", vuln.Analysis.State)
	}
}

func TestEnrich_UpdateExisting(t *testing.T) {
	e := NewSBOMEnricher()

	// Create SBOM with existing vulnerability
	bom := cdx.NewBOM()
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID: "CVE-2024-2222",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASInTriage,
			},
		},
	}

	// Create result that marks it as not affected
	vulnResults := map[string]*reachability.RunResult{
		"CVE-2024-2222": {
			Results: []*reachability.TestResult{
				{
					ID:       "REACH-002",
					Category: reachability.CategoryReachable,
					Pass:     false,
				},
			},
			CategoryScores: map[reachability.Category]*reachability.CategoryScore{
				reachability.CategoryReachable: {
					Score:     0.0,
					PassCount: 0,
					FailCount: 1,
				},
			},
		},
	}

	result, err := e.Enrich(bom, vulnResults)
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	if result.OriginalVulnCount != 1 {
		t.Errorf("expected OriginalVulnCount 1, got %d", result.OriginalVulnCount)
	}
	if result.UpdatedVulnCount != 1 {
		t.Errorf("expected UpdatedVulnCount 1, got %d", result.UpdatedVulnCount)
	}
	if result.AddedVulnCount != 0 {
		t.Errorf("expected AddedVulnCount 0, got %d", result.AddedVulnCount)
	}

	// Check the vulnerability was updated
	vuln := (*bom.Vulnerabilities)[0]
	if vuln.Analysis.State != cdx.IASNotAffected {
		t.Errorf("expected state to be updated to 'not_affected', got %q", vuln.Analysis.State)
	}
}

func TestFindAffectedRef(t *testing.T) {
	e := NewSBOMEnricher()

	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{
		{
			Type:       cdx.ComponentTypeLibrary,
			Name:       "lib-a",
			Version:    "1.0.0",
			BOMRef:     "ref-a",
			PackageURL: "pkg:golang/lib-a@1.0.0",
		},
		{
			Type:       cdx.ComponentTypeLibrary,
			Name:       "lib-b",
			Version:    "2.0.0",
			BOMRef:     "ref-b",
			PackageURL: "pkg:golang/lib-b@2.0.0",
		},
	}

	tests := []struct {
		name     string
		pkg      string
		expected string
	}{
		{"match by name", "lib-a", "ref-a"},
		{"match by purl", "lib-b", "ref-b"},
		{"no match", "lib-c", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &reachability.RunResult{
				Results: []*reachability.TestResult{
					{
						Details: map[string]any{
							"package": tc.pkg,
						},
					},
				},
			}

			ref := e.findAffectedRef(bom, result)
			if ref != tc.expected {
				t.Errorf("findAffectedRef for %q = %q, want %q", tc.pkg, ref, tc.expected)
			}
		})
	}
}

func TestCreateVEXDocument(t *testing.T) {
	e := NewSBOMEnricher()
	e.SetToolInfo("vex-test", "1.0.0", "TestOrg")

	vulnResults := map[string]*reachability.RunResult{
		"CVE-2024-3333": {
			Results: []*reachability.TestResult{
				{
					ID:       "REACH-001",
					Category: reachability.CategoryReachable,
					Pass:     false,
				},
			},
			CategoryScores: map[reachability.Category]*reachability.CategoryScore{
				reachability.CategoryReachable: {
					Score:     0.0,
					PassCount: 0,
					FailCount: 1,
				},
			},
		},
		"CVE-2024-4444": {
			Results: []*reachability.TestResult{
				{
					ID:       "REACH-001",
					Category: reachability.CategoryReachable,
					Pass:     true,
				},
				{
					ID:       "REACH-002",
					Category: reachability.CategoryReachable,
					Pass:     true,
				},
			},
			CategoryScores: map[reachability.Category]*reachability.CategoryScore{
				reachability.CategoryReachable: {
					Score:     8.0,
					PassCount: 2,
					FailCount: 0,
				},
			},
		},
	}

	bom := e.CreateVEXDocument(vulnResults)

	if bom.Metadata == nil {
		t.Fatal("expected metadata")
	}
	if bom.Metadata.Tools == nil || bom.Metadata.Tools.Components == nil {
		t.Fatal("expected tools in metadata")
	}
	if (*bom.Metadata.Tools.Components)[0].Name != "vex-test" {
		t.Errorf("expected tool name 'vex-test', got %q", (*bom.Metadata.Tools.Components)[0].Name)
	}

	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(*bom.Vulnerabilities))
	}

	// Check that document type property is set
	foundDocType := false
	for _, prop := range *bom.Metadata.Properties {
		if prop.Name == "graphize-appsec:document_type" && prop.Value == "vex" {
			foundDocType = true
			break
		}
	}
	if !foundDocType {
		t.Error("expected document_type property to be 'vex'")
	}
}

func TestUpdateMetadata(t *testing.T) {
	e := NewSBOMEnricher()
	e.SetToolInfo("enricher", "2.0.0", "Vendor")

	bom := cdx.NewBOM()
	e.updateMetadata(bom)

	if bom.Metadata == nil {
		t.Fatal("expected metadata")
	}
	if bom.Metadata.Timestamp == "" {
		t.Error("expected timestamp to be set")
	}
	if bom.Metadata.Tools == nil || bom.Metadata.Tools.Components == nil {
		t.Fatal("expected tools")
	}
	if len(*bom.Metadata.Tools.Components) == 0 {
		t.Error("expected at least one tool component")
	}

	// Check enrichment property
	if bom.Metadata.Properties == nil {
		t.Fatal("expected properties")
	}

	foundEnrichedAt := false
	for _, prop := range *bom.Metadata.Properties {
		if prop.Name == "graphize-appsec:enriched_at" {
			foundEnrichedAt = true
			break
		}
	}
	if !foundEnrichedAt {
		t.Error("expected enriched_at property")
	}
}
