package vex

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

// SBOMEnricher enriches CycloneDX SBOMs with VEX analysis from reachability tests.
type SBOMEnricher struct {
	converter *Converter
}

// NewSBOMEnricher creates a new SBOM enricher.
func NewSBOMEnricher() *SBOMEnricher {
	return &SBOMEnricher{
		converter: NewConverter(),
	}
}

// SetToolInfo sets the tool metadata for generated VEX.
func (e *SBOMEnricher) SetToolInfo(name, version, vendor string) {
	e.converter.ToolName = name
	e.converter.ToolVersion = version
	e.converter.ToolVendor = vendor
}

// ReadSBOM reads a CycloneDX SBOM from a file.
func ReadSBOM(path string) (*cdx.BOM, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}
	defer func() { _ = file.Close() }()

	format := detectFormat(path)
	return DecodeSBOM(file, format)
}

// DecodeSBOM decodes a CycloneDX SBOM from a reader.
func DecodeSBOM(r io.Reader, format cdx.BOMFileFormat) (*cdx.BOM, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(r, format)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decoding SBOM: %w", err)
	}
	return bom, nil
}

// WriteSBOM writes a CycloneDX SBOM to a file.
func WriteSBOM(bom *cdx.BOM, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}

	format := detectFormat(path)
	if err := EncodeSBOM(bom, file, format); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// EncodeSBOM encodes a CycloneDX SBOM to a writer.
func EncodeSBOM(bom *cdx.BOM, w io.Writer, format cdx.BOMFileFormat) error {
	encoder := cdx.NewBOMEncoder(w, format)
	encoder.SetPretty(true)
	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("encoding SBOM: %w", err)
	}
	return nil
}

// DetectFormatFromPath detects the SBOM format from file extension.
func DetectFormatFromPath(path string) cdx.BOMFileFormat {
	return detectFormat(path)
}

// detectFormat detects the SBOM format from file extension.
func detectFormat(path string) cdx.BOMFileFormat {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".xml":
		return cdx.BOMFileFormatXML
	default:
		return cdx.BOMFileFormatJSON
	}
}

// EnrichmentResult contains the result of enriching an SBOM.
type EnrichmentResult struct {
	// OriginalVulnCount is the number of vulnerabilities in the original SBOM.
	OriginalVulnCount int

	// EnrichedVulnCount is the number of vulnerabilities after enrichment.
	EnrichedVulnCount int

	// AddedVulnCount is the number of new vulnerabilities added.
	AddedVulnCount int

	// UpdatedVulnCount is the number of vulnerabilities updated with VEX.
	UpdatedVulnCount int

	// NotAffectedCount is vulnerabilities marked as not_affected.
	NotAffectedCount int

	// ExploitableCount is vulnerabilities marked as exploitable.
	ExploitableCount int

	// InTriageCount is vulnerabilities marked as in_triage.
	InTriageCount int
}

// Enrich adds VEX analysis to an SBOM based on reachability test results.
func (e *SBOMEnricher) Enrich(bom *cdx.BOM, vulnResults map[string]*reachability.RunResult) (*EnrichmentResult, error) {
	result := &EnrichmentResult{}

	// Count original vulnerabilities
	if bom.Vulnerabilities != nil {
		result.OriginalVulnCount = len(*bom.Vulnerabilities)
	}

	// Build a map of existing vulnerabilities
	existingVulns := make(map[string]*cdx.Vulnerability)
	if bom.Vulnerabilities != nil {
		for i := range *bom.Vulnerabilities {
			v := &(*bom.Vulnerabilities)[i]
			existingVulns[v.ID] = v
		}
	}

	// Process each vulnerability result
	for vulnID, runResult := range vulnResults {
		// Find the affected component reference
		affectedRef := e.findAffectedRef(bom, runResult)

		if existing, ok := existingVulns[vulnID]; ok {
			// Update existing vulnerability with VEX analysis
			e.updateVulnerability(existing, runResult)
			result.UpdatedVulnCount++
		} else {
			// Add new vulnerability with VEX analysis
			newVuln := e.converter.ConvertResult(vulnID, runResult, affectedRef)
			if bom.Vulnerabilities == nil {
				bom.Vulnerabilities = &[]cdx.Vulnerability{}
			}
			*bom.Vulnerabilities = append(*bom.Vulnerabilities, *newVuln)
			result.AddedVulnCount++
		}
	}

	// Count final states
	if bom.Vulnerabilities != nil {
		result.EnrichedVulnCount = len(*bom.Vulnerabilities)
		for _, v := range *bom.Vulnerabilities {
			if v.Analysis != nil {
				switch v.Analysis.State {
				case cdx.IASNotAffected:
					result.NotAffectedCount++
				case cdx.IASExploitable:
					result.ExploitableCount++
				case cdx.IASInTriage:
					result.InTriageCount++
				}
			}
		}
	}

	// Update SBOM metadata
	e.updateMetadata(bom)

	return result, nil
}

// updateVulnerability updates an existing vulnerability with VEX analysis.
func (e *SBOMEnricher) updateVulnerability(vuln *cdx.Vulnerability, result *reachability.RunResult) {
	state, justification := e.converter.determineStateAndJustification(result)
	detail := e.converter.generateDetail(result)
	responses := e.converter.determineResponses(result, state)

	now := time.Now().UTC().Format(time.RFC3339)

	if vuln.Analysis == nil {
		vuln.Analysis = &cdx.VulnerabilityAnalysis{}
	}

	vuln.Analysis.State = state
	vuln.Analysis.Justification = justification
	vuln.Analysis.Detail = detail
	vuln.Analysis.LastUpdated = now

	if vuln.Analysis.FirstIssued == "" {
		vuln.Analysis.FirstIssued = now
	}

	if len(responses) > 0 {
		vuln.Analysis.Response = &responses
	}

	// Add tool info
	vuln.Tools = e.converter.createToolsChoice()

	// Add properties
	props := e.converter.createProperties(result)
	if len(props) > 0 {
		if vuln.Properties == nil {
			vuln.Properties = &props
		} else {
			*vuln.Properties = append(*vuln.Properties, props...)
		}
	}
}

// findAffectedRef finds the component reference for the affected package.
func (e *SBOMEnricher) findAffectedRef(bom *cdx.BOM, result *reachability.RunResult) string {
	if bom.Components == nil {
		return ""
	}

	// Get the affected package from test results
	var affectedPkg string
	for _, testResult := range result.Results {
		if pkg, ok := testResult.Details["package"].(string); ok && pkg != "" {
			affectedPkg = pkg
			break
		}
	}

	if affectedPkg == "" {
		return ""
	}

	// Find matching component
	for _, comp := range *bom.Components {
		// Match by purl
		if comp.PackageURL != "" && strings.Contains(comp.PackageURL, affectedPkg) {
			if comp.BOMRef != "" {
				return comp.BOMRef
			}
			return comp.PackageURL
		}

		// Match by name
		if comp.Name == affectedPkg {
			if comp.BOMRef != "" {
				return comp.BOMRef
			}
			return comp.Name
		}
	}

	return ""
}

// updateMetadata updates SBOM metadata with enrichment info.
func (e *SBOMEnricher) updateMetadata(bom *cdx.BOM) {
	now := time.Now().UTC().Format(time.RFC3339)

	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}

	// Update timestamp
	bom.Metadata.Timestamp = now

	// Add tool to metadata
	toolComp := cdx.Component{
		Type:    cdx.ComponentTypeApplication,
		Name:    e.converter.ToolName,
		Version: e.converter.ToolVersion,
		Supplier: &cdx.OrganizationalEntity{
			Name: e.converter.ToolVendor,
		},
	}

	if bom.Metadata.Tools == nil {
		bom.Metadata.Tools = &cdx.ToolsChoice{}
	}

	if bom.Metadata.Tools.Components == nil {
		bom.Metadata.Tools.Components = &[]cdx.Component{}
	}

	*bom.Metadata.Tools.Components = append(*bom.Metadata.Tools.Components, toolComp)

	// Add enrichment property
	enrichmentProp := cdx.Property{
		Name:  "graphize-appsec:enriched_at",
		Value: now,
	}

	if bom.Metadata.Properties == nil {
		bom.Metadata.Properties = &[]cdx.Property{}
	}
	*bom.Metadata.Properties = append(*bom.Metadata.Properties, enrichmentProp)
}

// CreateVEXDocument creates a standalone VEX document (BOM with only vulnerabilities).
func (e *SBOMEnricher) CreateVEXDocument(vulnResults map[string]*reachability.RunResult) *cdx.BOM {
	bom := cdx.NewBOM()

	now := time.Now().UTC().Format(time.RFC3339)
	bom.Metadata = &cdx.Metadata{
		Timestamp: now,
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    e.converter.ToolName,
					Version: e.converter.ToolVersion,
					Supplier: &cdx.OrganizationalEntity{
						Name: e.converter.ToolVendor,
					},
				},
			},
		},
		Properties: &[]cdx.Property{
			{
				Name:  "graphize-appsec:document_type",
				Value: "vex",
			},
		},
	}

	// Add vulnerabilities
	vulns := make([]cdx.Vulnerability, 0, len(vulnResults))
	for vulnID, result := range vulnResults {
		vuln := e.converter.ConvertResult(vulnID, result, "")
		vulns = append(vulns, *vuln)
	}

	if len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}

	return bom
}
