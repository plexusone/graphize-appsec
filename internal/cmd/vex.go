package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/plexusone/graphfs/pkg/store"
	"github.com/spf13/cobra"

	"github.com/plexusone/graphize-appsec/pkg/reachability"
	"github.com/plexusone/graphize-appsec/pkg/vex"
)

var (
	vexSBOMPath    string
	vexOutputPath  string
	vexVulnsPath   string
	vexToolName    string
	vexToolVersion string
	vexToolVendor  string
)

// vexCmd represents the vex command group.
var vexCmd = &cobra.Command{
	Use:   "vex",
	Short: "Generate VEX (Vulnerability Exploitability eXchange) documents",
	Long: `Generate CycloneDX VEX documents from reachability analysis.

VEX documents communicate whether vulnerabilities are actually exploitable
in a specific deployment context. graphize-appsec uses code knowledge graphs
to determine reachability and produces standards-compliant VEX output.

Examples:
  # Enrich an SBOM with VEX analysis
  graphize-appsec vex enrich --sbom sbom.json --vulns vulns.json

  # Generate a standalone VEX document
  graphize-appsec vex generate --vulns vulns.json -o vex.json`,
}

// vexEnrichCmd enriches an SBOM with VEX analysis.
var vexEnrichCmd = &cobra.Command{
	Use:   "enrich",
	Short: "Enrich an SBOM with VEX analysis from reachability tests",
	Long: `Enrich a CycloneDX SBOM with VEX (Vulnerability Exploitability eXchange) data.

This command:
1. Reads an existing CycloneDX SBOM
2. Reads vulnerability scan results (from grype, trivy, etc.)
3. Runs reachability tests against the code knowledge graph
4. Adds VEX analysis to the SBOM showing which vulns are actually exploitable
5. Outputs the enriched SBOM

Examples:
  # Basic enrichment
  graphize-appsec vex enrich --sbom sbom.json --vulns vulns.json

  # Output to specific file
  graphize-appsec vex enrich --sbom sbom.json --vulns vulns.json -o enriched-sbom.json

  # With custom tool metadata
  graphize-appsec vex enrich --sbom sbom.json --vulns vulns.json \
    --tool-name "my-scanner" --tool-version "1.0.0"`,
	RunE: runVexEnrich,
}

// vexGenerateCmd generates a standalone VEX document.
var vexGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a standalone VEX document from reachability analysis",
	Long: `Generate a standalone CycloneDX VEX document.

This creates a VEX-only BOM (no components, just vulnerabilities with analysis)
that can be used alongside an existing SBOM for vulnerability communication.

Examples:
  # Generate VEX from vulnerability list
  graphize-appsec vex generate --vulns vulns.json -o vex.json

  # Generate VEX for specific CVEs
  graphize-appsec vex generate CVE-2023-1234 CVE-2023-5678 -o vex.json`,
	RunE: runVexGenerate,
}

func init() {
	rootCmd.AddCommand(vexCmd)
	vexCmd.AddCommand(vexEnrichCmd)
	vexCmd.AddCommand(vexGenerateCmd)

	// Common flags
	vexCmd.PersistentFlags().StringVar(&vexToolName, "tool-name", "graphize-appsec", "Tool name for VEX metadata")
	vexCmd.PersistentFlags().StringVar(&vexToolVersion, "tool-version", "0.1.0", "Tool version for VEX metadata")
	vexCmd.PersistentFlags().StringVar(&vexToolVendor, "tool-vendor", "PlexusOne", "Tool vendor for VEX metadata")

	// Enrich command flags
	vexEnrichCmd.Flags().StringVarP(&vexSBOMPath, "sbom", "s", "", "Path to input CycloneDX SBOM (required)")
	vexEnrichCmd.Flags().StringVarP(&vexVulnsPath, "vulns", "V", "", "Path to vulnerability scan results (JSON)")
	vexEnrichCmd.Flags().StringVarP(&vexOutputPath, "output", "o", "", "Output path (default: stdout or <sbom>-vex.json)")
	_ = vexEnrichCmd.MarkFlagRequired("sbom")

	// Generate command flags
	vexGenerateCmd.Flags().StringVarP(&vexVulnsPath, "vulns", "V", "", "Path to vulnerability scan results (JSON)")
	vexGenerateCmd.Flags().StringVarP(&vexOutputPath, "output", "o", "", "Output path (default: stdout)")
}

// VulnScanResult represents a vulnerability from a scanner (grype/trivy format).
type VulnScanResult struct {
	ID              string   `json:"id"`
	Severity        string   `json:"severity"`
	Package         string   `json:"package"`
	Version         string   `json:"version"`
	FixedVersion    string   `json:"fixed_version,omitempty"`
	CVSS            float64  `json:"cvss,omitempty"`
	EPSSScore       float64  `json:"epss_score,omitempty"`
	Description     string   `json:"description,omitempty"`
	References      []string `json:"references,omitempty"`
	AffectedPackage string   `json:"affected_package,omitempty"`
}

// VulnScanOutput represents the output from vulnerability scanners.
type VulnScanOutput struct {
	Matches []struct {
		Vulnerability struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			Fix         struct {
				Versions []string `json:"versions"`
			} `json:"fix"`
			URLs []string `json:"urls"`
			CVSS []struct {
				Score float64 `json:"score"`
			} `json:"cvss"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"artifact"`
	} `json:"matches"`
	// Simple format fallback
	Vulnerabilities []VulnScanResult `json:"vulnerabilities,omitempty"`
}

func runVexEnrich(cmd *cobra.Command, args []string) error {
	// Load the SBOM
	if verbose {
		fmt.Printf("Reading SBOM from %s\n", vexSBOMPath)
	}
	bom, err := vex.ReadSBOM(vexSBOMPath)
	if err != nil {
		return fmt.Errorf("failed to read SBOM: %w", err)
	}

	// Load vulnerability scan results
	vulns, err := loadVulnerabilities(vexVulnsPath, args)
	if err != nil {
		return fmt.Errorf("failed to load vulnerabilities: %w", err)
	}

	if len(vulns) == 0 {
		fmt.Println("No vulnerabilities to analyze")
		return nil
	}

	if verbose {
		fmt.Printf("Analyzing %d vulnerabilities\n", len(vulns))
	}

	// Load the graph
	fs, err := store.NewFSStore(graphPath)
	if err != nil {
		return fmt.Errorf("failed to create store: %w", err)
	}
	graph, err := fs.LoadGraph()
	if err != nil {
		return fmt.Errorf("failed to load graph from %s: %w", graphPath, err)
	}

	if verbose {
		fmt.Printf("Loaded graph with %d nodes and %d edges\n", graph.NodeCount(), graph.EdgeCount())
	}

	// Run reachability analysis for each vulnerability
	vulnResults := make(map[string]*reachability.RunResult)
	runner := reachability.NewRunner()

	for _, v := range vulns {
		if verbose {
			fmt.Printf("Analyzing %s (%s)...\n", v.ID, v.Package)
		}

		ctx := reachability.NewEvalContext(context.Background(), graph, v.ID)
		ctx.AffectedPackage = v.Package
		ctx.VulnInfo = &reachability.VulnerabilityInfo{
			ID:               v.ID,
			Severity:         v.Severity,
			CVSSScore:        v.CVSS,
			EPSSScore:        v.EPSSScore,
			Summary:          v.Description,
			AffectedPackages: []string{v.Package},
		}
		if v.FixedVersion != "" {
			ctx.VulnInfo.FixedVersions = map[string]string{v.Package: v.FixedVersion}
		}

		result, err := runner.Run(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to analyze %s: %v\n", v.ID, err)
			continue
		}

		// Add package info to results for affected ref lookup
		for _, tr := range result.Results {
			if tr.Details == nil {
				tr.Details = make(map[string]any)
			}
			tr.Details["package"] = v.Package
		}

		vulnResults[v.ID] = result

		if verbose {
			fmt.Printf("  Decision: %s (score: %.1f)\n", result.Decision(), result.WeightedScore())
		}
	}

	// Enrich the SBOM
	enricher := vex.NewSBOMEnricher()
	enricher.SetToolInfo(vexToolName, vexToolVersion, vexToolVendor)

	enrichResult, err := enricher.Enrich(bom, vulnResults)
	if err != nil {
		return fmt.Errorf("failed to enrich SBOM: %w", err)
	}

	// Output results
	outputPath := vexOutputPath
	if outputPath == "" {
		// Default to <sbom>-vex.json
		outputPath = strings.TrimSuffix(vexSBOMPath, ".json") + "-vex.json"
	}

	if err := vex.WriteSBOM(bom, outputPath); err != nil {
		return fmt.Errorf("failed to write enriched SBOM: %w", err)
	}

	// Print summary
	fmt.Println()
	fmt.Println("VEX Enrichment Summary")
	fmt.Println("======================")
	fmt.Printf("Original vulnerabilities:  %d\n", enrichResult.OriginalVulnCount)
	fmt.Printf("Added vulnerabilities:     %d\n", enrichResult.AddedVulnCount)
	fmt.Printf("Updated vulnerabilities:   %d\n", enrichResult.UpdatedVulnCount)
	fmt.Printf("Total vulnerabilities:     %d\n", enrichResult.EnrichedVulnCount)
	fmt.Println()
	fmt.Println("VEX Analysis Results:")
	fmt.Printf("  Not Affected:  %d\n", enrichResult.NotAffectedCount)
	fmt.Printf("  Exploitable:   %d\n", enrichResult.ExploitableCount)
	fmt.Printf("  In Triage:     %d\n", enrichResult.InTriageCount)
	fmt.Println()
	fmt.Printf("Output written to: %s\n", outputPath)

	return nil
}

func runVexGenerate(cmd *cobra.Command, args []string) error {
	// Load vulnerabilities from file or args
	vulns, err := loadVulnerabilities(vexVulnsPath, args)
	if err != nil {
		return fmt.Errorf("failed to load vulnerabilities: %w", err)
	}

	if len(vulns) == 0 {
		return fmt.Errorf("no vulnerabilities specified; use --vulns or provide CVE IDs as arguments")
	}

	if verbose {
		fmt.Printf("Generating VEX for %d vulnerabilities\n", len(vulns))
	}

	// Load the graph
	fs, err := store.NewFSStore(graphPath)
	if err != nil {
		return fmt.Errorf("failed to create store: %w", err)
	}
	graph, err := fs.LoadGraph()
	if err != nil {
		return fmt.Errorf("failed to load graph from %s: %w", graphPath, err)
	}

	// Run reachability analysis for each vulnerability
	vulnResults := make(map[string]*reachability.RunResult)
	runner := reachability.NewRunner()

	for _, v := range vulns {
		if verbose {
			fmt.Printf("Analyzing %s...\n", v.ID)
		}

		ctx := reachability.NewEvalContext(context.Background(), graph, v.ID)
		ctx.AffectedPackage = v.Package
		ctx.VulnInfo = &reachability.VulnerabilityInfo{
			ID:               v.ID,
			Severity:         v.Severity,
			CVSSScore:        v.CVSS,
			EPSSScore:        v.EPSSScore,
			Summary:          v.Description,
			AffectedPackages: []string{v.Package},
		}

		result, err := runner.Run(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to analyze %s: %v\n", v.ID, err)
			continue
		}

		vulnResults[v.ID] = result

		if verbose {
			fmt.Printf("  Decision: %s (score: %.1f)\n", result.Decision(), result.WeightedScore())
		}
	}

	// Generate VEX document
	enricher := vex.NewSBOMEnricher()
	enricher.SetToolInfo(vexToolName, vexToolVersion, vexToolVendor)

	vexDoc := enricher.CreateVEXDocument(vulnResults)

	// Output
	if vexOutputPath == "" || vexOutputPath == "-" {
		// Write to stdout
		return vex.EncodeSBOM(vexDoc, os.Stdout, vex.DetectFormatFromPath("output.json"))
	}

	if err := vex.WriteSBOM(vexDoc, vexOutputPath); err != nil {
		return fmt.Errorf("failed to write VEX document: %w", err)
	}

	fmt.Printf("VEX document written to: %s\n", vexOutputPath)
	fmt.Printf("Vulnerabilities analyzed: %d\n", len(vulnResults))

	return nil
}

// loadVulnerabilities loads vulnerabilities from a file or CLI args.
func loadVulnerabilities(filePath string, cveArgs []string) ([]VulnScanResult, error) {
	var vulns []VulnScanResult

	// Load from file if provided
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading vulns file: %w", err)
		}

		// Try grype format first
		var grypeOutput VulnScanOutput
		if err := json.Unmarshal(data, &grypeOutput); err == nil {
			// Convert grype matches to our format
			for _, m := range grypeOutput.Matches {
				v := VulnScanResult{
					ID:          m.Vulnerability.ID,
					Severity:    m.Vulnerability.Severity,
					Package:     m.Artifact.Name,
					Version:     m.Artifact.Version,
					Description: m.Vulnerability.Description,
					References:  m.Vulnerability.URLs,
				}
				if len(m.Vulnerability.Fix.Versions) > 0 {
					v.FixedVersion = m.Vulnerability.Fix.Versions[0]
				}
				if len(m.Vulnerability.CVSS) > 0 {
					v.CVSS = m.Vulnerability.CVSS[0].Score
				}
				vulns = append(vulns, v)
			}

			// Also check simple format
			vulns = append(vulns, grypeOutput.Vulnerabilities...)
		} else {
			// Try simple array format
			var simpleVulns []VulnScanResult
			if err := json.Unmarshal(data, &simpleVulns); err != nil {
				return nil, fmt.Errorf("parsing vulns file (tried grype and simple formats): %w", err)
			}
			vulns = simpleVulns
		}
	}

	// Add CVEs from CLI args
	for _, cve := range cveArgs {
		if strings.HasPrefix(cve, "CVE-") || strings.HasPrefix(cve, "GHSA-") {
			vulns = append(vulns, VulnScanResult{
				ID: cve,
			})
		}
	}

	return vulns, nil
}
