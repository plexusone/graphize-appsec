package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check environment prerequisites for graphize-appsec",
	Long: `Check that all required and recommended tools are installed
for running graphize-appsec analysis workflows.

Required:
  - graphize: Code knowledge graph generation

Recommended (for full workflow):
  - syft: SBOM generation
  - grype: Vulnerability scanning
  - trivy: Alternative SBOM/vuln scanner`,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

type toolCheck struct {
	name        string
	required    bool
	installHint string
	versionFlag string
}

var tools = []toolCheck{
	{
		name:        "graphize",
		required:    true,
		installHint: "go install github.com/plexusone/graphize/cmd/graphize@latest",
		versionFlag: "--version",
	},
	{
		name:        "syft",
		required:    false,
		installHint: "brew install syft  # or: go install github.com/anchore/syft/cmd/syft@latest",
		versionFlag: "version",
	},
	{
		name:        "grype",
		required:    false,
		installHint: "brew install grype  # or: go install github.com/anchore/grype/cmd/grype@latest",
		versionFlag: "version",
	},
	{
		name:        "trivy",
		required:    false,
		installHint: "brew install trivy  # or: go install github.com/aquasecurity/trivy/cmd/trivy@latest",
		versionFlag: "--version",
	},
}

func runDoctor(cmd *cobra.Command, args []string) error {
	fmt.Println()
	fmt.Println("graphize-appsec environment check")
	fmt.Println("==================================")
	fmt.Println()

	var hasErrors bool

	// Check tools
	fmt.Println("Tools:")
	for _, tool := range tools {
		status, version := checkTool(tool)
		printToolStatus(tool, status, version)
		if tool.required && status == "missing" {
			hasErrors = true
		}
	}

	fmt.Println()

	// Check current directory for .graphize
	fmt.Println("Current directory:")
	checkGraphizeDir()

	fmt.Println()

	if hasErrors {
		fmt.Println("⚠  Some required tools are missing. Install them before running analysis.")
		return nil
	}

	fmt.Println("✓  Environment looks good!")
	return nil
}

func checkTool(tool toolCheck) (status string, version string) {
	path, err := exec.LookPath(tool.name)
	if err != nil {
		return "missing", ""
	}

	// Try to get version
	cmd := exec.Command(path, tool.versionFlag)
	output, err := cmd.Output()
	if err != nil {
		return "installed", "(version unknown)"
	}

	// Extract first line of version output
	version = strings.TrimSpace(strings.Split(string(output), "\n")[0])
	if len(version) > 50 {
		version = version[:50] + "..."
	}

	return "installed", version
}

func printToolStatus(tool toolCheck, status string, version string) {
	var icon, label string

	switch status {
	case "installed":
		icon = "✓"
		label = version
	case "missing":
		if tool.required {
			icon = "✗"
			label = "not found (required)"
		} else {
			icon = "○"
			label = "not found (optional)"
		}
	}

	fmt.Printf("  %s %-15s %s\n", icon, tool.name, label)

	if status == "missing" {
		fmt.Printf("    %s Install: %s\n", " ", tool.installHint)
	}
}

func checkGraphizeDir() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("  ✗ Could not get current directory: %v\n", err)
		return
	}

	graphizeDir := filepath.Join(cwd, ".graphize")
	if _, err := os.Stat(graphizeDir); os.IsNotExist(err) {
		fmt.Printf("  ○ .graphize/      not found\n")
		fmt.Printf("                    Run: graphize init && graphize add . && graphize analyze\n")
	} else {
		fmt.Printf("  ✓ .graphize/      found\n")

		// Check for manifest
		manifest := filepath.Join(graphizeDir, "manifest.json")
		if _, err := os.Stat(manifest); err == nil {
			fmt.Printf("  ✓ manifest.json   found\n")
		}
	}
}
