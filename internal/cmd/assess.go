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
)

var (
	assessAffectedPackage  string
	assessAffectedFunction string
	assessCategories       []string
)

// assessCmd represents the assess command.
var assessCmd = &cobra.Command{
	Use:   "assess <vulnerability-id>",
	Short: "Assess a vulnerability for reachability and exploitability",
	Long: `Assess a vulnerability against the code knowledge graph.

Runs all reachability tests and generates a structured report showing:
  - Whether each test passed or failed
  - Confidence level of each result
  - Evidence and attack paths found
  - Overall decision (PASS/CONDITIONAL/FAIL)

Examples:
  # Assess a CVE
  graphize-appsec assess CVE-2021-44228

  # Assess with specific package
  graphize-appsec assess CVE-2021-44228 --package log4j-core

  # Output as JSON
  graphize-appsec assess CVE-2021-44228 --format json

  # Only run reachable tests
  graphize-appsec assess CVE-2021-44228 --category reachable`,
	Args: cobra.ExactArgs(1),
	RunE: runAssess,
}

func init() {
	rootCmd.AddCommand(assessCmd)

	assessCmd.Flags().StringVarP(&assessAffectedPackage, "package", "p", "", "Affected package name or purl")
	assessCmd.Flags().StringVar(&assessAffectedFunction, "function", "", "Affected function ID")
	assessCmd.Flags().StringSliceVarP(&assessCategories, "category", "c", nil, "Categories to test: reachable, exploitable, damage")
}

func runAssess(cmd *cobra.Command, args []string) error {
	vulnID := args[0]

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

	// Create evaluation context
	ctx := reachability.NewEvalContext(context.Background(), graph, vulnID)
	ctx.AffectedPackage = assessAffectedPackage
	ctx.AffectedFunction = assessAffectedFunction

	// TODO: Fetch vulnerability info from OSV/NVD
	// For now, create a placeholder
	if ctx.VulnInfo == nil {
		ctx.VulnInfo = &reachability.VulnerabilityInfo{
			ID: vulnID,
		}
	}

	// Create runner
	var runner *reachability.Runner
	if len(assessCategories) > 0 {
		var categories []reachability.Category
		for _, c := range assessCategories {
			categories = append(categories, reachability.Category(strings.ToLower(c)))
		}
		runner = reachability.NewRunnerForCategories(categories...)
	} else {
		runner = reachability.NewRunner()
	}

	// Run tests
	result, err := runner.Run(ctx)
	if err != nil {
		return fmt.Errorf("test execution failed: %w", err)
	}

	// Output results
	switch format {
	case "json":
		return outputJSON(result)
	case "summary":
		return outputSummary(vulnID, result)
	default:
		return outputDetailed(vulnID, result)
	}
}

func outputJSON(result *reachability.RunResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputSummary(vulnID string, result *reachability.RunResult) error {
	decision := result.Decision()
	fmt.Printf("%s: %s (score: %.1f/10)\n", vulnID, decision, result.WeightedScore())
	fmt.Printf("Tests: %d passed, %d failed, %d errors\n",
		result.PassCount, result.FailCount, result.ErrorCount)
	return nil
}

func outputDetailed(vulnID string, result *reachability.RunResult) error {
	fmt.Println("=" + strings.Repeat("=", 70))
	fmt.Printf(" Security Reachability Assessment: %s\n", vulnID)
	fmt.Println("=" + strings.Repeat("=", 70))
	fmt.Println()

	// Category scores
	fmt.Println("Category Scores:")
	fmt.Println("-" + strings.Repeat("-", 70))
	for _, cat := range reachability.AllCategories() {
		score := result.CategoryScores[cat]
		fmt.Printf("  %-15s: %.1f/10 (weight: %.0f%%)  %s\n",
			cat, score.Score, score.Weight*100, score.Justification)
	}
	fmt.Println()

	// Test results by category
	for _, cat := range reachability.AllCategories() {
		results := result.ByCategory[cat]
		if len(results) == 0 {
			continue
		}

		fmt.Printf("%s Tests:\n", strings.ToUpper(string(cat)))
		fmt.Println("-" + strings.Repeat("-", 70))

		for _, r := range results {
			var status string
			switch {
			case r.Error != "":
				status = "[!]"
			case r.Pass:
				status = "[Y]"
			default:
				status = "[N]"
			}

			fmt.Printf("  %s %-8s %-25s  (conf: %.0f%%)\n",
				status, r.ID, r.Name, r.Confidence*100)
			fmt.Printf("              %s\n", r.Evidence)
		}
		fmt.Println()
	}

	// Overall decision
	decision := result.Decision()
	score := result.WeightedScore()

	fmt.Println("=" + strings.Repeat("=", 70))
	fmt.Printf(" Decision: %s  |  Score: %.1f/10  |  Duration: %s\n",
		decision, score, result.TotalDuration.Round(1e6))
	fmt.Println("=" + strings.Repeat("=", 70))

	return nil
}
