package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

// testCmd represents the test command.
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "List or run specific reachability tests",
	Long: `List available reachability tests or run specific tests.

Examples:
  # List all tests
  graphize-appsec test list

  # List tests by category
  graphize-appsec test list --category reachable`,
}

// testListCmd lists available tests.
var testListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available reachability tests",
	RunE:  runTestList,
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.AddCommand(testListCmd)
}

func runTestList(cmd *cobra.Command, args []string) error {
	tests := reachability.All()

	fmt.Printf("Available Tests: %d\n\n", len(tests))

	currentCategory := reachability.Category("")
	for _, t := range tests {
		if t.Category() != currentCategory {
			currentCategory = t.Category()
			fmt.Printf("\n%s:\n", currentCategory)
		}
		fmt.Printf("  %-12s  %s\n", t.ID(), t.Name())
		if verbose {
			fmt.Printf("              %s\n", t.Description())
		}
	}

	counts := reachability.CountByCategory()
	fmt.Printf("\nSummary:\n")
	for _, cat := range reachability.AllCategories() {
		fmt.Printf("  %-15s: %d tests\n", cat, counts[cat])
	}

	return nil
}
