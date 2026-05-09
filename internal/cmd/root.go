// Package cmd implements the CLI commands for graphize-appsec.
package cmd

import (
	"github.com/spf13/cobra"

	// Import test packages to register tests
	_ "github.com/plexusone/graphize-appsec/pkg/reachability/damage"
	_ "github.com/plexusone/graphize-appsec/pkg/reachability/exploitable"
	_ "github.com/plexusone/graphize-appsec/pkg/reachability/reachable"
)

var (
	graphPath string
	format    string
	verbose   bool
)

// rootCmd represents the base command.
var rootCmd = &cobra.Command{
	Use:   "graphize-appsec",
	Short: "Security reachability analysis using code knowledge graphs",
	Long: `graphize-appsec performs reachability analysis
using graphize's code knowledge graph. It answers the question:
"Is this vulnerability actually exploitable in my deployment?"

The tool runs a series of tests across three categories:
  - Reachable: Is the vulnerable code actually reachable?
  - Exploitable: Is the vulnerability exploitable in practice?
  - Damage: What is the potential damage if exploited?

Each test returns a Y/N result with evidence and confidence level.`,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&graphPath, "graph", "g", ".graphize", "Path to graphize graph directory")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "detailed", "Output format: json, detailed, summary")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
}
