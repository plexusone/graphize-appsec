// graphize-appsec is a security analysis tool that performs reachability analysis
// using graphize's code knowledge graph.
package main

import (
	"os"

	"github.com/plexusone/graphize-appsec/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
