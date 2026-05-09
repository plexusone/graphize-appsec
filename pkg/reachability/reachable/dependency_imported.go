// Package reachable implements reachability tests.
package reachable

import (
	"fmt"

	fsgraph "github.com/plexusone/graphfs/pkg/graph"
	"github.com/plexusone/structured-evaluation/evaluation"

	"github.com/plexusone/graphize-appsec/pkg/graph"
	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func init() {
	reachability.Register(NewDependencyImportedTest())
}

// DependencyImportedTest checks if the vulnerable package is imported.
type DependencyImportedTest struct {
	reachability.BaseTest
}

// NewDependencyImportedTest creates a new test.
func NewDependencyImportedTest() *DependencyImportedTest {
	return &DependencyImportedTest{
		BaseTest: reachability.NewBaseTest(
			"REACH-001",
			"Dependency Imported",
			"Checks if the vulnerable package is imported in the codebase",
			reachability.CategoryReachable,
		),
	}
}

// Evaluate runs the test.
func (t *DependencyImportedTest) Evaluate(ctx *reachability.EvalContext) (*reachability.TestResult, error) {
	q := graph.NewQuery(ctx.Graph)

	// Check if we have a specific package to look for
	packageToFind := ctx.AffectedPackage
	if packageToFind == "" && ctx.VulnInfo != nil && len(ctx.VulnInfo.AffectedPackages) > 0 {
		packageToFind = ctx.VulnInfo.AffectedPackages[0]
	}

	if packageToFind == "" {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false,
			Confidence: 0.5,
			Severity:   evaluation.SeverityInfo,
			Evidence:   "No affected package specified",
			Details: map[string]any{
				"reason": "missing_package_info",
			},
		}, nil
	}

	// Check if the package exists in the graph
	if q.HasPackage(packageToFind) {
		// Find the actual node for more details
		nodes := q.NodesWhere(func(n *fsgraph.Node) bool {
			if n.Type != "package" && n.Type != "module" {
				return false
			}
			return n.Label == packageToFind ||
				n.Attrs["name"] == packageToFind ||
				n.ID == packageToFind ||
				n.ID == "pkg_"+packageToFind
		})

		var details map[string]any
		if len(nodes) > 0 {
			details = map[string]any{
				"node_id":   nodes[0].ID,
				"node_type": nodes[0].Type,
				"version":   nodes[0].Attrs["version"],
			}
		}

		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       true, // Package IS imported - risk exists
			Confidence: 1.0,
			Severity:   evaluation.SeverityMedium,
			Evidence:   fmt.Sprintf("Package %s is imported in the codebase", packageToFind),
			Details:    details,
		}, nil
	}

	return &reachability.TestResult{
		ID:         t.ID(),
		Name:       t.Name(),
		Category:   t.Category(),
		Pass:       false, // Package NOT imported - no risk
		Confidence: 0.95,
		Severity:   evaluation.SeverityInfo,
		Evidence:   fmt.Sprintf("Package %s is not found in the dependency graph", packageToFind),
		Details: map[string]any{
			"searched_package": packageToFind,
		},
	}, nil
}
