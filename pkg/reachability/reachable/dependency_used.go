package reachable

import (
	"fmt"

	fsgraph "github.com/plexusone/graphfs/pkg/graph"
	"github.com/plexusone/structured-evaluation/evaluation"

	"github.com/plexusone/graphize-appsec/pkg/graph"
	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func init() {
	reachability.Register(NewDependencyUsedTest())
}

// DependencyUsedTest checks if vulnerable code is actually called.
type DependencyUsedTest struct {
	reachability.BaseTest
}

// NewDependencyUsedTest creates a new test.
func NewDependencyUsedTest() *DependencyUsedTest {
	return &DependencyUsedTest{
		BaseTest: reachability.NewBaseTest(
			"REACH-002",
			"Dependency Used",
			"Checks if the vulnerable code is actually called from entry points",
			reachability.CategoryReachable,
		),
	}
}

// Evaluate runs the test.
func (t *DependencyUsedTest) Evaluate(ctx *reachability.EvalContext) (*reachability.TestResult, error) {
	q := graph.NewQuery(ctx.Graph)

	// Get target nodes to check reachability to
	targetIDs := ctx.AffectedNodeIDs
	if len(targetIDs) == 0 && ctx.AffectedFunction != "" {
		targetIDs = []string{ctx.AffectedFunction}
	}

	if len(targetIDs) == 0 {
		// Try to find nodes related to the affected package
		if ctx.AffectedPackage != "" {
			nodes := q.NodesWhere(func(n *fsgraph.Node) bool {
				return n.Attrs["package"] == ctx.AffectedPackage
			})
			for _, n := range nodes {
				targetIDs = append(targetIDs, n.ID)
			}
		}
	}

	if len(targetIDs) == 0 {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false,
			Confidence: 0.3,
			Severity:   evaluation.SeverityInfo,
			Evidence:   "No target functions identified for reachability analysis",
			Details: map[string]any{
				"reason": "no_targets",
			},
		}, nil
	}

	// Find entry points
	entryPoints := q.FindEntryPoints()
	if len(entryPoints) == 0 {
		// Fall back to all function nodes
		entryPoints = q.FindFunctionNodes()
	}

	// Check reachability from each entry point
	for _, ep := range entryPoints {
		paths := q.FindAllPaths(ep.ID, targetIDs, []string{"calls"}, 50)
		if len(paths) > 0 {
			shortestPath := paths[0]
			for _, p := range paths[1:] {
				if p.Depth < shortestPath.Depth {
					shortestPath = p
				}
			}

			return &reachability.TestResult{
				ID:         t.ID(),
				Name:       t.Name(),
				Category:   t.Category(),
				Pass:       true, // Dependency IS used - risk exists
				Confidence: 1.0,
				Severity:   evaluation.SeverityHigh,
				Evidence:   fmt.Sprintf("Vulnerable code reachable from %s in %d calls", ep.Label, shortestPath.Depth),
				Details: map[string]any{
					"entry_point": ep.ID,
					"target":      shortestPath.ToID,
					"depth":       shortestPath.Depth,
					"path":        shortestPath.String(),
					"paths_found": len(paths),
				},
			}, nil
		}
	}

	return &reachability.TestResult{
		ID:         t.ID(),
		Name:       t.Name(),
		Category:   t.Category(),
		Pass:       false, // Dependency NOT used - no risk
		Confidence: 0.85,  // Lower confidence due to potential dynamic calls
		Severity:   evaluation.SeverityLow,
		Evidence:   fmt.Sprintf("No call path found to vulnerable code from %d entry points", len(entryPoints)),
		Details: map[string]any{
			"entry_points_checked": len(entryPoints),
			"targets_checked":      len(targetIDs),
		},
	}, nil
}
