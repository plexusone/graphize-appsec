package reachable

import (
	"fmt"

	fsgraph "github.com/plexusone/graphfs/pkg/graph"
	"github.com/plexusone/structured-evaluation/evaluation"

	"github.com/plexusone/graphize-appsec/pkg/graph"
	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func init() {
	reachability.Register(NewDirectDependencyTest())
}

// DirectDependencyTest checks if the vulnerable package is a direct dependency.
type DirectDependencyTest struct {
	reachability.BaseTest
}

// NewDirectDependencyTest creates a new test.
func NewDirectDependencyTest() *DirectDependencyTest {
	return &DirectDependencyTest{
		BaseTest: reachability.NewBaseTest(
			"REACH-004",
			"Direct Dependency",
			"Checks if the vulnerable package is a direct (not transitive) dependency",
			reachability.CategoryReachable,
		),
	}
}

// Evaluate runs the test.
func (t *DirectDependencyTest) Evaluate(ctx *reachability.EvalContext) (*reachability.TestResult, error) {
	q := graph.NewQuery(ctx.Graph)

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
		}, nil
	}

	// Find the package node
	var packageNode *fsgraph.Node
	nodes := q.NodesWhere(func(n *fsgraph.Node) bool {
		if n.Type != "package" && n.Type != "module" {
			return false
		}
		return n.Label == packageToFind ||
			n.Attrs["name"] == packageToFind ||
			n.ID == packageToFind ||
			n.ID == "pkg_"+packageToFind
	})

	if len(nodes) > 0 {
		packageNode = nodes[0]
	}

	if packageNode == nil {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false,
			Confidence: 0.8,
			Severity:   evaluation.SeverityInfo,
			Evidence:   fmt.Sprintf("Package %s not found in dependency graph", packageToFind),
		}, nil
	}

	// Get the depth of this package from root
	depth := q.GetDependencyDepth(packageNode.ID)

	if depth == 1 {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       true, // IS direct dependency - more control over updates
			Confidence: 1.0,
			Severity:   evaluation.SeverityMedium,
			Evidence:   fmt.Sprintf("Package %s is a direct dependency", packageToFind),
			Details: map[string]any{
				"package": packageToFind,
				"depth":   depth,
				"type":    "direct",
			},
		}, nil
	} else if depth > 1 {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false, // NOT direct - transitive dependency
			Confidence: 1.0,
			Severity:   evaluation.SeverityLow,
			Evidence:   fmt.Sprintf("Package %s is a transitive dependency at depth %d", packageToFind, depth),
			Details: map[string]any{
				"package": packageToFind,
				"depth":   depth,
				"type":    "transitive",
			},
		}, nil
	}

	return &reachability.TestResult{
		ID:         t.ID(),
		Name:       t.Name(),
		Category:   t.Category(),
		Pass:       false,
		Confidence: 0.7,
		Severity:   evaluation.SeverityInfo,
		Evidence:   fmt.Sprintf("Could not determine dependency depth for %s", packageToFind),
	}, nil
}
