package reachable

import (
	"fmt"
	"strings"

	fsgraph "github.com/plexusone/graphfs/pkg/graph"
	"github.com/plexusone/structured-evaluation/evaluation"

	"github.com/plexusone/graphize-appsec/pkg/graph"
	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func init() {
	reachability.Register(NewApplicationLayerTest())
}

// ApplicationLayerTest checks if the vulnerability is in the application layer vs infrastructure.
type ApplicationLayerTest struct {
	reachability.BaseTest
}

// NewApplicationLayerTest creates a new test.
func NewApplicationLayerTest() *ApplicationLayerTest {
	return &ApplicationLayerTest{
		BaseTest: reachability.NewBaseTest(
			"REACH-006",
			"Application Layer",
			"Checks if the vulnerability is in the application layer (not infrastructure)",
			reachability.CategoryReachable,
		),
	}
}

// Evaluate runs the test.
func (t *ApplicationLayerTest) Evaluate(ctx *reachability.EvalContext) (*reachability.TestResult, error) {
	q := graph.NewQuery(ctx.Graph)

	// Infrastructure packages that are typically less directly exploitable
	infraPatterns := []string{
		"k8s.io/",
		"kubernetes/",
		"docker/",
		"containerd/",
		"etcd",
		"prometheus/",
		"grafana/",
		"terraform",
		"ansible",
		"helm",
		"istio",
		"envoy",
	}

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
			Confidence: 0.3,
			Severity:   evaluation.SeverityInfo,
			Evidence:   "No affected package specified",
		}, nil
	}

	// Check if package matches infrastructure patterns
	isInfra := false
	matchedPattern := ""
	for _, pattern := range infraPatterns {
		if strings.Contains(strings.ToLower(packageToFind), pattern) {
			isInfra = true
			matchedPattern = pattern
			break
		}
	}

	// Also check the package node attributes if available
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
		node := nodes[0]
		if layer := node.Attrs["layer"]; layer != "" {
			if layer == "infrastructure" || layer == "infra" {
				isInfra = true
			}
		}
	}

	if isInfra {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false, // Infrastructure - harder to exploit directly
			Confidence: 0.8,
			Severity:   evaluation.SeverityLow,
			Evidence:   fmt.Sprintf("Package %s appears to be infrastructure-level (matched: %s)", packageToFind, matchedPattern),
			Details: map[string]any{
				"package": packageToFind,
				"layer":   "infrastructure",
				"pattern": matchedPattern,
			},
		}, nil
	}

	return &reachability.TestResult{
		ID:         t.ID(),
		Name:       t.Name(),
		Category:   t.Category(),
		Pass:       true, // Application layer - more directly exploitable
		Confidence: 0.7,
		Severity:   evaluation.SeverityMedium,
		Evidence:   fmt.Sprintf("Package %s is in the application layer", packageToFind),
		Details: map[string]any{
			"package": packageToFind,
			"layer":   "application",
		},
	}, nil
}
