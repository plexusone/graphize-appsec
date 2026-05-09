package damage

import (
	"fmt"
	"strings"

	fsgraph "github.com/plexusone/graphfs/pkg/graph"
	"github.com/plexusone/structured-evaluation/evaluation"

	"github.com/plexusone/graphize-appsec/pkg/graph"
	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func init() {
	reachability.Register(NewCriticalBusinessTest())
}

// CriticalBusinessTest checks if the vulnerability affects critical business systems.
type CriticalBusinessTest struct {
	reachability.BaseTest
}

// NewCriticalBusinessTest creates a new test.
func NewCriticalBusinessTest() *CriticalBusinessTest {
	return &CriticalBusinessTest{
		BaseTest: reachability.NewBaseTest(
			"DAMAGE-001",
			"Critical Business Priority",
			"Checks if the vulnerability affects systems marked as critical business priority",
			reachability.CategoryDamage,
		),
	}
}

// Evaluate runs the test.
func (t *CriticalBusinessTest) Evaluate(ctx *reachability.EvalContext) (*reachability.TestResult, error) {
	q := graph.NewQuery(ctx.Graph)

	// Critical business indicators
	criticalPatterns := []string{
		"payment",
		"billing",
		"checkout",
		"order",
		"transaction",
		"pii",
		"personal_data",
		"gdpr",
		"hipaa",
		"pci",
		"financial",
		"banking",
		"trading",
		"compliance",
		"audit",
		"admin",
		"dashboard",
	}

	// Get target nodes
	targetIDs := ctx.AffectedNodeIDs
	if len(targetIDs) == 0 && ctx.AffectedFunction != "" {
		targetIDs = []string{ctx.AffectedFunction}
	}

	// Check deployment info for business criticality
	if ctx.DeploymentInfo != nil {
		criticality := ctx.DeploymentInfo.BusinessCriticality
		if criticality == "critical" || criticality == "high" {
			return &reachability.TestResult{
				ID:         t.ID(),
				Name:       t.Name(),
				Category:   t.Category(),
				Pass:       true, // Critical business system
				Confidence: 1.0,
				Severity:   evaluation.SeverityCritical,
				Evidence:   fmt.Sprintf("System marked as %s business priority", criticality),
				Details: map[string]any{
					"criticality":  criticality,
					"service_name": ctx.DeploymentInfo.ServiceName,
				},
			}, nil
		}

		if criticality == "low" || criticality == "minimal" {
			return &reachability.TestResult{
				ID:         t.ID(),
				Name:       t.Name(),
				Category:   t.Category(),
				Pass:       false,
				Confidence: 0.9,
				Severity:   evaluation.SeverityLow,
				Evidence:   "System marked as low business priority",
				Details: map[string]any{
					"criticality": criticality,
				},
			}, nil
		}
	}

	// Analyze the code graph for critical patterns
	criticalNodes := q.NodesWhere(func(n *fsgraph.Node) bool {
		labelLower := strings.ToLower(n.Label)
		for _, pattern := range criticalPatterns {
			if strings.Contains(labelLower, pattern) {
				return true
			}
		}

		// Check attributes
		if n.Attrs["business_critical"] == "true" {
			return true
		}
		if n.Attrs["pii_handling"] == "true" {
			return true
		}
		if n.Attrs["compliance"] != "" {
			return true
		}

		return false
	})

	// Check if affected code is reachable from or affects critical nodes
	if len(targetIDs) > 0 && len(criticalNodes) > 0 {
		for _, critNode := range criticalNodes {
			// Check if there's a path from critical functionality to vulnerable code
			paths := q.FindAllPaths(critNode.ID, targetIDs, nil, 30)
			if len(paths) > 0 {
				return &reachability.TestResult{
					ID:         t.ID(),
					Name:       t.Name(),
					Category:   t.Category(),
					Pass:       true, // Critical business functionality affected
					Confidence: 0.9,
					Severity:   evaluation.SeverityCritical,
					Evidence:   fmt.Sprintf("Vulnerability reachable from critical function: %s", critNode.Label),
					Details: map[string]any{
						"critical_node":  critNode.ID,
						"critical_label": critNode.Label,
						"path_depth":     paths[0].Depth,
					},
				}, nil
			}

			// Check reverse: vulnerable code can affect critical functionality
			reversePaths := q.FindAllPaths(targetIDs[0], []string{critNode.ID}, nil, 30)
			if len(reversePaths) > 0 {
				return &reachability.TestResult{
					ID:         t.ID(),
					Name:       t.Name(),
					Category:   t.Category(),
					Pass:       true,
					Confidence: 0.85,
					Severity:   evaluation.SeverityHigh,
					Evidence:   fmt.Sprintf("Vulnerable code can affect critical function: %s", critNode.Label),
					Details: map[string]any{
						"critical_node":  critNode.ID,
						"critical_label": critNode.Label,
						"path_depth":     reversePaths[0].Depth,
					},
				}, nil
			}
		}
	}

	// Check if the affected package itself is critical
	packageToFind := ctx.AffectedPackage
	if packageToFind == "" && ctx.VulnInfo != nil && len(ctx.VulnInfo.AffectedPackages) > 0 {
		packageToFind = ctx.VulnInfo.AffectedPackages[0]
	}

	if packageToFind != "" {
		for _, pattern := range criticalPatterns {
			if strings.Contains(strings.ToLower(packageToFind), pattern) {
				return &reachability.TestResult{
					ID:         t.ID(),
					Name:       t.Name(),
					Category:   t.Category(),
					Pass:       true,
					Confidence: 0.8,
					Severity:   evaluation.SeverityHigh,
					Evidence:   fmt.Sprintf("Affected package (%s) appears to handle critical business data", packageToFind),
					Details: map[string]any{
						"package":         packageToFind,
						"matched_pattern": pattern,
					},
				}, nil
			}
		}
	}

	// No critical business indicators found
	return &reachability.TestResult{
		ID:         t.ID(),
		Name:       t.Name(),
		Category:   t.Category(),
		Pass:       false,
		Confidence: 0.6,
		Severity:   evaluation.SeverityLow,
		Evidence:   "No critical business functionality indicators detected",
		Details: map[string]any{
			"critical_nodes_in_graph": len(criticalNodes),
		},
	}, nil
}
