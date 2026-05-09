package reachable

import (
	"fmt"

	fsgraph "github.com/plexusone/graphfs/pkg/graph"
	"github.com/plexusone/structured-evaluation/evaluation"

	"github.com/plexusone/graphize-appsec/pkg/graph"
	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func init() {
	reachability.Register(NewExposedByAPITest())
}

// ExposedByAPITest checks if vulnerable code is reachable from API endpoints.
type ExposedByAPITest struct {
	reachability.BaseTest
}

// NewExposedByAPITest creates a new test.
func NewExposedByAPITest() *ExposedByAPITest {
	return &ExposedByAPITest{
		BaseTest: reachability.NewBaseTest(
			"REACH-003",
			"Exposed by API",
			"Checks if vulnerable code is reachable from a public API endpoint",
			reachability.CategoryReachable,
		),
	}
}

// Evaluate runs the test.
func (t *ExposedByAPITest) Evaluate(ctx *reachability.EvalContext) (*reachability.TestResult, error) {
	q := graph.NewQuery(ctx.Graph)

	// Find API endpoints
	apiEndpoints := q.FindAPIEndpoints()
	if len(apiEndpoints) == 0 {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false,
			Confidence: 0.6, // May not have API detection
			Severity:   evaluation.SeverityInfo,
			Evidence:   "No API endpoints detected in the codebase",
			Details: map[string]any{
				"reason": "no_api_endpoints",
			},
		}, nil
	}

	// Get target nodes
	targetIDs := ctx.AffectedNodeIDs
	if len(targetIDs) == 0 && ctx.AffectedFunction != "" {
		targetIDs = []string{ctx.AffectedFunction}
	}

	if len(targetIDs) == 0 {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false,
			Confidence: 0.3,
			Severity:   evaluation.SeverityInfo,
			Evidence:   "No target functions identified for API exposure analysis",
		}, nil
	}

	// Check reachability from each API endpoint
	type apiPath struct {
		endpoint   *fsgraph.Node
		path       *graph.AttackPath
		httpMethod string
		httpPath   string
	}

	var exposedPaths []apiPath

	for _, ep := range apiEndpoints {
		paths := q.FindAllPaths(ep.ID, targetIDs, nil, 50) // nil = all edge types
		for _, path := range paths {
			exposedPaths = append(exposedPaths, apiPath{
				endpoint:   ep,
				path:       path,
				httpMethod: ep.Attrs["http_method"],
				httpPath:   ep.Attrs["http_path"],
			})
		}
	}

	if len(exposedPaths) > 0 {
		// Find the shortest/most direct path
		shortest := exposedPaths[0]
		for _, ep := range exposedPaths[1:] {
			if ep.path.Depth < shortest.path.Depth {
				shortest = ep
			}
		}

		// Check if authentication is required
		requiresAuth := shortest.endpoint.Attrs["requires_auth"] == "true"
		authLevel := shortest.endpoint.Attrs["auth_level"]

		severity := evaluation.SeverityCritical
		if requiresAuth {
			severity = evaluation.SeverityHigh
		}

		details := map[string]any{
			"api_endpoint":  shortest.endpoint.ID,
			"http_method":   shortest.httpMethod,
			"http_path":     shortest.httpPath,
			"target":        shortest.path.ToID,
			"depth":         shortest.path.Depth,
			"path":          shortest.path.String(),
			"requires_auth": requiresAuth,
			"exposed_paths": len(exposedPaths),
			"api_count":     len(apiEndpoints),
		}

		if authLevel != "" {
			details["auth_level"] = authLevel
		}

		evidence := fmt.Sprintf("Vulnerable code reachable from API endpoint %s %s",
			shortest.httpMethod, shortest.httpPath)
		if shortest.httpMethod == "" && shortest.httpPath == "" {
			evidence = fmt.Sprintf("Vulnerable code reachable from API endpoint %s", shortest.endpoint.Label)
		}
		if requiresAuth {
			evidence += " (requires authentication)"
		} else {
			evidence += " (public endpoint)"
		}

		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       true, // API DOES expose vulnerable code - risk exists
			Confidence: 1.0,
			Severity:   severity,
			Evidence:   evidence,
			Details:    details,
		}, nil
	}

	return &reachability.TestResult{
		ID:         t.ID(),
		Name:       t.Name(),
		Category:   t.Category(),
		Pass:       false, // API does NOT expose vulnerable code - no direct risk
		Confidence: 0.9,
		Severity:   evaluation.SeverityLow,
		Evidence:   fmt.Sprintf("No API path to vulnerable code from %d endpoints", len(apiEndpoints)),
		Details: map[string]any{
			"api_endpoints_checked": len(apiEndpoints),
			"targets_checked":       len(targetIDs),
		},
	}, nil
}
