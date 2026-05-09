package damage

import (
	"fmt"
	"strings"

	"github.com/plexusone/structured-evaluation/evaluation"

	"github.com/plexusone/graphize-appsec/pkg/graph"
	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func init() {
	reachability.Register(NewLoginManagementTest())
}

// LoginManagementTest checks if vulnerability affects authentication/login systems.
type LoginManagementTest struct {
	reachability.BaseTest
}

// NewLoginManagementTest creates a new test.
func NewLoginManagementTest() *LoginManagementTest {
	return &LoginManagementTest{
		BaseTest: reachability.NewBaseTest(
			"DAMAGE-002",
			"Login Management",
			"Checks if the vulnerability affects authentication or login management systems",
			reachability.CategoryDamage,
		),
	}
}

// Evaluate runs the test.
func (t *LoginManagementTest) Evaluate(ctx *reachability.EvalContext) (*reachability.TestResult, error) {
	q := graph.NewQuery(ctx.Graph)

	// Get target nodes
	targetIDs := ctx.AffectedNodeIDs
	if len(targetIDs) == 0 && ctx.AffectedFunction != "" {
		targetIDs = []string{ctx.AffectedFunction}
	}

	// Also check the affected package
	packageName := ctx.AffectedPackage
	if packageName == "" && ctx.VulnInfo != nil && len(ctx.VulnInfo.AffectedPackages) > 0 {
		packageName = ctx.VulnInfo.AffectedPackages[0]
	}

	// Auth-related terms
	authTerms := ctx.Config.AuthPackages
	if len(authTerms) == 0 {
		authTerms = []string{"auth", "login", "session", "oauth", "jwt", "token", "credential", "password", "saml", "oidc", "identity"}
	}

	// Check 1: Is the affected package auth-related?
	packageIsAuth := false
	if packageName != "" {
		lowerPkg := strings.ToLower(packageName)
		for _, term := range authTerms {
			if strings.Contains(lowerPkg, term) {
				packageIsAuth = true
				break
			}
		}
	}

	if packageIsAuth {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       true, // Affects auth - high damage
			Confidence: 0.95,
			Severity:   evaluation.SeverityCritical,
			Evidence:   fmt.Sprintf("Vulnerable package %s appears to be authentication-related", packageName),
			Details: map[string]any{
				"package":    packageName,
				"matched_on": "package_name",
				"auth_terms": authTerms,
			},
		}, nil
	}

	// Check 2: Are the affected functions auth-related?
	if len(targetIDs) > 0 {
		for _, targetID := range targetIDs {
			lowerID := strings.ToLower(targetID)
			for _, term := range authTerms {
				if strings.Contains(lowerID, term) {
					return &reachability.TestResult{
						ID:         t.ID(),
						Name:       t.Name(),
						Category:   t.Category(),
						Pass:       true,
						Confidence: 0.9,
						Severity:   evaluation.SeverityCritical,
						Evidence:   fmt.Sprintf("Vulnerable function %s appears to be authentication-related", targetID),
						Details: map[string]any{
							"function":   targetID,
							"matched_on": "function_name",
						},
					}, nil
				}
			}
		}
	}

	// Check 3: Is the vulnerable code called from auth-related functions?
	authNodes := q.NodesWhere(graph.IsAuthRelated())

	for _, authNode := range authNodes {
		for _, targetID := range targetIDs {
			if q.IsReachable(authNode.ID, targetID, []string{"calls"}) {
				return &reachability.TestResult{
					ID:         t.ID(),
					Name:       t.Name(),
					Category:   t.Category(),
					Pass:       true,
					Confidence: 0.85,
					Severity:   evaluation.SeverityHigh,
					Evidence:   fmt.Sprintf("Vulnerable code is called from authentication function %s", authNode.Label),
					Details: map[string]any{
						"auth_function": authNode.ID,
						"target":        targetID,
						"matched_on":    "call_graph",
					},
				}, nil
			}
		}
	}

	// Check 4: Does the vulnerable code call auth-related functions?
	for _, targetID := range targetIDs {
		for _, authNode := range authNodes {
			if q.IsReachable(targetID, authNode.ID, []string{"calls"}) {
				return &reachability.TestResult{
					ID:         t.ID(),
					Name:       t.Name(),
					Category:   t.Category(),
					Pass:       true,
					Confidence: 0.80,
					Severity:   evaluation.SeverityHigh,
					Evidence:   fmt.Sprintf("Vulnerable code calls authentication function %s", authNode.Label),
					Details: map[string]any{
						"auth_function": authNode.ID,
						"caller":        targetID,
						"matched_on":    "reverse_call_graph",
					},
				}, nil
			}
		}
	}

	return &reachability.TestResult{
		ID:         t.ID(),
		Name:       t.Name(),
		Category:   t.Category(),
		Pass:       false, // Does NOT affect auth - limited damage
		Confidence: 0.75,  // Moderate confidence - may miss some patterns
		Severity:   evaluation.SeverityLow,
		Evidence:   "No connection to authentication or login management detected",
		Details: map[string]any{
			"auth_nodes_checked": len(authNodes),
			"targets_checked":    len(targetIDs),
		},
	}, nil
}
