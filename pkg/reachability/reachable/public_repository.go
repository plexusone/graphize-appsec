package reachable

import (
	"strings"

	"github.com/plexusone/structured-evaluation/evaluation"

	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func init() {
	reachability.Register(NewPublicRepositoryTest())
}

// PublicRepositoryTest checks if the vulnerable component is in a public repository.
type PublicRepositoryTest struct {
	reachability.BaseTest
}

// NewPublicRepositoryTest creates a new test.
func NewPublicRepositoryTest() *PublicRepositoryTest {
	return &PublicRepositoryTest{
		BaseTest: reachability.NewBaseTest(
			"REACH-005",
			"Public Repository",
			"Checks if the vulnerable component is exposed in a public repository",
			reachability.CategoryReachable,
		),
	}
}

// Evaluate runs the test.
func (t *PublicRepositoryTest) Evaluate(ctx *reachability.EvalContext) (*reachability.TestResult, error) {
	// Check deployment info for repository visibility
	if ctx.DeploymentInfo != nil {
		repoURL := ctx.DeploymentInfo.RepositoryURL

		// Check if repo URL indicates public visibility
		isPublic := false
		visibility := "unknown"

		if repoURL != "" {
			// Check for common public repository patterns
			publicPatterns := []string{
				"github.com/",
				"gitlab.com/",
				"bitbucket.org/",
			}

			for _, pattern := range publicPatterns {
				if strings.Contains(repoURL, pattern) {
					// Public hosting service - assume public unless indicated otherwise
					isPublic = true
					visibility = "public"
					break
				}
			}

			// Check for private patterns
			privatePatterns := []string{
				"github.com/enterprise",
				"gitlab.example.com",
				"bitbucket.example.com",
			}
			for _, pattern := range privatePatterns {
				if strings.Contains(repoURL, pattern) {
					isPublic = false
					visibility = "private"
					break
				}
			}
		}

		// Check explicit visibility setting
		if ctx.DeploymentInfo.Visibility != "" {
			visibility = ctx.DeploymentInfo.Visibility
			isPublic = visibility == "public"
		}

		if isPublic {
			return &reachability.TestResult{
				ID:         t.ID(),
				Name:       t.Name(),
				Category:   t.Category(),
				Pass:       true, // Public repo - increased exposure
				Confidence: 0.9,
				Severity:   evaluation.SeverityHigh,
				Evidence:   "Vulnerable component is in a public repository",
				Details: map[string]any{
					"repository": repoURL,
					"visibility": visibility,
				},
			}, nil
		}

		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false, // Private repo - less exposure
			Confidence: 0.9,
			Severity:   evaluation.SeverityLow,
			Evidence:   "Vulnerable component is in a private repository",
			Details: map[string]any{
				"repository": repoURL,
				"visibility": visibility,
			},
		}, nil
	}

	return &reachability.TestResult{
		ID:         t.ID(),
		Name:       t.Name(),
		Category:   t.Category(),
		Pass:       false,
		Confidence: 0.3,
		Severity:   evaluation.SeverityInfo,
		Evidence:   "No repository information available",
		Details: map[string]any{
			"reason": "missing_deployment_info",
		},
	}, nil
}
