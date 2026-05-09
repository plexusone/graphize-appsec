package reachable

import (
	"github.com/plexusone/structured-evaluation/evaluation"

	"github.com/plexusone/graphize-appsec/pkg/reachability"
)

func init() {
	reachability.Register(NewCloudDeployedTest())
}

// CloudDeployedTest checks if the vulnerable container/image is actually deployed.
type CloudDeployedTest struct {
	reachability.BaseTest
}

// NewCloudDeployedTest creates a new test.
func NewCloudDeployedTest() *CloudDeployedTest {
	return &CloudDeployedTest{
		BaseTest: reachability.NewBaseTest(
			"REACH-007",
			"Cloud Deployed",
			"Checks if the container/image with the vulnerability is actually deployed and running",
			reachability.CategoryReachable,
		),
	}
}

// Evaluate runs the test.
func (t *CloudDeployedTest) Evaluate(ctx *reachability.EvalContext) (*reachability.TestResult, error) {
	// Check deployment info
	if ctx.DeploymentInfo == nil {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false,
			Confidence: 0.3,
			Severity:   evaluation.SeverityInfo,
			Evidence:   "No deployment information available",
			Details: map[string]any{
				"reason": "missing_deployment_info",
			},
		}, nil
	}

	// Check if running in cloud environment
	env := ctx.DeploymentInfo.Environment
	isCloudEnv := env == "production" || env == "staging" || env == "cloud"

	// Check container/image deployment status
	imageDeployed := ctx.DeploymentInfo.ImageDeployed
	containerRunning := ctx.DeploymentInfo.ContainerRunning

	if containerRunning {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       true, // Container is running - vulnerability is active
			Confidence: 1.0,
			Severity:   evaluation.SeverityCritical,
			Evidence:   "Vulnerable container is actively running in deployment",
			Details: map[string]any{
				"environment":       env,
				"image_deployed":    imageDeployed,
				"container_running": containerRunning,
				"namespace":         ctx.DeploymentInfo.Namespace,
				"cluster":           ctx.DeploymentInfo.Cluster,
			},
		}, nil
	}

	if imageDeployed && isCloudEnv {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       true, // Image deployed but not confirmed running
			Confidence: 0.8,
			Severity:   evaluation.SeverityHigh,
			Evidence:   "Vulnerable image is deployed to cloud environment",
			Details: map[string]any{
				"environment":       env,
				"image_deployed":    imageDeployed,
				"container_running": containerRunning,
			},
		}, nil
	}

	if !imageDeployed {
		return &reachability.TestResult{
			ID:         t.ID(),
			Name:       t.Name(),
			Category:   t.Category(),
			Pass:       false, // Image not deployed - no active risk
			Confidence: 0.9,
			Severity:   evaluation.SeverityLow,
			Evidence:   "Vulnerable image is not deployed",
			Details: map[string]any{
				"environment":       env,
				"image_deployed":    imageDeployed,
				"container_running": containerRunning,
			},
		}, nil
	}

	// Image deployed but in non-cloud environment
	return &reachability.TestResult{
		ID:         t.ID(),
		Name:       t.Name(),
		Category:   t.Category(),
		Pass:       false,
		Confidence: 0.7,
		Severity:   evaluation.SeverityMedium,
		Evidence:   "Vulnerable image deployed to non-production environment",
		Details: map[string]any{
			"environment":       env,
			"image_deployed":    imageDeployed,
			"container_running": containerRunning,
		},
	}, nil
}
