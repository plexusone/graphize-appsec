package reachability

import (
	"context"

	"github.com/plexusone/graphfs/pkg/graph"
	"github.com/plexusone/graphfs/pkg/query"
)

// EvalContext provides the data needed for test evaluation.
type EvalContext struct {
	// Context is the Go context for cancellation and timeouts.
	Context context.Context

	// Graph is the loaded code knowledge graph.
	Graph *graph.Graph

	// Traverser provides graph traversal capabilities.
	Traverser *query.Traverser

	// VulnID is the vulnerability identifier (e.g., "CVE-2021-44228").
	VulnID string

	// VulnInfo contains detailed vulnerability information.
	VulnInfo *VulnerabilityInfo

	// AffectedPackage is the package containing the vulnerability.
	AffectedPackage string

	// AffectedFunction is the specific function containing the vulnerability (if known).
	AffectedFunction string

	// AffectedNodeIDs are the graph node IDs that represent vulnerable code.
	AffectedNodeIDs []string

	// DeploymentInfo contains runtime deployment information (optional).
	DeploymentInfo *DeploymentInfo

	// Deployments contains runtime deployment information (optional).
	Deployments []*DeploymentInfo

	// Config contains test configuration.
	Config *Config
}

// NewEvalContext creates a new evaluation context.
func NewEvalContext(ctx context.Context, g *graph.Graph, vulnID string) *EvalContext {
	return &EvalContext{
		Context:   ctx,
		Graph:     g,
		Traverser: query.NewTraverser(g),
		VulnID:    vulnID,
		Config:    DefaultConfig(),
	}
}

// VulnerabilityInfo contains information about a vulnerability.
type VulnerabilityInfo struct {
	// ID is the primary identifier (e.g., "CVE-2021-44228").
	ID string `json:"id"`

	// Aliases are alternative identifiers (e.g., "GHSA-xxx").
	Aliases []string `json:"aliases,omitempty"`

	// Summary is a brief description.
	Summary string `json:"summary"`

	// Description is the detailed description.
	Description string `json:"description"`

	// Severity is the severity level.
	Severity string `json:"severity"`

	// CVSSScore is the CVSS score (0.0-10.0).
	CVSSScore float64 `json:"cvss_score"`

	// CVSSVector is the CVSS vector string.
	CVSSVector string `json:"cvss_vector,omitempty"`

	// EPSSScore is the EPSS probability (0.0-1.0).
	EPSSScore float64 `json:"epss_score"`

	// IsKnownExploited indicates if in CISA KEV.
	IsKnownExploited bool `json:"is_known_exploited"`

	// InCISAKEV indicates if in CISA Known Exploited Vulnerabilities catalog.
	InCISAKEV bool `json:"in_cisa_kev"`

	// AffectedPackages lists affected package identifiers (purls).
	AffectedPackages []string `json:"affected_packages"`

	// AffectedVersions maps package to affected version ranges.
	AffectedVersions map[string]string `json:"affected_versions,omitempty"`

	// FixedVersions maps package to fixed versions.
	FixedVersions map[string]string `json:"fixed_versions,omitempty"`

	// References are URLs for more information.
	References []string `json:"references,omitempty"`

	// PublicExploits lists known public exploits.
	PublicExploits []string `json:"public_exploits,omitempty"`

	// Community Buzz fields
	ExploitDBID       string `json:"exploitdb_id,omitempty"`
	HasPublicPoC      bool   `json:"has_public_poc"`
	TwitterMentions   int    `json:"twitter_mentions"`
	GitHubPoCStstars  int    `json:"github_poc_stars"`
	SecurityBlogPosts int    `json:"security_blog_posts"`

	// Patching history fields
	PatchIterations           int      `json:"patch_iterations"`
	PatchBypasses             int      `json:"patch_bypasses"`
	RelatedCVEs               []string `json:"related_cves,omitempty"`
	HasIncompleteFixIndicator bool     `json:"has_incomplete_fix_indicator"`

	// Exploit availability fields
	MetasploitModule string `json:"metasploit_module,omitempty"`
	GitHubPoCCount   int    `json:"github_poc_count"`
	NucleiTemplate   bool   `json:"nuclei_template"`

	// AI analysis fields
	AIAnalysisPerformed   bool    `json:"ai_analysis_performed"`
	AIExploitabilityScore float64 `json:"ai_exploitability_score"`
	AIConfidence          float64 `json:"ai_confidence"`
	AIReasoning           string  `json:"ai_reasoning,omitempty"`
}

// DeploymentInfo contains runtime deployment information.
type DeploymentInfo struct {
	// Name is the deployment name.
	Name string `json:"name"`

	// ServiceName is the service/application name.
	ServiceName string `json:"service_name,omitempty"`

	// Namespace is the Kubernetes namespace.
	Namespace string `json:"namespace"`

	// Cluster is the Kubernetes cluster name.
	Cluster string `json:"cluster,omitempty"`

	// Environment is the deployment environment (e.g., "production", "staging").
	Environment string `json:"environment"`

	// Status is the deployment status (e.g., "running", "stopped").
	Status string `json:"status"`

	// Replicas is the number of running replicas.
	Replicas int `json:"replicas"`

	// Image is the container image.
	Image string `json:"image"`

	// ImageDeployed indicates if the image is deployed.
	ImageDeployed bool `json:"image_deployed"`

	// ContainerRunning indicates if the container is actively running.
	ContainerRunning bool `json:"container_running"`

	// IsInternetExposed indicates if the deployment is internet-accessible.
	IsInternetExposed bool `json:"is_internet_exposed"`

	// IngressPaths are the exposed HTTP paths.
	IngressPaths []string `json:"ingress_paths,omitempty"`

	// RepositoryURL is the source code repository URL.
	RepositoryURL string `json:"repository_url,omitempty"`

	// Visibility is the repository visibility (public/private).
	Visibility string `json:"visibility,omitempty"`

	// BusinessCriticality is the business criticality level (critical/high/medium/low).
	BusinessCriticality string `json:"business_criticality,omitempty"`
}

// Config contains test configuration.
type Config struct {
	// Thresholds for scoring
	MinConfidence    float64 `yaml:"min_confidence"`
	HighSeverityCVSS float64 `yaml:"high_severity_cvss"`
	EPSSHighRisk     float64 `yaml:"epss_high_risk"`

	// Category weights
	CategoryWeights map[Category]float64 `yaml:"category_weights"`

	// Business context
	CriticalPackages []string `yaml:"critical_packages"`
	AuthPackages     []string `yaml:"auth_packages"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		MinConfidence:    0.5,
		HighSeverityCVSS: 7.0,
		EPSSHighRisk:     0.1,
		CategoryWeights: map[Category]float64{
			CategoryReachable:   0.40,
			CategoryExploitable: 0.35,
			CategoryDamage:      0.25,
		},
		CriticalPackages: []string{},
		AuthPackages:     []string{"auth", "login", "session", "oauth", "jwt"},
	}
}
