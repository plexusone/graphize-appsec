package reachability

import (
	"time"

	"github.com/plexusone/structured-evaluation/evaluation"
)

// Test defines the interface for a reachability test.
type Test interface {
	// ID returns the unique test identifier (e.g., "REACH-001").
	ID() string

	// Name returns the human-readable test name.
	Name() string

	// Description returns a detailed description of what the test checks.
	Description() string

	// Category returns the test category (reachable, exploitable, damage).
	Category() Category

	// Evaluate runs the test and returns the result.
	Evaluate(ctx *EvalContext) (*TestResult, error)
}

// TestResult holds the outcome of a reachability test.
type TestResult struct {
	// ID is the test identifier.
	ID string `json:"id"`

	// Name is the human-readable test name.
	Name string `json:"name"`

	// Category is the test category.
	Category Category `json:"category"`

	// Pass indicates whether the condition tested is TRUE.
	// For "risk exists" tests: Pass=true means risk exists.
	// For "risk mitigated" tests: Pass=true means risk is mitigated.
	Pass bool `json:"pass"`

	// Confidence is the certainty of the result (0.0-1.0).
	Confidence float64 `json:"confidence"`

	// Severity indicates the security severity based on the result.
	Severity evaluation.Severity `json:"severity"`

	// Evidence provides human-readable explanation of the finding.
	Evidence string `json:"evidence"`

	// Details contains structured additional information.
	Details map[string]any `json:"details,omitempty"`

	// Duration is how long the test took to run.
	Duration time.Duration `json:"duration"`

	// Error contains any error message if the test failed to execute.
	Error string `json:"error,omitempty"`
}

// ToFinding converts the test result to a structured-evaluation Finding.
func (r *TestResult) ToFinding() *evaluation.Finding {
	return &evaluation.Finding{
		ID:          r.ID,
		Category:    r.Category.String(),
		Severity:    r.Severity,
		Title:       r.Name,
		Description: r.Evidence,
	}
}

// BaseTest provides common functionality for tests.
type BaseTest struct {
	id          string
	name        string
	description string
	category    Category
}

// NewBaseTest creates a new BaseTest.
func NewBaseTest(id, name, description string, category Category) BaseTest {
	return BaseTest{
		id:          id,
		name:        name,
		description: description,
		category:    category,
	}
}

// ID returns the test identifier.
func (t BaseTest) ID() string { return t.id }

// Name returns the test name.
func (t BaseTest) Name() string { return t.name }

// Description returns the test description.
func (t BaseTest) Description() string { return t.description }

// Category returns the test category.
func (t BaseTest) Category() Category { return t.category }
