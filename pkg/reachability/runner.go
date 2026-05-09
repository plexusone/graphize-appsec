package reachability

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/plexusone/structured-evaluation/evaluation"
)

// Runner orchestrates test execution.
type Runner struct {
	tests  []Test
	logger *slog.Logger
}

// NewRunner creates a new test runner with all registered tests.
func NewRunner() *Runner {
	return &Runner{
		tests:  All(),
		logger: slog.Default(),
	}
}

// NewRunnerWithTests creates a runner with specific tests.
func NewRunnerWithTests(tests []Test) *Runner {
	return &Runner{
		tests:  tests,
		logger: slog.Default(),
	}
}

// NewRunnerForCategories creates a runner for specific categories.
func NewRunnerForCategories(categories ...Category) *Runner {
	var tests []Test
	for _, cat := range categories {
		tests = append(tests, ByCategory(cat)...)
	}
	return &Runner{
		tests:  tests,
		logger: slog.Default(),
	}
}

// SetLogger sets the logger for the runner.
func (r *Runner) SetLogger(logger *slog.Logger) {
	r.logger = logger
}

// RunResult contains the results of running all tests.
type RunResult struct {
	// Results contains individual test results.
	Results []*TestResult `json:"results"`

	// ByCategory groups results by category.
	ByCategory map[Category][]*TestResult `json:"by_category"`

	// CategoryScores contains aggregated scores per category.
	CategoryScores map[Category]*CategoryScore `json:"category_scores"`

	// TotalDuration is the total time taken.
	TotalDuration time.Duration `json:"total_duration"`

	// PassCount is the number of passing tests.
	PassCount int `json:"pass_count"`

	// FailCount is the number of failing tests.
	FailCount int `json:"fail_count"`

	// ErrorCount is the number of tests that errored.
	ErrorCount int `json:"error_count"`
}

// CategoryScore contains the aggregated score for a category.
type CategoryScore struct {
	Category      Category `json:"category"`
	Score         float64  `json:"score"`
	Weight        float64  `json:"weight"`
	WeightedScore float64  `json:"weighted_score"`
	PassCount     int      `json:"pass_count"`
	FailCount     int      `json:"fail_count"`
	Justification string   `json:"justification"`
}

// Run executes all tests and returns the results.
func (r *Runner) Run(ctx *EvalContext) (*RunResult, error) {
	if ctx.Context == nil {
		ctx.Context = context.Background()
	}

	start := time.Now()
	result := &RunResult{
		Results:        make([]*TestResult, 0, len(r.tests)),
		ByCategory:     make(map[Category][]*TestResult),
		CategoryScores: make(map[Category]*CategoryScore),
	}

	// Initialize category groupings
	for _, cat := range AllCategories() {
		result.ByCategory[cat] = []*TestResult{}
		result.CategoryScores[cat] = &CategoryScore{
			Category: cat,
			Weight:   cat.Weight(),
		}
	}

	// Run each test
	for _, test := range r.tests {
		select {
		case <-ctx.Context.Done():
			return result, ctx.Context.Err()
		default:
		}

		testResult := r.runTest(ctx, test)
		result.Results = append(result.Results, testResult)
		result.ByCategory[test.Category()] = append(result.ByCategory[test.Category()], testResult)

		// Update counts
		if testResult.Error != "" {
			result.ErrorCount++
		} else if testResult.Pass {
			result.PassCount++
			result.CategoryScores[test.Category()].PassCount++
		} else {
			result.FailCount++
			result.CategoryScores[test.Category()].FailCount++
		}
	}

	// Calculate category scores
	for cat, score := range result.CategoryScores {
		results := result.ByCategory[cat]
		if len(results) > 0 {
			score.Score = r.calculateCategoryScore(cat, results)
			score.WeightedScore = score.Score * score.Weight
			score.Justification = r.generateJustification(cat, results)
		}
	}

	result.TotalDuration = time.Since(start)
	return result, nil
}

// runTest executes a single test with error handling.
func (r *Runner) runTest(ctx *EvalContext, test Test) *TestResult {
	start := time.Now()

	result, err := test.Evaluate(ctx)
	if err != nil {
		r.logger.Warn("test execution error",
			"test_id", test.ID(),
			"error", err,
		)
		return &TestResult{
			ID:         test.ID(),
			Name:       test.Name(),
			Category:   test.Category(),
			Pass:       false,
			Confidence: 0.0,
			Severity:   evaluation.SeverityInfo,
			Evidence:   fmt.Sprintf("Test error: %v", err),
			Duration:   time.Since(start),
			Error:      err.Error(),
		}
	}

	result.Duration = time.Since(start)
	return result
}

// calculateCategoryScore calculates the score for a category.
// Higher score = higher risk (for security context).
func (r *Runner) calculateCategoryScore(cat Category, results []*TestResult) float64 {
	if len(results) == 0 {
		return 0.0
	}

	var totalScore float64
	var totalWeight float64

	for _, result := range results {
		if result.Error != "" {
			continue
		}

		// Weight by confidence
		weight := result.Confidence
		totalWeight += weight

		// Score based on pass/fail and category semantics
		var score float64
		switch cat {
		case CategoryReachable:
			// For reachable: Pass=true means risk exists (higher score = more risk)
			if result.Pass {
				score = 10.0 // Risk exists
			} else {
				score = 0.0 // No risk
			}
		case CategoryExploitable:
			// For exploitable: Mixed semantics
			// Some tests: Pass=true means exploitable (bad)
			// Some tests (EPSS Low, AI Unexploitable): Pass=true means safe (good)
			if isRiskMitigatedTest(result.ID) {
				if result.Pass {
					score = 0.0 // Risk mitigated
				} else {
					score = 10.0 // Risk not mitigated
				}
			} else {
				if result.Pass {
					score = 10.0 // Exploitable
				} else {
					score = 0.0 // Not exploitable
				}
			}
		case CategoryDamage:
			// For damage: Pass=true means high damage potential
			if result.Pass {
				score = 10.0 // High damage
			} else {
				score = 0.0 // Low damage
			}
		}

		totalScore += score * weight
	}

	if totalWeight == 0 {
		return 0.0
	}

	return totalScore / totalWeight
}

// isRiskMitigatedTest returns true if the test's Pass=true means risk is mitigated.
func isRiskMitigatedTest(testID string) bool {
	// These tests have inverted semantics: Pass=true is good (risk mitigated)
	mitigatedTests := map[string]bool{
		"EXPLOIT-005": true, // EPSS Low Risk - Pass means low risk
		"EXPLOIT-006": true, // AI Unexploitable - Pass means unexploitable
	}
	return mitigatedTests[testID]
}

// generateJustification creates a human-readable justification for the category score.
func (r *Runner) generateJustification(cat Category, results []*TestResult) string {
	passCount := 0
	failCount := 0
	for _, result := range results {
		if result.Error == "" {
			if result.Pass {
				passCount++
			} else {
				failCount++
			}
		}
	}

	total := passCount + failCount
	if total == 0 {
		return "No tests completed"
	}

	switch cat {
	case CategoryReachable:
		if passCount == 0 {
			return "No reachability indicators found - vulnerability appears isolated"
		}
		return fmt.Sprintf("%d/%d reachability tests indicate exposure", passCount, total)
	case CategoryExploitable:
		return fmt.Sprintf("%d/%d exploitability tests indicate risk", passCount, total)
	case CategoryDamage:
		if passCount == 0 {
			return "Low damage potential based on context analysis"
		}
		return fmt.Sprintf("%d/%d damage indicators present", passCount, total)
	default:
		return fmt.Sprintf("%d/%d tests passed", passCount, total)
	}
}

// Decision determines the overall decision based on results.
func (r *RunResult) Decision() evaluation.DecisionStatus {
	// Check for critical findings
	for _, result := range r.Results {
		if result.Severity == evaluation.SeverityCritical && result.Pass {
			return evaluation.DecisionFail
		}
	}

	// Calculate weighted score
	var totalWeightedScore float64
	for _, score := range r.CategoryScores {
		totalWeightedScore += score.WeightedScore
	}

	// Decision based on weighted score (0-10 scale)
	switch {
	case totalWeightedScore >= 7.0:
		return evaluation.DecisionFail
	case totalWeightedScore >= 4.0:
		return evaluation.DecisionConditional
	default:
		return evaluation.DecisionPass
	}
}

// WeightedScore returns the total weighted score.
func (r *RunResult) WeightedScore() float64 {
	var total float64
	for _, score := range r.CategoryScores {
		total += score.WeightedScore
	}
	return total
}
