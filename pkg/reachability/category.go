// Package reachability provides the test framework for security reachability analysis.
package reachability

// Category represents a test category for reachability analysis.
type Category string

const (
	// CategoryReachable tests whether vulnerable code is reachable.
	CategoryReachable Category = "reachable"

	// CategoryExploitable tests whether the vulnerability is exploitable.
	CategoryExploitable Category = "exploitable"

	// CategoryDamage tests the potential damage if exploited.
	CategoryDamage Category = "damage"
)

// String returns the string representation of the category.
func (c Category) String() string {
	return string(c)
}

// Weight returns the default weight for scoring.
func (c Category) Weight() float64 {
	switch c {
	case CategoryReachable:
		return 0.40
	case CategoryExploitable:
		return 0.35
	case CategoryDamage:
		return 0.25
	default:
		return 0.0
	}
}

// AllCategories returns all test categories in order.
func AllCategories() []Category {
	return []Category{
		CategoryReachable,
		CategoryExploitable,
		CategoryDamage,
	}
}
