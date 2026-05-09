package reachability

import (
	"fmt"
	"sync"
)

// registry holds all registered tests.
var (
	registryMu sync.RWMutex
	tests      = make(map[string]Test)
	testOrder  []string
)

// Register adds a test to the global registry.
func Register(t Test) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := tests[t.ID()]; exists {
		panic(fmt.Sprintf("test %s already registered", t.ID()))
	}

	tests[t.ID()] = t
	testOrder = append(testOrder, t.ID())
}

// Get returns a test by ID.
func Get(id string) (Test, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	t, ok := tests[id]
	return t, ok
}

// All returns all registered tests in registration order.
func All() []Test {
	registryMu.RLock()
	defer registryMu.RUnlock()

	result := make([]Test, 0, len(testOrder))
	for _, id := range testOrder {
		if t, ok := tests[id]; ok {
			result = append(result, t)
		}
	}
	return result
}

// ByCategory returns all tests in a specific category.
func ByCategory(category Category) []Test {
	registryMu.RLock()
	defer registryMu.RUnlock()

	var result []Test
	for _, id := range testOrder {
		if t, ok := tests[id]; ok && t.Category() == category {
			result = append(result, t)
		}
	}
	return result
}

// IDs returns all registered test IDs in order.
func IDs() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	result := make([]string, len(testOrder))
	copy(result, testOrder)
	return result
}

// Count returns the number of registered tests.
func Count() int {
	registryMu.RLock()
	defer registryMu.RUnlock()

	return len(tests)
}

// CountByCategory returns the count of tests per category.
func CountByCategory() map[Category]int {
	registryMu.RLock()
	defer registryMu.RUnlock()

	counts := make(map[Category]int)
	for _, t := range tests {
		counts[t.Category()]++
	}
	return counts
}
