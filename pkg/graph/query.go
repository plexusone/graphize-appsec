// Package graph provides utilities for querying the code knowledge graph.
package graph

import (
	"strings"

	"github.com/plexusone/graphfs/pkg/graph"
	"github.com/plexusone/graphfs/pkg/query"
)

// Query wraps graphfs traversal with security-focused utilities.
type Query struct {
	graph     *graph.Graph
	traverser *query.Traverser
}

// NewQuery creates a new query wrapper.
func NewQuery(g *graph.Graph) *Query {
	return &Query{
		graph:     g,
		traverser: query.NewTraverser(g),
	}
}

// Graph returns the underlying graph.
func (q *Query) Graph() *graph.Graph {
	return q.graph
}

// Traverser returns the underlying traverser.
func (q *Query) Traverser() *query.Traverser {
	return q.traverser
}

// FindEntryPoints returns all nodes that are entry points.
func (q *Query) FindEntryPoints() []*graph.Node {
	return q.NodesWhere(func(n *graph.Node) bool {
		// Check explicit entry point marker
		if n.Attrs["is_entrypoint"] == "true" {
			return true
		}

		// Check handler marker
		if n.Attrs["is_handler"] == "true" {
			return true
		}

		// Check for main functions
		if n.Type == "function" && n.Attrs["name"] == "main" {
			return true
		}

		// Check framework layers (controllers are entry points)
		if n.Attrs["framework_layer"] == "controller" {
			return true
		}

		return false
	})
}

// FindAPIEndpoints returns all API endpoint nodes.
func (q *Query) FindAPIEndpoints() []*graph.Node {
	return q.NodesWhere(func(n *graph.Node) bool {
		if n.Type == "api_endpoint" {
			return true
		}
		if n.Attrs["is_handler"] == "true" {
			return true
		}
		if n.Attrs["http_method"] != "" {
			return true
		}
		if n.Attrs["framework_layer"] == "controller" {
			return true
		}
		return false
	})
}

// FindPackageNodes returns all package nodes.
func (q *Query) FindPackageNodes() []*graph.Node {
	return q.NodesWhere(func(n *graph.Node) bool {
		return n.Type == "package" || n.Type == "module"
	})
}

// FindFunctionNodes returns all function/method nodes.
func (q *Query) FindFunctionNodes() []*graph.Node {
	return q.NodesWhere(func(n *graph.Node) bool {
		return n.Type == "function" || n.Type == "method"
	})
}

// NodesWhere returns nodes matching the predicate.
func (q *Query) NodesWhere(predicate func(*graph.Node) bool) []*graph.Node {
	var result []*graph.Node
	for _, node := range q.graph.Nodes {
		if predicate(node) {
			result = append(result, node)
		}
	}
	return result
}

// NodeByID returns a node by ID.
func (q *Query) NodeByID(id string) *graph.Node {
	return q.graph.GetNode(id)
}

// NodesByIDs returns nodes by IDs.
func (q *Query) NodesByIDs(ids []string) []*graph.Node {
	var result []*graph.Node
	for _, id := range ids {
		if node := q.graph.GetNode(id); node != nil {
			result = append(result, node)
		}
	}
	return result
}

// HasNode checks if a node exists.
func (q *Query) HasNode(id string) bool {
	return q.graph.GetNode(id) != nil
}

// HasPackage checks if a package exists in the graph.
func (q *Query) HasPackage(packageName string) bool {
	// Try various ID formats
	prefixes := []string{"pkg_", "go_pkg_", "java_pkg_", "ts_pkg_", "groovy_pkg_"}
	for _, prefix := range prefixes {
		if q.HasNode(prefix + packageName) {
			return true
		}
	}

	// Also check by searching nodes
	for _, node := range q.graph.Nodes {
		if node.Type == "package" || node.Type == "module" {
			if node.Label == packageName || node.Attrs["name"] == packageName {
				return true
			}
			// Check purl
			if purl := node.Attrs["purl"]; purl != "" && strings.Contains(purl, packageName) {
				return true
			}
		}
	}

	return false
}

// IsReachable checks if target is reachable from source.
func (q *Query) IsReachable(sourceID, targetID string, edgeTypes []string) bool {
	path := q.FindPath(sourceID, targetID, edgeTypes)
	return path != nil && len(path.Nodes) > 0
}

// FindPath finds the shortest path between two nodes.
func (q *Query) FindPath(fromID, toID string, edgeTypes []string) *AttackPath {
	result := q.traverser.FindPath(fromID, toID, edgeTypes)
	if result == nil || len(result.Visited) == 0 {
		return nil
	}

	return &AttackPath{
		FromID:    fromID,
		ToID:      toID,
		Nodes:     result.Visited,
		Edges:     result.Edges,
		Depth:     result.Depth[toID],
		EdgeTypes: edgeTypes,
	}
}

// FindAllPaths finds all paths from source to any of the targets.
func (q *Query) FindAllPaths(sourceID string, targetIDs []string, edgeTypes []string, maxDepth int) []*AttackPath {
	if maxDepth <= 0 {
		maxDepth = 100
	}

	result := q.traverser.BFS(sourceID, query.Outgoing, maxDepth, edgeTypes)
	if result == nil {
		return nil
	}

	var paths []*AttackPath
	for _, targetID := range targetIDs {
		if depth, found := result.Depth[targetID]; found {
			path := q.reconstructPath(result, sourceID, targetID)
			path.Depth = depth
			paths = append(paths, path)
		}
	}

	return paths
}

// reconstructPath reconstructs the path from BFS result.
func (q *Query) reconstructPath(result *query.TraversalResult, fromID, toID string) *AttackPath {
	// Work backwards from target to source using Parents
	var nodes []string
	var edges []*graph.Edge

	current := toID
	for current != fromID && current != "" {
		nodes = append([]string{current}, nodes...)
		if edge, ok := result.Parents[current]; ok {
			edges = append([]*graph.Edge{edge}, edges...)
			current = edge.From
		} else {
			break
		}
	}
	nodes = append([]string{fromID}, nodes...)

	return &AttackPath{
		FromID: fromID,
		ToID:   toID,
		Nodes:  nodes,
		Edges:  edges,
	}
}

// CanReachFromEntryPoint checks if target is reachable from any entry point.
func (q *Query) CanReachFromEntryPoint(targetID string) (*AttackPath, bool) {
	entryPoints := q.FindEntryPoints()
	for _, ep := range entryPoints {
		if path := q.FindPath(ep.ID, targetID, []string{"calls"}); path != nil {
			return path, true
		}
	}
	return nil, false
}

// CanReachFromAPI checks if target is reachable from any API endpoint.
func (q *Query) CanReachFromAPI(targetID string) (*AttackPath, bool) {
	apis := q.FindAPIEndpoints()
	for _, api := range apis {
		if path := q.FindPath(api.ID, targetID, nil); path != nil {
			return path, true
		}
	}
	return nil, false
}

// GetDependencyDepth returns the depth of a package from the root.
// Returns -1 if not found.
func (q *Query) GetDependencyDepth(packageID string) int {
	// Find root packages (packages with no incoming depends_on edges)
	roots := q.findRootPackages()

	for _, root := range roots {
		result := q.traverser.BFS(root.ID, query.Outgoing, -1, []string{"depends_on", "imports"})
		if depth, found := result.Depth[packageID]; found {
			return depth
		}
	}

	return -1
}

// findRootPackages finds packages that are not dependencies of other packages.
func (q *Query) findRootPackages() []*graph.Node {
	// Build set of packages that are depended upon
	dependedUpon := make(map[string]bool)
	for _, edge := range q.graph.Edges {
		if edge.Type == "depends_on" || edge.Type == "imports" {
			dependedUpon[edge.To] = true
		}
	}

	// Find packages not in that set
	var roots []*graph.Node
	for _, node := range q.graph.Nodes {
		if (node.Type == "package" || node.Type == "module") && !dependedUpon[node.ID] {
			roots = append(roots, node)
		}
	}

	return roots
}

// AttackPath represents a path from entry point to vulnerable code.
type AttackPath struct {
	// FromID is the starting node.
	FromID string `json:"from_id"`

	// ToID is the ending node.
	ToID string `json:"to_id"`

	// Nodes are the node IDs in the path.
	Nodes []string `json:"nodes"`

	// Edges are the edges traversed.
	Edges []*graph.Edge `json:"edges"`

	// Depth is the number of hops.
	Depth int `json:"depth"`

	// EdgeTypes used in the query.
	EdgeTypes []string `json:"edge_types,omitempty"`
}

// String returns a human-readable representation.
func (p *AttackPath) String() string {
	if p == nil || len(p.Nodes) == 0 {
		return "(no path)"
	}
	return strings.Join(p.Nodes, " → ")
}
