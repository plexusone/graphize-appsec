package graph

import (
	"strings"

	"github.com/plexusone/graphfs/pkg/graph"
)

// NodeFilter is a predicate for filtering nodes.
type NodeFilter func(*graph.Node) bool

// EdgeFilter is a predicate for filtering edges.
type EdgeFilter func(*graph.Edge) bool

// And combines filters with AND logic.
func And(filters ...NodeFilter) NodeFilter {
	return func(n *graph.Node) bool {
		for _, f := range filters {
			if !f(n) {
				return false
			}
		}
		return true
	}
}

// Or combines filters with OR logic.
func Or(filters ...NodeFilter) NodeFilter {
	return func(n *graph.Node) bool {
		for _, f := range filters {
			if f(n) {
				return true
			}
		}
		return false
	}
}

// Not negates a filter.
func Not(filter NodeFilter) NodeFilter {
	return func(n *graph.Node) bool {
		return !filter(n)
	}
}

// ByType returns a filter for nodes of a specific type.
func ByType(nodeType string) NodeFilter {
	return func(n *graph.Node) bool {
		return n.Type == nodeType
	}
}

// ByTypes returns a filter for nodes of any of the specified types.
func ByTypes(types ...string) NodeFilter {
	typeSet := make(map[string]bool)
	for _, t := range types {
		typeSet[t] = true
	}
	return func(n *graph.Node) bool {
		return typeSet[n.Type]
	}
}

// ByAttr returns a filter for nodes with a specific attribute value.
func ByAttr(key, value string) NodeFilter {
	return func(n *graph.Node) bool {
		return n.Attrs[key] == value
	}
}

// HasAttr returns a filter for nodes that have a specific attribute.
func HasAttr(key string) NodeFilter {
	return func(n *graph.Node) bool {
		_, ok := n.Attrs[key]
		return ok
	}
}

// AttrContains returns a filter for nodes where an attribute contains a substring.
func AttrContains(key, substring string) NodeFilter {
	return func(n *graph.Node) bool {
		return strings.Contains(n.Attrs[key], substring)
	}
}

// LabelContains returns a filter for nodes whose label contains a substring.
func LabelContains(substring string) NodeFilter {
	return func(n *graph.Node) bool {
		return strings.Contains(strings.ToLower(n.Label), strings.ToLower(substring))
	}
}

// IDContains returns a filter for nodes whose ID contains a substring.
func IDContains(substring string) NodeFilter {
	return func(n *graph.Node) bool {
		return strings.Contains(strings.ToLower(n.ID), strings.ToLower(substring))
	}
}

// IsEntryPoint returns a filter for entry point nodes.
func IsEntryPoint() NodeFilter {
	return Or(
		ByAttr("is_entrypoint", "true"),
		ByAttr("is_handler", "true"),
		And(ByType("function"), ByAttr("name", "main")),
		ByAttr("framework_layer", "controller"),
	)
}

// IsAPIEndpoint returns a filter for API endpoint nodes.
func IsAPIEndpoint() NodeFilter {
	return Or(
		ByType("api_endpoint"),
		ByAttr("is_handler", "true"),
		HasAttr("http_method"),
		ByAttr("framework_layer", "controller"),
	)
}

// IsPackage returns a filter for package nodes.
func IsPackage() NodeFilter {
	return ByTypes("package", "module")
}

// IsFunction returns a filter for function nodes.
func IsFunction() NodeFilter {
	return ByTypes("function", "method")
}

// IsAuthRelated returns a filter for authentication-related nodes.
func IsAuthRelated() NodeFilter {
	authTerms := []string{"auth", "login", "session", "oauth", "jwt", "token", "credential", "password"}
	return func(n *graph.Node) bool {
		label := strings.ToLower(n.Label)
		id := strings.ToLower(n.ID)
		for _, term := range authTerms {
			if strings.Contains(label, term) || strings.Contains(id, term) {
				return true
			}
		}
		return false
	}
}

// RequiresAuth returns a filter for nodes that require authentication.
func RequiresAuth() NodeFilter {
	return ByAttr("requires_auth", "true")
}

// IsPublic returns a filter for public nodes.
func IsPublic() NodeFilter {
	return ByAttr("visibility", "public")
}

// EdgeByType returns a filter for edges of a specific type.
func EdgeByType(edgeType string) EdgeFilter {
	return func(e *graph.Edge) bool {
		return e.Type == edgeType
	}
}

// EdgeByTypes returns a filter for edges of any of the specified types.
func EdgeByTypes(types ...string) EdgeFilter {
	typeSet := make(map[string]bool)
	for _, t := range types {
		typeSet[t] = true
	}
	return func(e *graph.Edge) bool {
		return typeSet[e.Type]
	}
}

// EdgeFrom returns a filter for edges from a specific node.
func EdgeFrom(nodeID string) EdgeFilter {
	return func(e *graph.Edge) bool {
		return e.From == nodeID
	}
}

// EdgeTo returns a filter for edges to a specific node.
func EdgeTo(nodeID string) EdgeFilter {
	return func(e *graph.Edge) bool {
		return e.To == nodeID
	}
}

// FilterNodes filters a slice of nodes.
func FilterNodes(nodes []*graph.Node, filter NodeFilter) []*graph.Node {
	var result []*graph.Node
	for _, n := range nodes {
		if filter(n) {
			result = append(result, n)
		}
	}
	return result
}

// FilterEdges filters a slice of edges.
func FilterEdges(edges []*graph.Edge, filter EdgeFilter) []*graph.Edge {
	var result []*graph.Edge
	for _, e := range edges {
		if filter(e) {
			result = append(result, e)
		}
	}
	return result
}
