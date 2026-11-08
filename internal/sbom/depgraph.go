package sbom

import "strings"

// depGraph is a package dependency graph that knows about extras: the
// optional dependencies of a package are only followed when an edge into
// that package enables the extra (requests[socks] → pysocks).
type depGraph struct {
	edges  map[string][]depEdge            // package → its required dependencies
	extras map[string]map[string][]depEdge // package → extra → optional dependencies
}

type depEdge struct {
	to     string
	extras []string
}

func newDepGraph() *depGraph {
	return &depGraph{edges: map[string][]depEdge{}, extras: map[string]map[string][]depEdge{}}
}

func (g *depGraph) addEdge(from string, e depEdge) {
	g.edges[from] = append(g.edges[from], e)
}

func (g *depGraph) addExtra(pkg, extra string, e depEdge) {
	if g.extras[pkg] == nil {
		g.extras[pkg] = map[string][]depEdge{}
	}
	g.extras[pkg][extra] = append(g.extras[pkg][extra], e)
}

// reach returns every package reachable from roots, following extras only
// where an edge enables them.
func (g *depGraph) reach(roots []depEdge) map[string]bool {
	seen := map[string]bool{}
	seenExtra := map[string]bool{}
	stack := append([]depEdge{}, roots...)
	for len(stack) > 0 {
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !seen[e.to] {
			seen[e.to] = true
			stack = append(stack, g.edges[e.to]...)
		}
		for _, x := range e.extras {
			if k := e.to + "[" + x + "]"; !seenExtra[k] {
				seenExtra[k] = true
				stack = append(stack, g.extras[e.to][x]...)
			}
		}
	}
	return seen
}

// devOnly marks packages not reachable from production roots as dev.
// Without production roots nothing can be concluded (all false).
func (g *depGraph) devOnly(prodRoots []depEdge) func(string) bool {
	if len(prodRoots) == 0 {
		return func(string) bool { return false }
	}
	prod := g.reach(prodRoots)
	return func(name string) bool { return !prod[name] }
}

// extrasList turns "[a, b]" (PEP 508 extras) into ["a", "b"].
func extrasList(s string) []string {
	var out []string
	for _, x := range strings.Split(strings.Trim(s, "[]"), ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, NormalizePyPIName(x))
		}
	}
	return out
}
