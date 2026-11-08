package fixer

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"sbomapp/internal/sbom"
)

// Pure helpers that decide how to re-declare a Python dependency with
// `poetry add` / `uv add` without losing its section, extras or markers.

// pyDecl is where and how a dependency is declared in pyproject.toml.
type pyDecl struct {
	found bool
	// args selects the section for poetry/uv add: nil (main),
	// ["--group", "dev"] or ["--optional", "docs"] (uv only).
	args []string
	// spec is the version part of the old declaration ("==2.19.0", "^2.19", ">=1").
	spec   string
	extras string // "[socks]" or ""
	marker string // "; python_version > '3'" or ""
	// complex is set for poetry table declarations ({version=..., markers=...})
	// that `poetry add` would flatten.
	complex bool
}

var pep508 = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;]*?)\s*(;.*)?$`)

type pyprojectDecls struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// findPyDecl locates a dependency in pyproject.toml contents. Production
// sections are searched first so a package declared in both stays in main.
func findPyDecl(pyproject []byte, name string) (pyDecl, error) {
	var p pyprojectDecls
	if _, err := toml.Decode(string(pyproject), &p); err != nil {
		return pyDecl{}, fmt.Errorf("pyproject.toml 파싱 실패: %w", err)
	}
	want := sbom.NormalizePyPIName(name)

	fromPEP508 := func(reqs []string, args []string) (pyDecl, bool) {
		for _, r := range reqs {
			m := pep508.FindStringSubmatch(r)
			if m != nil && sbom.NormalizePyPIName(m[1]) == want {
				return pyDecl{found: true, args: args, extras: m[2], spec: strings.TrimSpace(m[3]), marker: strings.TrimSpace(m[4])}, true
			}
		}
		return pyDecl{}, false
	}
	fromPoetry := func(deps map[string]any, args []string) (pyDecl, bool) {
		for key, v := range deps {
			if sbom.NormalizePyPIName(key) != want {
				continue
			}
			if s, ok := v.(string); ok {
				return pyDecl{found: true, args: args, spec: s}, true
			}
			return pyDecl{found: true, args: args, complex: true}, true
		}
		return pyDecl{}, false
	}

	if d, ok := fromPEP508(p.Project.Dependencies, nil); ok {
		return d, nil
	}
	if d, ok := fromPoetry(p.Tool.Poetry.Dependencies, nil); ok {
		return d, nil
	}
	for _, extra := range sortedKeys(p.Project.OptionalDependencies) {
		if d, ok := fromPEP508(p.Project.OptionalDependencies[extra], []string{"--optional", extra}); ok {
			return d, nil
		}
	}
	for _, g := range sortedKeys(p.DependencyGroups) {
		var reqs []string
		for _, r := range p.DependencyGroups[g] {
			if s, ok := r.(string); ok {
				reqs = append(reqs, s)
			}
		}
		if d, ok := fromPEP508(reqs, []string{"--group", g}); ok {
			return d, nil
		}
	}
	groups := map[string]map[string]any{}
	for g, v := range p.Tool.Poetry.Group {
		groups[g] = v.Dependencies
	}
	for _, g := range sortedKeys(groups) {
		var args []string
		if g != "main" {
			args = []string{"--group", g}
		}
		if d, ok := fromPoetry(groups[g], args); ok {
			return d, nil
		}
	}
	if d, ok := fromPoetry(p.Tool.Poetry.DevDependencies, []string{"--group", "dev"}); ok {
		return d, nil
	}
	return pyDecl{}, nil
}

// newPySpec keeps the constraint style of the old spec while moving it to
// target: ==, ~=, ^ and ~ (poetry) are kept; anything else becomes >=.
func newPySpec(old, target string) string {
	s := strings.TrimSpace(old)
	for _, op := range []string{"===", "==", "~=", "^", "~"} {
		if strings.HasPrefix(s, op) {
			return op + target
		}
	}
	// A bare version in poetry ("2.19.0") is an exact pin.
	if s != "" && s[0] >= '0' && s[0] <= '9' && !strings.ContainsAny(s, ",<>*") {
		return "==" + target
	}
	return ">=" + target
}

// requirement renders "name[extras]<spec>; marker" for poetry/uv add.
func (d pyDecl) requirement(name, target string) string {
	r := name + d.extras + newPySpec(d.spec, target)
	if d.marker != "" {
		r += " " + d.marker
	}
	return r
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
