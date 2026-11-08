package sbom

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// PySectionKind tells where in pyproject.toml a dependency is declared.
type PySectionKind string

const (
	PyProject         PySectionKind = "project"           // [project] dependencies
	PyOptional        PySectionKind = "optional"          // [project.optional-dependencies].<name>
	PyGroup           PySectionKind = "group"             // [dependency-groups].<name> (PEP 735)
	PyPoetry          PySectionKind = "poetry"            // [tool.poetry.dependencies]
	PyPoetryGroup     PySectionKind = "poetry-group"      // [tool.poetry.group.<name>.dependencies]
	PyPoetryLegacyDev PySectionKind = "poetry-legacy-dev" // [tool.poetry.dev-dependencies] (Poetry < 1.2)
	PyUvLegacyDev     PySectionKind = "uv-legacy-dev"     // [tool.uv] dev-dependencies
)

// PyRequirement is one dependency declaration in pyproject.toml.
type PyRequirement struct {
	Name    string // PEP 503 normalised
	Kind    PySectionKind
	Section string // extra or group name, when the kind has one
	// Spec is the version part ("==2.19.0", ">=2,<3", "^2.10"); for Poetry
	// string values it is the value itself.
	Spec   string
	Extras string // "[socks]"
	Marker string // "; python_version > '3'"
	URL    bool   // "pkg @ https://..." direct reference
	Table  bool   // Poetry table form ({version = ..., markers = ...})
}

// Production reports whether the requirement is a runtime dependency.
func (r PyRequirement) Production() bool {
	switch r.Kind {
	case PyProject, PyOptional, PyPoetry:
		return true
	case PyPoetryGroup:
		return r.Section == "main"
	}
	return false
}

type pyprojectFile struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]any `toml:"dependency-groups"` // entries may be {include-group = ...}
	Tool             struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
		Uv struct {
			DevDependencies []string `toml:"dev-dependencies"`
		} `toml:"uv"`
	} `toml:"tool"`
}

var pep508Re = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(@\s*[^;]*|[^;]*?)\s*(;.*)?$`)

// ParsePEP508 splits "name[extras] spec ; marker". ok=false if unparsable.
func ParsePEP508(s string) (PyRequirement, bool) {
	m := pep508Re.FindStringSubmatch(s)
	if m == nil {
		return PyRequirement{}, false
	}
	spec := strings.TrimSpace(m[3])
	return PyRequirement{
		Name:   NormalizePyPIName(m[1]),
		Extras: m[2],
		Spec:   spec,
		Marker: strings.TrimSpace(m[4]),
		URL:    strings.HasPrefix(spec, "@"),
	}, true
}

// ParsePyproject lists every dependency declared in pyproject.toml.
// Production sections come first, then the rest; within a section entries
// are sorted, so callers looking for the first match get a stable result.
func ParsePyproject(data []byte) ([]PyRequirement, error) {
	var p pyprojectFile
	if _, err := toml.Decode(string(data), &p); err != nil {
		return nil, err
	}
	var out []PyRequirement
	addPEP508 := func(reqs []string, kind PySectionKind, section string) {
		for _, s := range reqs {
			if r, ok := ParsePEP508(s); ok {
				r.Kind, r.Section = kind, section
				out = append(out, r)
			}
		}
	}
	addPoetry := func(deps map[string]any, kind PySectionKind, section string) {
		for _, name := range slices.Sorted(maps.Keys(deps)) {
			if strings.EqualFold(name, "python") {
				continue
			}
			r := PyRequirement{Name: NormalizePyPIName(name), Kind: kind, Section: section}
			if s, ok := deps[name].(string); ok {
				r.Spec = s
			} else {
				r.Table = true
			}
			out = append(out, r)
		}
	}

	addPEP508(p.Project.Dependencies, PyProject, "")
	addPoetry(p.Tool.Poetry.Dependencies, PyPoetry, "")
	for _, extra := range slices.Sorted(maps.Keys(p.Project.OptionalDependencies)) {
		addPEP508(p.Project.OptionalDependencies[extra], PyOptional, extra)
	}
	for _, g := range slices.Sorted(maps.Keys(p.Tool.Poetry.Group)) {
		addPoetry(p.Tool.Poetry.Group[g].Dependencies, PyPoetryGroup, g)
	}
	for _, g := range slices.Sorted(maps.Keys(p.DependencyGroups)) {
		var reqs []string
		for _, e := range p.DependencyGroups[g] {
			if s, ok := e.(string); ok {
				reqs = append(reqs, s)
			}
		}
		addPEP508(reqs, PyGroup, g)
	}
	addPoetry(p.Tool.Poetry.DevDependencies, PyPoetryLegacyDev, "dev")
	addPEP508(p.Tool.Uv.DevDependencies, PyUvLegacyDev, "dev")

	// Production entries first (stable).
	slices.SortStableFunc(out, func(a, b PyRequirement) int {
		switch {
		case a.Production() == b.Production():
			return 0
		case a.Production():
			return -1
		}
		return 1
	})
	return out, nil
}
