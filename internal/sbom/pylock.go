package sbom

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"
)

// PythonLockFiles are the Python lock files with full dependency trees.
var PythonLockFiles = []string{"poetry.lock", "uv.lock"}

// readPyDeclared reads the pyproject.toml next to a lock file and returns the
// declared dependencies (direct) and those declared only for development.
func readPyDeclared(lockPath string) declaredDeps {
	d := declaredDeps{direct: map[string]bool{}, dev: map[string]bool{}}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(lockPath), "pyproject.toml"))
	if err != nil {
		return d
	}
	reqs, err := ParsePyproject(data)
	if err != nil {
		return d
	}
	prod := map[string]bool{}
	for _, r := range reqs {
		d.direct[r.Name] = true
		if r.Production() {
			prod[r.Name] = true
		}
	}
	for _, r := range reqs {
		if !prod[r.Name] {
			d.dev[r.Name] = true
		}
	}
	return d
}

// ---------- poetry.lock ----------

// PoetryLockParser reads poetry.lock (Poetry 1.x and 2.x).
type PoetryLockParser struct{}

func (PoetryLockParser) Match(name string) bool { return name == "poetry.lock" }
func (PoetryLockParser) Label() string          { return "Poetry 의존성 분석" }

type poetryLock struct {
	Package []struct {
		Name     string   `toml:"name"`
		Version  string   `toml:"version"`
		Category string   `toml:"category"` // poetry <= 1.4: "main" | "dev"
		Groups   []string `toml:"groups"`   // poetry >= 2.0
		Source   struct {
			Type string `toml:"type"` // "directory", "file", "git", "url", "legacy"
		} `toml:"source"`
	} `toml:"package"`
}

func (PoetryLockParser) Parse(absPath, relPath string) (ParseResult, error) {
	var lock poetryLock
	if _, err := toml.DecodeFile(absPath, &lock); err != nil {
		return ParseResult{}, fmt.Errorf("%s: %w", relPath, err)
	}
	decl := readPyDeclared(absPath)
	c := newCollector(EcosystemPyPI, relPath)
	for _, p := range lock.Package {
		if p.Source.Type == "directory" || p.Source.Type == "file" {
			continue // local path dependency, not a PyPI release
		}
		name := NormalizePyPIName(p.Name)
		dev := decl.dev[name]
		if p.Category != "" {
			dev = p.Category == "dev"
		} else if len(p.Groups) > 0 {
			dev = !slices.Contains(p.Groups, "main")
		}
		c.add(name, p.Version, decl.direct[name], dev)
	}
	return ParseResult{Components: c.out}, nil
}

// ---------- uv.lock ----------

// UvLockParser reads uv.lock. The project itself (and workspace members)
// appear as packages with a virtual/editable source; their dependency lists
// are the direct dependencies.
type UvLockParser struct{}

func (UvLockParser) Match(name string) bool { return name == "uv.lock" }
func (UvLockParser) Label() string          { return "uv 의존성 분석" }

type uvDep struct {
	Name string `toml:"name"`
}

type uvLock struct {
	Package []struct {
		Name                 string             `toml:"name"`
		Version              string             `toml:"version"`
		Source               map[string]any     `toml:"source"`
		Dependencies         []uvDep            `toml:"dependencies"`
		OptionalDependencies map[string][]uvDep `toml:"optional-dependencies"`
		DevDependencies      map[string][]uvDep `toml:"dev-dependencies"`
	} `toml:"package"`
}

// uvProjectSource reports the project itself or a workspace member.
func uvProjectSource(src map[string]any) bool {
	_, virtual := src["virtual"]
	_, editable := src["editable"]
	return virtual || editable
}

// uvLocalSource reports packages that are not registry releases.
func uvLocalSource(src map[string]any) bool {
	for _, k := range []string{"virtual", "editable", "directory", "path"} {
		if _, ok := src[k]; ok {
			return true
		}
	}
	return false
}

func (UvLockParser) Parse(absPath, relPath string) (ParseResult, error) {
	var lock uvLock
	if _, err := toml.DecodeFile(absPath, &lock); err != nil {
		return ParseResult{}, fmt.Errorf("%s: %w", relPath, err)
	}
	// Direct dependencies come from the project (workspace member) entries;
	// dev-only status follows the dependency graph: a package is dev when it
	// is reachable from dev dependencies but not from production ones.
	graph := map[string][]string{}
	var prodRoots, devRoots []string
	for _, p := range lock.Package {
		name := NormalizePyPIName(p.Name)
		for _, d := range p.Dependencies {
			graph[name] = append(graph[name], NormalizePyPIName(d.Name))
		}
		for _, deps := range p.OptionalDependencies {
			for _, d := range deps {
				graph[name] = append(graph[name], NormalizePyPIName(d.Name))
			}
		}
		if !uvProjectSource(p.Source) {
			continue
		}
		for _, d := range p.Dependencies {
			prodRoots = append(prodRoots, NormalizePyPIName(d.Name))
		}
		for _, deps := range p.OptionalDependencies {
			for _, d := range deps {
				prodRoots = append(prodRoots, NormalizePyPIName(d.Name))
			}
		}
		for _, deps := range p.DevDependencies {
			for _, d := range deps {
				devRoots = append(devRoots, NormalizePyPIName(d.Name))
			}
		}
	}
	direct := map[string]bool{}
	for _, n := range append(append([]string{}, prodRoots...), devRoots...) {
		direct[n] = true
	}
	prodReach, devReach := reachable(graph, prodRoots), reachable(graph, devRoots)

	c := newCollector(EcosystemPyPI, relPath)
	for _, p := range lock.Package {
		if uvLocalSource(p.Source) {
			continue
		}
		name := NormalizePyPIName(p.Name)
		c.add(name, p.Version, direct[name], devReach[name] && !prodReach[name])
	}
	return ParseResult{Components: c.out}, nil
}

// ---------- pyproject.toml without a lock ----------

// PyprojectCheck warns about pyproject.toml files that declare dependencies
// but have no lock file (versions unknown).
type PyprojectCheck struct{}

func (PyprojectCheck) Match(name string) bool { return name == "pyproject.toml" }
func (PyprojectCheck) Label() string          { return "" }

func (PyprojectCheck) Parse(absPath, relPath string) (ParseResult, error) {
	dir := filepath.Dir(absPath)
	for _, lock := range PythonLockFiles {
		if _, err := os.Stat(filepath.Join(dir, lock)); err == nil {
			return ParseResult{}, nil
		}
	}
	if len(readPyDeclared(absPath).direct) == 0 {
		return ParseResult{}, nil // tool config only (black, ruff, ...)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "requirements*.txt"))
	if len(matches) > 0 {
		return ParseResult{}, nil // pinned versions come from requirements files
	}
	return ParseResult{Warnings: []string{
		relPath + ": lock 파일(poetry.lock, uv.lock)이 없어 Python 의존성 버전을 알 수 없습니다. poetry lock 또는 uv lock 후 다시 분석하세요",
	}}, nil
}

// reachable returns every node reachable from roots (roots included).
func reachable(graph map[string][]string, roots []string) map[string]bool {
	seen := map[string]bool{}
	stack := append([]string{}, roots...)
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[n] {
			continue
		}
		seen[n] = true
		stack = append(stack, graph[n]...)
	}
	return seen
}
