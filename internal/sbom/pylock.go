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

// readPyproject parses the pyproject.toml next to a lock file (nil if
// missing or invalid).
func readPyproject(lockPath string) []PyRequirement {
	data, err := os.ReadFile(filepath.Join(filepath.Dir(lockPath), "pyproject.toml"))
	if err != nil {
		return nil
	}
	reqs, err := ParsePyproject(data)
	if err != nil {
		return nil
	}
	return reqs
}

// pyDeclared summarises declarations: direct = declared anywhere,
// dev = declared only outside production sections.
func pyDeclared(reqs []PyRequirement) declaredDeps {
	d := declaredDeps{direct: map[string]bool{}, dev: map[string]bool{}}
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

// pyProdRoots are the production declarations as graph roots (with extras).
func pyProdRoots(reqs []PyRequirement) []depEdge {
	var roots []depEdge
	for _, r := range reqs {
		if r.Production() {
			roots = append(roots, depEdge{to: r.Name, extras: extrasList(r.Extras)})
		}
	}
	return roots
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
		Groups   []string `toml:"groups"`   // poetry >= 2.0 (absent in 1.5–1.8)
		Source   struct {
			Type string `toml:"type"` // "directory", "file", "git", "url", "legacy"
		} `toml:"source"`
		// name → "constraint" or {version, optional, extras, markers}
		Dependencies map[string]any      `toml:"dependencies"`
		Extras       map[string][]string `toml:"extras"` // extra → ["PySocks (>=1.5.6)"]
	} `toml:"package"`
}

func (PoetryLockParser) Parse(absPath, relPath string) (ParseResult, error) {
	var lock poetryLock
	if _, err := toml.DecodeFile(absPath, &lock); err != nil {
		return ParseResult{}, fmt.Errorf("%s: %w", relPath, err)
	}
	reqs := readPyproject(absPath)
	decl := pyDeclared(reqs)

	// Poetry 1.5–1.8 record neither category nor groups: derive dev status
	// from the dependency graph (unreachable from production → dev).
	g := newDepGraph()
	for _, p := range lock.Package {
		name := NormalizePyPIName(p.Name)
		for dep, v := range p.Dependencies {
			e := depEdge{to: NormalizePyPIName(dep)}
			if t, ok := v.(map[string]any); ok {
				if opt, _ := t["optional"].(bool); opt {
					continue // only pulled in through an extra
				}
				if xs, ok := t["extras"].([]any); ok {
					for _, x := range xs {
						if s, ok := x.(string); ok {
							e.extras = append(e.extras, NormalizePyPIName(s))
						}
					}
				}
			}
			g.addEdge(name, e)
		}
		for extra, deps := range p.Extras {
			for _, d := range deps {
				if r, ok := ParsePEP508(d); ok {
					g.addExtra(name, NormalizePyPIName(extra), depEdge{to: r.Name})
				}
			}
		}
	}
	graphDev := g.devOnly(pyProdRoots(reqs))

	c := newCollector(EcosystemPyPI, relPath)
	for _, p := range lock.Package {
		if p.Source.Type == "directory" || p.Source.Type == "file" {
			continue // local path dependency, not a PyPI release
		}
		name := NormalizePyPIName(p.Name)
		var dev bool
		switch {
		case p.Category != "":
			dev = p.Category == "dev"
		case len(p.Groups) > 0:
			dev = !slices.Contains(p.Groups, "main")
		default:
			dev = graphDev(name) || decl.dev[name]
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
	Name  string   `toml:"name"`
	Extra []string `toml:"extra"` // extras enabled on this dependency
}

func (d uvDep) edge() depEdge {
	e := depEdge{to: NormalizePyPIName(d.Name)}
	for _, x := range d.Extra {
		e.extras = append(e.extras, NormalizePyPIName(x))
	}
	return e
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
	// Direct dependencies come from the project (workspace member) entries.
	// Dev status follows the dependency graph: anything not reachable from
	// the projects' production dependencies is dev-only. Optional
	// dependencies of a package count only where an edge enables the extra.
	g := newDepGraph()
	direct := map[string]bool{}
	var prodRoots []depEdge
	for _, p := range lock.Package {
		name := NormalizePyPIName(p.Name)
		for _, d := range p.Dependencies {
			g.addEdge(name, d.edge())
		}
		for extra, deps := range p.OptionalDependencies {
			for _, d := range deps {
				g.addExtra(name, NormalizePyPIName(extra), d.edge())
			}
		}
		if !uvProjectSource(p.Source) {
			continue
		}
		// The project's own dependencies and extras are production roots.
		for _, d := range p.Dependencies {
			prodRoots = append(prodRoots, d.edge())
			direct[d.edge().to] = true
		}
		for _, deps := range p.OptionalDependencies {
			for _, d := range deps {
				prodRoots = append(prodRoots, d.edge())
				direct[d.edge().to] = true
			}
		}
		for _, deps := range p.DevDependencies {
			for _, d := range deps {
				direct[d.edge().to] = true
			}
		}
	}
	devOnly := g.devOnly(prodRoots)

	c := newCollector(EcosystemPyPI, relPath)
	for _, p := range lock.Package {
		if uvLocalSource(p.Source) {
			continue
		}
		name := NormalizePyPIName(p.Name)
		c.add(name, p.Version, direct[name], devOnly(name))
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
	if len(readPyproject(absPath)) == 0 {
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
