package sbom

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// Pipenv: Pipfile (TOML, declarations) + Pipfile.lock (JSON, resolved pins).
//
// Pipfile sections are package categories: [packages] (runtime),
// [dev-packages] and, since pipenv 2023, any custom category ([docs]).
// Pipfile.lock stores each category under its own key; the two built-in
// ones are renamed: packages → "default", dev-packages → "develop".

// pipfileReserved are Pipfile tables that are not package categories.
var pipfileReserved = map[string]bool{"source": true, "requires": true, "pipenv": true, "scripts": true}

// PipenvLockCategory maps a Pipfile section to its Pipfile.lock key.
func PipenvLockCategory(section string) string {
	switch section {
	case "packages":
		return "default"
	case "dev-packages":
		return "develop"
	}
	return section
}

// ParsePipfile lists every dependency declared in a Pipfile. [packages]
// comes first, then the other categories in name order; within a section
// entries are sorted by name.
func ParsePipfile(data []byte) ([]PyRequirement, error) {
	var p map[string]any
	if _, err := toml.Decode(string(data), &p); err != nil {
		return nil, err
	}
	var out []PyRequirement
	for _, section := range sortedFirst(p, "packages") {
		deps, ok := p[section].(map[string]any)
		if !ok || pipfileReserved[section] {
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(deps)) {
			r := PyRequirement{Name: NormalizePyPIName(name), Kind: PyPipfile, Section: section}
			switch v := deps[name].(type) {
			case string:
				r.Spec = v
			case map[string]any:
				r.Table = true
				r.Spec, _ = v["version"].(string)
				for _, k := range []string{"git", "path", "file"} {
					if _, ok := v[k]; ok {
						r.URL = true
					}
				}
				if xs, ok := v["extras"].([]any); ok && len(xs) > 0 {
					var names []string
					for _, x := range xs {
						if s, ok := x.(string); ok {
							names = append(names, s)
						}
					}
					r.Extras = "[" + strings.Join(names, ",") + "]"
				}
				if m, ok := v["markers"].(string); ok && m != "" {
					r.Marker = "; " + m
				}
			default:
				continue
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// sortedFirst returns the keys of m in name order, with first (if present)
// moved to the front.
func sortedFirst[V any](m map[string]V, first string) []string {
	keys := slices.Sorted(maps.Keys(m))
	if i := slices.Index(keys, first); i > 0 {
		keys = append([]string{first}, slices.Delete(keys, i, i+1)...)
	}
	return keys
}

// readPipfile parses the Pipfile next to a lock file (nil if missing or invalid).
func readPipfile(lockPath string) []PyRequirement {
	data, err := os.ReadFile(filepath.Join(filepath.Dir(lockPath), "Pipfile"))
	if err != nil {
		return nil
	}
	reqs, err := ParsePipfile(data)
	if err != nil {
		return nil
	}
	return reqs
}

// ---------- Pipfile.lock ----------

// PipfileLockParser reads pipenv's Pipfile.lock. Direct dependencies come
// from the Pipfile next to it; everything outside the "default" category
// is dev-only (pipenv resolves each category separately and repeats shared
// packages in every category that needs them).
type PipfileLockParser struct{}

func (PipfileLockParser) Match(name string) bool { return name == "Pipfile.lock" }
func (PipfileLockParser) Label() string          { return "pipenv 의존성 분석" }

type pipfileLockEntry struct {
	Version string `json:"version"` // "==2.19.0"
	Git     string `json:"git"`
	Path    string `json:"path"`
	File    string `json:"file"`
}

// pinnedVersion returns the version of an exact "==X" / "===X" pin.
func (e pipfileLockEntry) pinnedVersion() string {
	if e.Git != "" || e.Path != "" || e.File != "" {
		return "" // VCS or local dependency, not a PyPI release
	}
	v := strings.TrimSpace(e.Version)
	if !strings.HasPrefix(v, "==") {
		return ""
	}
	return strings.TrimSpace(strings.TrimLeft(v, "="))
}

// parsePipfileLock decodes Pipfile.lock into category → name → entry.
func parsePipfileLock(data []byte) (map[string]map[string]pipfileLockEntry, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if _, ok := raw["_meta"]; !ok {
		return nil, fmt.Errorf("_meta가 없어 Pipfile.lock 형식이 아닙니다")
	}
	out := map[string]map[string]pipfileLockEntry{}
	for cat, msg := range raw {
		if cat == "_meta" {
			continue
		}
		var entries map[string]pipfileLockEntry
		if err := json.Unmarshal(msg, &entries); err != nil {
			return nil, fmt.Errorf("%s: %w", cat, err)
		}
		out[cat] = entries
	}
	return out, nil
}

func (PipfileLockParser) Parse(absPath, relPath string) (ParseResult, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ParseResult{}, err
	}
	lock, err := parsePipfileLock(data)
	if err != nil {
		return ParseResult{}, fmt.Errorf("%s: %w", relPath, err)
	}
	decl := pyDeclared(readPipfile(absPath))

	// "default" first so a package shared with develop stays production.
	c := newCollector(EcosystemPyPI, relPath)
	for _, cat := range sortedFirst(lock, "default") {
		for _, name := range slices.Sorted(maps.Keys(lock[cat])) {
			n := NormalizePyPIName(name)
			c.add(n, lock[cat][name].pinnedVersion(), decl.direct[n], cat != "default")
		}
	}
	return ParseResult{Components: c.out}, nil
}

// ---------- Pipfile without a lock ----------

// PipfileCheck warns about a Pipfile that declares packages but has no
// Pipfile.lock (versions unknown).
type PipfileCheck struct{}

func (PipfileCheck) Match(name string) bool { return name == "Pipfile" }
func (PipfileCheck) Label() string          { return "" }

func (PipfileCheck) Parse(absPath, relPath string) (ParseResult, error) {
	dir := filepath.Dir(absPath)
	if _, err := os.Stat(filepath.Join(dir, "Pipfile.lock")); err == nil {
		return ParseResult{}, nil
	}
	if len(readPipfile(filepath.Join(dir, "Pipfile.lock"))) == 0 {
		return ParseResult{}, nil
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "requirements*.txt")); len(matches) > 0 {
		return ParseResult{}, nil // pinned versions come from requirements files
	}
	return ParseResult{Warnings: []string{
		relPath + ": lock 파일(Pipfile.lock)이 없어 Python 의존성 버전을 알 수 없습니다. pipenv lock 후 다시 분석하세요",
	}}, nil
}
