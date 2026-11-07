package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// NpmLockParser reads package-lock.json (lockfileVersion 1, 2 and 3).
type NpmLockParser struct{}

func (NpmLockParser) Match(name string) bool { return name == "package-lock.json" }
func (NpmLockParser) Label() string          { return "npm 의존성 분석" }

// NpmManifestCheck warns about package.json files without a lock file,
// because exact versions cannot be known without one.
type NpmManifestCheck struct{}

func (NpmManifestCheck) Match(name string) bool { return name == "package.json" }
func (NpmManifestCheck) Label() string          { return "" }

func (NpmManifestCheck) Parse(absPath, relPath string) (ParseResult, error) {
	if _, err := os.Stat(filepath.Join(filepath.Dir(absPath), "package-lock.json")); err == nil {
		return ParseResult{}, nil
	}
	return ParseResult{Warnings: []string{
		relPath + ": package-lock.json이 없어 npm 의존성을 분석하지 못했습니다 (npm install 후 다시 스캔하세요. yarn/pnpm은 아직 지원하지 않습니다)",
	}}, nil
}

type npmDeclared struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

func (p npmDeclared) names() map[string]bool {
	out := map[string]bool{}
	for _, m := range []map[string]string{p.Dependencies, p.DevDependencies, p.OptionalDependencies, p.PeerDependencies} {
		for k := range m {
			out[k] = true
		}
	}
	return out
}

type npmLockPackage struct {
	npmDeclared
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
	Link    bool   `json:"link"`
}

type npmLockV1Dep struct {
	Version      string                  `json:"version"`
	Dev          bool                    `json:"dev"`
	Dependencies map[string]npmLockV1Dep `json:"dependencies"`
}

type npmLock struct {
	Packages     map[string]npmLockPackage `json:"packages"`
	Dependencies map[string]npmLockV1Dep   `json:"dependencies"`
}

func (NpmLockParser) Parse(absPath, relPath string) (ParseResult, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ParseResult{}, err
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return ParseResult{}, fmt.Errorf("%s: %w", relPath, err)
	}

	direct := map[string]bool{}
	if pj, err := os.ReadFile(filepath.Join(filepath.Dir(absPath), "package.json")); err == nil {
		var p npmDeclared
		if json.Unmarshal(pj, &p) == nil {
			direct = p.names()
		}
	}

	c := newCollector(EcosystemNpm, relPath)
	if len(lock.Packages) > 0 {
		if root, ok := lock.Packages[""]; ok && len(direct) == 0 {
			direct = root.names()
		}
		for key, p := range lock.Packages {
			if key == "" || p.Link {
				continue
			}
			name, ok := npmNameFromPath(key)
			if !ok {
				continue // workspace package itself
			}
			c.add(name, p.Version, key == "node_modules/"+name && direct[name], p.Dev)
		}
		return ParseResult{Components: c.out}, nil
	}

	var walk func(deps map[string]npmLockV1Dep, top bool)
	walk = func(deps map[string]npmLockV1Dep, top bool) {
		for name, d := range deps {
			c.add(name, d.Version, top && direct[name], d.Dev)
			walk(d.Dependencies, false)
		}
	}
	walk(lock.Dependencies, true)
	return ParseResult{Components: c.out}, nil
}

// npmNameFromPath extracts "pkg" from "node_modules/a/node_modules/pkg".
func npmNameFromPath(key string) (string, bool) {
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		return "", false
	}
	return key[idx+len("node_modules/"):], true
}
