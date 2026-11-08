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

// JSLockFiles are the lock files of the supported JavaScript package managers.
var JSLockFiles = []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}

func (NpmManifestCheck) Parse(absPath, relPath string) (ParseResult, error) {
	dir := filepath.Dir(absPath)
	for _, lock := range JSLockFiles {
		if _, err := os.Stat(filepath.Join(dir, lock)); err == nil {
			return ParseResult{}, nil
		}
	}
	return ParseResult{Warnings: []string{
		relPath + ": lock 파일(package-lock.json, yarn.lock, pnpm-lock.yaml)이 없어 의존성 버전을 알 수 없습니다. 패키지 매니저로 install 후 다시 분석하세요",
	}}, nil
}

type npmDeclared struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// declaredDeps is what a package.json says about its own dependencies.
type declaredDeps struct {
	direct map[string]bool // declared in any dependency section
	dev    map[string]bool // declared only in devDependencies
}

// readNpmDeclared reads the package.json next to a lock file.
func readNpmDeclared(lockPath string) declaredDeps {
	d := declaredDeps{direct: map[string]bool{}, dev: map[string]bool{}}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(lockPath), "package.json"))
	if err != nil {
		return d
	}
	var p npmDeclared
	if json.Unmarshal(data, &p) != nil {
		return d
	}
	d.direct = p.names()
	for name := range p.DevDependencies {
		if _, prod := p.Dependencies[name]; !prod {
			d.dev[name] = true
		}
	}
	return d
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

	direct := readNpmDeclared(absPath).direct

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
