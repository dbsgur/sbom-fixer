package sbom

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// PnpmLockParser reads pnpm-lock.yaml (lockfileVersion 5.x, 6.x and 9.x).
//
// Package keys differ per version:
//
//	5.x  /lodash/4.17.21   /@scope/pkg/1.0.0_peer@1.0.0
//	6.x  /lodash@4.17.21   /@scope/pkg@1.0.0(peer@1.0.0)
//	9.x   lodash@4.17.21    @scope/pkg@1.0.0
type PnpmLockParser struct{}

func (PnpmLockParser) Match(name string) bool { return name == "pnpm-lock.yaml" }
func (PnpmLockParser) Label() string          { return "pnpm 의존성 분석" }

// pnpmDeps is a dependency section; values are either a version string
// (5.x) or {specifier, version} (6.x+).
type pnpmDeps map[string]yaml.Node

type pnpmImporter struct {
	Dependencies         pnpmDeps `yaml:"dependencies"`
	DevDependencies      pnpmDeps `yaml:"devDependencies"`
	OptionalDependencies pnpmDeps `yaml:"optionalDependencies"`
}

type pnpmLock struct {
	pnpmImporter `yaml:",inline"`        // single-project 5.x/6.x layout
	Importers    map[string]pnpmImporter `yaml:"importers"`
	Packages     map[string]struct {
		Dev *bool `yaml:"dev"`
	} `yaml:"packages"`
}

func (PnpmLockParser) Parse(absPath, relPath string) (ParseResult, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ParseResult{}, err
	}
	var lock pnpmLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return ParseResult{}, fmt.Errorf("%s: %w", relPath, err)
	}

	// name@version pairs the project itself declares (all importers).
	direct, devOnly := map[string]bool{}, map[string]bool{}
	importers := []pnpmImporter{lock.pnpmImporter}
	for _, imp := range lock.Importers {
		importers = append(importers, imp)
	}
	for _, imp := range importers {
		for _, sec := range []struct {
			deps pnpmDeps
			dev  bool
		}{{imp.Dependencies, false}, {imp.OptionalDependencies, false}, {imp.DevDependencies, true}} {
			for name, node := range sec.deps {
				v := pnpmCleanVersion(pnpmNodeVersion(node))
				if v == "" {
					continue
				}
				k := name + "@" + v
				direct[k] = true
				if sec.dev {
					devOnly[k] = true
				} else {
					delete(devOnly, k)
				}
			}
		}
	}

	c := newCollector(EcosystemNpm, relPath)
	for key, p := range lock.Packages {
		name, version, ok := pnpmPackageKey(key)
		if !ok {
			continue
		}
		k := name + "@" + version
		dev := devOnly[k]
		if p.Dev != nil {
			dev = *p.Dev
		}
		c.add(name, version, direct[k], dev)
	}
	sortComponents(c.out) // map iteration order is random
	return ParseResult{Components: c.out}, nil
}

func pnpmNodeVersion(n yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	var v struct {
		Version string `yaml:"version"`
	}
	if n.Decode(&v) != nil {
		return ""
	}
	return v.Version
}

// pnpmCleanVersion strips peer-dependency suffixes and rejects non-registry
// versions (link:, file:, workspace:, git URLs...).
func pnpmCleanVersion(v string) string {
	if i := strings.IndexAny(v, "(_"); i > 0 {
		v = v[:i]
	}
	if v == "" || strings.Contains(v, ":") || strings.Contains(v, "/") {
		return ""
	}
	return v
}

// pnpmPackageKey splits a "packages" key into name and version.
func pnpmPackageKey(key string) (name, version string, ok bool) {
	k := strings.TrimPrefix(key, "/")
	if i := strings.IndexByte(k, '('); i > 0 { // 6.x peer suffix
		k = k[:i]
	}
	// Set the scope aside so its '@' and '/' don't confuse the split.
	scope, rest := "", k
	if strings.HasPrefix(k, "@") {
		i := strings.IndexByte(k, '/')
		if i < 0 {
			return "", "", false
		}
		scope, rest = k[:i+1], k[i+1:]
	}
	// 6.x/9.x put '@' before any '/'; 5.x is name/version where a peer
	// suffix may contain '@' later (pkg/1.0.0_react@18.2.0).
	at, slash := strings.IndexByte(rest, '@'), strings.IndexByte(rest, '/')
	switch {
	case at > 0 && (slash < 0 || at < slash):
		name, version = scope+rest[:at], pnpmCleanVersion(rest[at+1:])
	case slash > 0:
		name, version = scope+rest[:slash], pnpmCleanVersion(rest[slash+1:])
	}
	if name == "" || version == "" || strings.Contains(name, ":") {
		return "", "", false
	}
	return name, version, true
}
