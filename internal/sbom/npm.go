package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type npmPackageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

func (p npmPackageJSON) directNames() map[string]bool {
	out := map[string]bool{}
	for _, m := range []map[string]string{p.Dependencies, p.DevDependencies, p.OptionalDependencies, p.PeerDependencies} {
		for k := range m {
			out[k] = true
		}
	}
	return out
}

type npmLockPackage struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
	Link    bool   `json:"link"`
	// Root entry ("") carries the project's own dependency declarations.
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type npmLockV1Dep struct {
	Version      string                  `json:"version"`
	Dev          bool                    `json:"dev"`
	Dependencies map[string]npmLockV1Dep `json:"dependencies"`
}

type npmLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage `json:"packages"`
	Dependencies    map[string]npmLockV1Dep   `json:"dependencies"`
}

// parseNpmLock reads a package-lock.json (v1, v2 or v3).
func parseNpmLock(absPath, relPath string) ([]Component, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("%s: %w", relPath, err)
	}

	direct := map[string]bool{}
	if pj, err := os.ReadFile(filepath.Join(filepath.Dir(absPath), "package.json")); err == nil {
		var p npmPackageJSON
		if json.Unmarshal(pj, &p) == nil {
			direct = p.directNames()
		}
	}

	seen := map[string]bool{}
	var out []Component
	add := func(name, version string, dev, isDirect bool) {
		if name == "" || version == "" {
			return
		}
		k := name + "@" + version
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, Component{
			Name:      name,
			Version:   version,
			Ecosystem: EcosystemNpm,
			PURL:      makePURL(EcosystemNpm, name, version),
			Manifest:  relPath,
			Direct:    isDirect,
			Dev:       dev,
		})
	}

	if len(lock.Packages) > 0 {
		if root, ok := lock.Packages[""]; ok && len(direct) == 0 {
			direct = npmPackageJSON{root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies}.directNames()
		}
		for key, p := range lock.Packages {
			if key == "" || p.Link {
				continue
			}
			idx := strings.LastIndex(key, "node_modules/")
			if idx < 0 {
				continue // workspace package itself
			}
			name := key[idx+len("node_modules/"):]
			isDirect := key == "node_modules/"+name && direct[name]
			add(name, p.Version, p.Dev, isDirect)
		}
		return out, nil
	}

	// lockfileVersion 1
	var walk func(deps map[string]npmLockV1Dep, top bool)
	walk = func(deps map[string]npmLockV1Dep, top bool) {
		for name, d := range deps {
			add(name, d.Version, d.Dev, top && direct[name])
			walk(d.Dependencies, false)
		}
	}
	walk(lock.Dependencies, true)
	return out, nil
}
