// Package sbom discovers dependency manifests in a repository and builds a
// software bill of materials (list of components) from them.
package sbom

import (
	"fmt"
	"strings"
)

// Ecosystem names follow the OSV naming so they can be passed straight to OSV.
const (
	EcosystemNpm  = "npm"
	EcosystemGo   = "Go"
	EcosystemPyPI = "PyPI"
)

// Component is a single package found in the repository.
type Component struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
	// Manifest is the lock/manifest file (relative to the scanned root) the
	// component was found in. Fixes are applied relative to this file.
	Manifest string `json:"manifest"`
	// Direct is true when the project declares the package itself (as opposed
	// to pulling it in transitively).
	Direct bool `json:"direct"`
	Dev    bool `json:"dev"`
}

// Key identifies a component uniquely inside one manifest.
func (c Component) Key() string {
	return c.Ecosystem + "|" + c.Manifest + "|" + c.Name + "@" + c.Version
}

func makePURL(ecosystem, name, version string) string {
	switch ecosystem {
	case EcosystemNpm:
		if strings.HasPrefix(name, "@") {
			if i := strings.Index(name, "/"); i > 0 {
				return fmt.Sprintf("pkg:npm/%s/%s@%s", "%40"+name[1:i], name[i+1:], version)
			}
		}
		return fmt.Sprintf("pkg:npm/%s@%s", name, version)
	case EcosystemGo:
		return fmt.Sprintf("pkg:golang/%s@%s", name, version)
	case EcosystemPyPI:
		return fmt.Sprintf("pkg:pypi/%s@%s", NormalizePyPIName(name), version)
	}
	return ""
}

// NormalizePyPIName applies PEP 503 normalisation.
func NormalizePyPIName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	r := strings.NewReplacer("_", "-", ".", "-")
	n = r.Replace(n)
	for strings.Contains(n, "--") {
		n = strings.ReplaceAll(n, "--", "-")
	}
	return n
}
