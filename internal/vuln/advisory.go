package vuln

import (
	"strings"

	"sbomapp/internal/sbom"
)

// queryVersion converts a component version to the form OSV expects
// (Go module versions are stored without the leading "v").
func queryVersion(c sbom.Component) string {
	if c.Ecosystem == sbom.EcosystemGo {
		return strings.TrimPrefix(c.Version, "v")
	}
	return c.Version
}

// summary returns a one-line description of the advisory.
func (a *Advisory) summary() string {
	if a.Summary != "" {
		return a.Summary
	}
	d := strings.TrimSpace(a.Details)
	if i := strings.IndexByte(d, '\n'); i > 0 {
		d = d[:i]
	}
	if r := []rune(d); len(r) > 200 {
		d = string(r[:200]) + "…"
	}
	return d
}

func normSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "MODERATE":
		return SeverityMedium
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return s
	}
	return ""
}

// severity picks the best available severity: the database's own rating
// (e.g. GitHub's), then per-package ratings, then a computed CVSS v3 score.
func (a *Advisory) severity() string {
	if s, ok := a.DatabaseSpecific["severity"].(string); ok {
		if n := normSeverity(s); n != "" {
			return n
		}
	}
	for _, af := range a.Affected {
		for _, m := range []map[string]any{af.EcosystemSpecific, af.DatabaseSpecific} {
			if s, ok := m["severity"].(string); ok {
				if n := normSeverity(s); n != "" {
					return n
				}
			}
		}
	}
	for _, s := range a.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V3") {
			if score, ok := cvss3BaseScore(s.Score); ok {
				return severityFromScore(score)
			}
		}
	}
	return SeverityUnknown
}

func samePackage(ecosystem, a, b string) bool {
	if ecosystem == sbom.EcosystemPyPI {
		return sbom.NormalizePyPIName(a) == sbom.NormalizePyPIName(b)
	}
	return a == b
}

// fixedVersionFor returns the smallest "fixed" event greater than the
// component's current version, formatted for the component's ecosystem
// ("" when no fix is published).
func (a *Advisory) fixedVersionFor(c sbom.Component) string {
	cur := queryVersion(c)
	best := ""
	for _, af := range a.Affected {
		if af.Package.Ecosystem != c.Ecosystem || !samePackage(c.Ecosystem, af.Package.Name, c.Name) {
			continue
		}
		for _, r := range af.Ranges {
			if r.Type == "GIT" {
				continue
			}
			for _, ev := range r.Events {
				fx, ok := ev["fixed"]
				if !ok || CompareVersions(fx, cur) <= 0 {
					continue
				}
				if best == "" || CompareVersions(fx, best) < 0 {
					best = fx
				}
			}
		}
	}
	if best != "" && c.Ecosystem == sbom.EcosystemGo && !strings.HasPrefix(best, "v") {
		best = "v" + best
	}
	return best
}

// toVulnerability projects the advisory onto one component.
func (a *Advisory) toVulnerability(c sbom.Component) Vulnerability {
	return Vulnerability{
		ID:           a.ID,
		Aliases:      a.Aliases,
		Summary:      a.summary(),
		Severity:     a.severity(),
		FixedVersion: a.fixedVersionFor(c),
		URL:          "https://osv.dev/vulnerability/" + a.ID,
	}
}
