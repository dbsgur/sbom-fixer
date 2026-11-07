// Package vuln finds known vulnerabilities for SBOM components and works out
// which version fixes them.
//
// Checker holds the analysis logic and depends only on the AdvisoryDB
// interface; OSVClient is the production AdvisoryDB backed by api.osv.dev.
package vuln

import (
	"context"

	"sbomapp/internal/sbom"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityUnknown  = "UNKNOWN"
)

var severityRank = map[string]int{SeverityUnknown: 0, SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4}

// SeverityRank orders severities (higher = worse).
func SeverityRank(s string) int { return severityRank[s] }

// AdvisoryDB is a source of vulnerability advisories.
type AdvisoryDB interface {
	// QueryIDs returns, for every component (same order), the IDs of the
	// advisories affecting that exact version.
	QueryIDs(ctx context.Context, comps []sbom.Component) ([][]string, error)
	// Advisories returns the full records for the given IDs.
	Advisories(ctx context.Context, ids []string) (map[string]*Advisory, error)
}

// Advisory is a vulnerability record in OSV schema
// (https://ossf.github.io/osv-schema/), trimmed to the fields we use.
type Advisory struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected         []Affected     `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// Affected describes the affected versions of one package.
type Affected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
	DatabaseSpecific  map[string]any `json:"database_specific"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific"`
}

// Vulnerability is a single advisory as it applies to one component.
type Vulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity string   `json:"severity"`
	// FixedVersion is the smallest version newer than the installed one that
	// fixes this advisory ("" if no fix is published).
	FixedVersion string `json:"fixedVersion"`
	URL          string `json:"url"`
}

// Finding groups all advisories for one vulnerable component.
type Finding struct {
	Component sbom.Component  `json:"component"`
	Vulns     []Vulnerability `json:"vulns"`
	Severity  string          `json:"severity"`
	// FixVersion is the smallest version that fixes every advisory that has
	// a fix. Empty when no advisory has a fix.
	FixVersion string `json:"fixVersion"`
	// Fixable is true when FixVersion resolves at least one advisory.
	Fixable bool `json:"fixable"`
	// FullyFixed is true when FixVersion resolves every advisory.
	FullyFixed bool `json:"fullyFixed"`
	// MajorBump warns that FixVersion changes the major version.
	MajorBump bool `json:"majorBump"`
	// TargetVulnerable is true when even FixVersion is affected by an
	// advisory that has no published fix yet.
	TargetVulnerable bool `json:"targetVulnerable"`
}
