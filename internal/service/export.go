package service

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"sbomapp/internal/sbom"
	"sbomapp/internal/vuln"
)

// ExportFormat is a file the user can save from a scan report. Adding a
// format means appending to ExportFormats; the UI and Wails binding are
// generic over the ID.
type ExportFormat struct {
	ID          string `json:"id"`
	Label       string `json:"label"`       // button text
	DialogTitle string `json:"dialogTitle"` // save dialog title
	FilterName  string `json:"filterName"`
	Suffix      string `json:"suffix"` // appended to the project name
	render      func(rep *ScanReport, now time.Time) ([]byte, error)
}

// Render produces the file contents.
func (f ExportFormat) Render(rep *ScanReport, now time.Time) ([]byte, error) {
	return f.render(rep, now)
}

// DefaultFilename suggests "<project><suffix>".
func (f ExportFormat) DefaultFilename(rep *ScanReport) string {
	return filepath.Base(rep.Root) + f.Suffix
}

var ExportFormats = []ExportFormat{
	{
		ID: "cyclonedx", Label: "SBOM (CycloneDX)", DialogTitle: "SBOM 저장 (CycloneDX 1.5 JSON)",
		FilterName: "CycloneDX JSON", Suffix: ".cdx.json",
		render: func(rep *ScanReport, _ time.Time) ([]byte, error) { return CycloneDX(rep) },
	},
	{
		ID: "vulns", Label: "취약점 리포트 (JSON)", DialogTitle: "취약점 스캔 결과 저장 (JSON)",
		FilterName: "JSON", Suffix: ".vulns.json",
		render: VulnReportJSON,
	},
}

// FindExportFormat looks a format up by ID.
func FindExportFormat(id string) (ExportFormat, error) {
	for _, f := range ExportFormats {
		if f.ID == id {
			return f, nil
		}
	}
	return ExportFormat{}, fmt.Errorf("알 수 없는 내보내기 형식: %s", id)
}

// CycloneDX renders a scan report as a CycloneDX JSON document.
func CycloneDX(rep *ScanReport) ([]byte, error) {
	var vs []sbom.CycloneDXVuln
	for _, f := range rep.Findings {
		for _, v := range f.Vulns {
			vs = append(vs, sbom.CycloneDXVuln{
				ID: v.ID, Severity: strings.ToLower(v.Severity), Summary: v.Summary,
				BomRef: f.Component.Key(), FixedIn: v.FixedVersion,
			})
		}
	}
	return sbom.CycloneDX(filepath.Base(rep.Root), rep.Components, vs)
}

// VulnReportSchemaVersion is bumped on breaking changes to VulnReport.
const VulnReportSchemaVersion = "1"

// VulnReport is the vulnerability scan result as a standalone JSON file,
// meant for CI gates, dashboards or attaching to tickets.
type VulnReport struct {
	SchemaVersion string        `json:"schemaVersion"`
	Tool          string        `json:"tool"`
	GeneratedAt   string        `json:"generatedAt"`
	ScannedAt     string        `json:"scannedAt"`
	Project       ReportProject `json:"project"`
	Summary       ReportSummary `json:"summary"`
	Findings      []ReportItem  `json:"findings"`
	Warnings      []string      `json:"warnings"`
}

type ReportProject struct {
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Manifests []string `json:"manifests"`
}

type ReportSummary struct {
	Components         int            `json:"components"`
	VulnerablePackages int            `json:"vulnerablePackages"`
	Vulnerabilities    int            `json:"vulnerabilities"`
	FixablePackages    int            `json:"fixablePackages"`
	BySeverity         map[string]int `json:"bySeverity"`
	ByEcosystem        map[string]int `json:"byEcosystem"`
}

type ReportPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
	Manifest  string `json:"manifest"`
	Direct    bool   `json:"direct"`
	Dev       bool   `json:"dev"`
}

type ReportItem struct {
	Package            ReportPackage    `json:"package"`
	Severity           string           `json:"severity"`
	RecommendedVersion string           `json:"recommendedVersion"`
	Fixable            bool             `json:"fixable"`
	FullyFixed         bool             `json:"fullyFixed"`
	MajorBump          bool             `json:"majorBump"`
	TargetVulnerable   bool             `json:"targetVulnerable"`
	Vulnerabilities    []ReportAdvisory `json:"vulnerabilities"`
}

type ReportAdvisory struct {
	ID           string   `json:"id"`
	Aliases      []string `json:"aliases"`
	Severity     string   `json:"severity"`
	Summary      string   `json:"summary"`
	FixedVersion string   `json:"fixedVersion"`
	URL          string   `json:"url"`
}

// BuildVulnReport converts a scan report into the export model.
func BuildVulnReport(rep *ScanReport, now time.Time) VulnReport {
	out := VulnReport{
		SchemaVersion: VulnReportSchemaVersion,
		Tool:          "sbom-fixer",
		GeneratedAt:   now.Format(time.RFC3339),
		ScannedAt:     rep.ScannedAt,
		Project:       ReportProject{Name: filepath.Base(rep.Root), Path: rep.Root, Manifests: nonNil(rep.Manifests)},
		Summary: ReportSummary{
			Components:  len(rep.Components),
			BySeverity:  map[string]int{},
			ByEcosystem: map[string]int{},
		},
		Findings: []ReportItem{},
		Warnings: nonNil(rep.Warnings),
	}
	for _, s := range []string{vuln.SeverityCritical, vuln.SeverityHigh, vuln.SeverityMedium, vuln.SeverityLow, vuln.SeverityUnknown} {
		out.Summary.BySeverity[s] = 0
	}
	for _, f := range rep.Findings {
		c := f.Component
		item := ReportItem{
			Package: ReportPackage{
				Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem, PURL: c.PURL,
				Manifest: c.Manifest, Direct: c.Direct, Dev: c.Dev,
			},
			Severity:           f.Severity,
			RecommendedVersion: f.FixVersion,
			Fixable:            f.Fixable,
			FullyFixed:         f.FullyFixed,
			MajorBump:          f.MajorBump,
			TargetVulnerable:   f.TargetVulnerable,
			Vulnerabilities:    []ReportAdvisory{},
		}
		for _, v := range f.Vulns {
			item.Vulnerabilities = append(item.Vulnerabilities, ReportAdvisory{
				ID: v.ID, Aliases: nonNil(v.Aliases), Severity: v.Severity,
				Summary: v.Summary, FixedVersion: v.FixedVersion, URL: v.URL,
			})
		}
		out.Findings = append(out.Findings, item)
		out.Summary.VulnerablePackages++
		out.Summary.Vulnerabilities += len(f.Vulns)
		out.Summary.BySeverity[f.Severity]++
		out.Summary.ByEcosystem[c.Ecosystem]++
		if f.Fixable {
			out.Summary.FixablePackages++
		}
	}
	return out
}

// VulnReportJSON renders BuildVulnReport as indented JSON.
func VulnReportJSON(rep *ScanReport, now time.Time) ([]byte, error) {
	return json.MarshalIndent(BuildVulnReport(rep, now), "", "  ")
}
