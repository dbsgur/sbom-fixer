package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sbomapp/internal/sbom"
	"sbomapp/internal/vuln"
)

func sampleReport() *ScanReport {
	minimist := sbom.Component{Name: "minimist", Version: "0.0.8", Ecosystem: "npm", Manifest: "web/yarn.lock", PURL: "pkg:npm/minimist@0.0.8"}
	text := sbom.Component{Name: "golang.org/x/text", Version: "v0.3.5", Ecosystem: "Go", Manifest: "go.mod", Direct: true}
	return &ScanReport{
		Root:       "/work/my-proj",
		Components: []sbom.Component{lodash, minimist, text},
		Manifests:  []string{"web/yarn.lock", "go.mod"},
		ScannedAt:  "2026-11-08 10:00:00",
		Findings: []vuln.Finding{
			{Component: minimist, Severity: vuln.SeverityCritical, FixVersion: "0.2.4", Fixable: true, FullyFixed: true,
				Vulns: []vuln.Vulnerability{{ID: "GHSA-1", Severity: vuln.SeverityCritical, FixedVersion: "0.2.1"}, {ID: "GHSA-2", Aliases: []string{"CVE-2021-1"}, Severity: vuln.SeverityMedium, FixedVersion: "0.2.4"}}},
			{Component: text, Severity: vuln.SeverityHigh,
				Vulns: []vuln.Vulnerability{{ID: "GO-1", Severity: vuln.SeverityHigh}}},
		},
	}
}

func TestBuildVulnReport(t *testing.T) {
	now := time.Date(2026, 11, 8, 1, 2, 3, 0, time.UTC)
	r := BuildVulnReport(sampleReport(), now)

	if r.SchemaVersion != VulnReportSchemaVersion || r.GeneratedAt != "2026-11-08T01:02:03Z" || r.Project.Name != "my-proj" {
		t.Errorf("header = %+v", r)
	}
	s := r.Summary
	if s.Components != 3 || s.VulnerablePackages != 2 || s.Vulnerabilities != 3 || s.FixablePackages != 1 {
		t.Errorf("summary = %+v", s)
	}
	if s.BySeverity["CRITICAL"] != 1 || s.BySeverity["HIGH"] != 1 || s.BySeverity["LOW"] != 0 || len(s.BySeverity) != 5 {
		t.Errorf("bySeverity = %v (all five keys expected)", s.BySeverity)
	}
	if s.ByEcosystem["npm"] != 1 || s.ByEcosystem["Go"] != 1 {
		t.Errorf("byEcosystem = %v", s.ByEcosystem)
	}
	f := r.Findings[0]
	if f.Package.Manifest != "web/yarn.lock" || f.RecommendedVersion != "0.2.4" || len(f.Vulnerabilities) != 2 {
		t.Errorf("finding = %+v", f)
	}
	if !r.Findings[1].Package.Direct || r.Findings[1].Fixable {
		t.Errorf("second finding = %+v", r.Findings[1])
	}
}

func TestVulnReportJSON_NoNullArrays(t *testing.T) {
	data, err := VulnReportJSON(&ScanReport{Root: "/x/empty"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, null := range []string{`"findings": null`, `"warnings": null`, `"manifests": null`} {
		if strings.Contains(string(data), null) {
			t.Errorf("found %s in %s", null, data)
		}
	}
	data, _ = VulnReportJSON(sampleReport(), time.Now())
	if strings.Contains(string(data), `"aliases": null`) {
		t.Errorf("aliases should be [] not null")
	}
}

func TestExportFormats(t *testing.T) {
	rep := sampleReport()
	want := map[string]string{"cyclonedx": "my-proj.cdx.json", "vulns": "my-proj.vulns.json"}
	for id, filename := range want {
		f, err := FindExportFormat(id)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.DefaultFilename(rep); got != filename {
			t.Errorf("%s filename = %s want %s", id, got, filename)
		}
		data, err := f.Render(rep, time.Now())
		if err != nil || !json.Valid(data) {
			t.Errorf("%s: invalid output (err=%v)", id, err)
		}
	}
	if len(ExportFormats) != len(want) {
		t.Errorf("formats = %d, update this test", len(ExportFormats))
	}
	if _, err := FindExportFormat("pdf"); err == nil {
		t.Error("unknown format should fail")
	}
}
