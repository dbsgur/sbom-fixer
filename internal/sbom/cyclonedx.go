package sbom

import (
	"encoding/json"
	"time"
)

// CycloneDXVuln is the minimal vulnerability info embedded in the exported BOM.
type CycloneDXVuln struct {
	ID       string
	Severity string
	Summary  string
	BomRef   string
	FixedIn  string
}

// CycloneDX renders the components (and optional vulnerabilities) as a
// CycloneDX 1.5 JSON document.
func CycloneDX(projectName string, comps []Component, vulns []CycloneDXVuln) ([]byte, error) {
	type prop struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type comp struct {
		Type       string `json:"type"`
		BomRef     string `json:"bom-ref"`
		Name       string `json:"name"`
		Version    string `json:"version"`
		PURL       string `json:"purl,omitempty"`
		Scope      string `json:"scope,omitempty"`
		Properties []prop `json:"properties,omitempty"`
	}
	type rating struct {
		Severity string `json:"severity"`
	}
	type affect struct {
		Ref string `json:"ref"`
	}
	type vuln struct {
		ID             string   `json:"id"`
		Description    string   `json:"description,omitempty"`
		Recommendation string   `json:"recommendation,omitempty"`
		Ratings        []rating `json:"ratings,omitempty"`
		Affects        []affect `json:"affects"`
	}
	type doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Version     int    `json:"version"`
		Metadata    struct {
			Timestamp string `json:"timestamp"`
			Tools     struct {
				Components []map[string]string `json:"components"`
			} `json:"tools"`
			Component map[string]string `json:"component"`
		} `json:"metadata"`
		Components      []comp `json:"components"`
		Vulnerabilities []vuln `json:"vulnerabilities,omitempty"`
	}

	d := doc{BomFormat: "CycloneDX", SpecVersion: "1.5", Version: 1}
	d.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	d.Metadata.Tools.Components = []map[string]string{{"type": "application", "name": "sbomapp"}}
	d.Metadata.Component = map[string]string{"type": "application", "name": projectName, "bom-ref": "root"}
	d.Components = []comp{}

	for _, c := range comps {
		cc := comp{Type: "library", BomRef: c.Key(), Name: c.Name, Version: c.Version, PURL: c.PURL,
			Properties: []prop{{"sbomapp:manifest", c.Manifest}}}
		if c.Dev {
			cc.Scope = "optional"
		}
		d.Components = append(d.Components, cc)
	}
	for _, v := range vulns {
		vv := vuln{ID: v.ID, Description: v.Summary, Affects: []affect{{v.BomRef}}}
		if v.Severity != "" {
			vv.Ratings = []rating{{v.Severity}}
		}
		if v.FixedIn != "" {
			vv.Recommendation = "Upgrade to " + v.FixedIn
		}
		d.Vulnerabilities = append(d.Vulnerabilities, vv)
	}
	return json.MarshalIndent(d, "", "  ")
}
