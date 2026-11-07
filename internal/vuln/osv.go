// Package vuln looks up known vulnerabilities for SBOM components using the
// OSV.dev API (https://osv.dev) and works out which version fixes them.
package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

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

// Vulnerability is a single advisory affecting a component.
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

// Client talks to the OSV API.
type Client struct {
	BaseURL string
	HTTP    *http.Client

	mu    sync.Mutex
	cache map[string]*osvVuln
}

func NewClient() *Client {
	return &Client{
		BaseURL: "https://api.osv.dev",
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		cache:   map[string]*osvVuln{},
	}
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
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
	} `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

func osvVersion(c sbom.Component) string {
	if c.Ecosystem == sbom.EcosystemGo {
		return strings.TrimPrefix(c.Version, "v")
	}
	return c.Version
}

// Check queries OSV for every component and returns the vulnerable ones.
func (cl *Client) Check(ctx context.Context, comps []sbom.Component, progress func(string)) ([]Finding, error) {
	if progress == nil {
		progress = func(string) {}
	}
	// 1. Batch query: which advisory IDs affect each component.
	ids, err := cl.queryIDs(ctx, comps, progress)
	if err != nil {
		return nil, err
	}

	// 2. Fetch advisory details (deduplicated, in parallel).
	unique := map[string]bool{}
	for _, l := range ids {
		for _, id := range l {
			unique[id] = true
		}
	}
	progress(fmt.Sprintf("취약점 상세 정보 %d건 조회 중...", len(unique)))
	if err := cl.fetchAll(ctx, unique); err != nil {
		return nil, err
	}

	// 3. Build findings.
	var findings []Finding
	for i, c := range comps {
		if len(ids[i]) == 0 {
			continue
		}
		f := Finding{Component: c, Severity: SeverityUnknown}
		covered := 0
		for _, id := range ids[i] {
			ov := cl.cache[id]
			if ov == nil {
				continue
			}
			v := Vulnerability{
				ID:       ov.ID,
				Aliases:  ov.Aliases,
				Summary:  summaryOf(ov),
				Severity: severityOf(ov),
				URL:      "https://osv.dev/vulnerability/" + ov.ID,
			}
			v.FixedVersion = fixedVersionFor(ov, c)
			if v.FixedVersion != "" {
				covered++
				if f.FixVersion == "" || CompareVersions(v.FixedVersion, f.FixVersion) > 0 {
					f.FixVersion = v.FixedVersion
				}
			}
			if SeverityRank(v.Severity) > SeverityRank(f.Severity) {
				f.Severity = v.Severity
			}
			f.Vulns = append(f.Vulns, v)
		}
		if len(f.Vulns) == 0 {
			continue
		}
		f.Vulns = dedupeAliases(f.Vulns)
		f.Fixable = f.FixVersion != ""
		f.FullyFixed = f.Fixable && covered == len(ids[i])
		sort.Slice(f.Vulns, func(a, b int) bool {
			return SeverityRank(f.Vulns[a].Severity) > SeverityRank(f.Vulns[b].Severity)
		})
		findings = append(findings, f)
	}
	if err := cl.refineTargets(ctx, findings, progress); err != nil {
		return nil, err
	}
	for i := range findings {
		f := &findings[i]
		if f.Fixable {
			f.MajorBump = MajorOf(f.FixVersion) != MajorOf(f.Component.Version)
		}
	}
	sort.SliceStable(findings, func(a, b int) bool {
		ra, rb := SeverityRank(findings[a].Severity), SeverityRank(findings[b].Severity)
		if ra != rb {
			return ra > rb
		}
		return findings[a].Component.Name < findings[b].Component.Name
	})
	return findings, nil
}

// queryIDs returns, for every component, the IDs of advisories affecting it.
func (cl *Client) queryIDs(ctx context.Context, comps []sbom.Component, progress func(string)) ([][]string, error) {
	ids := make([][]string, len(comps))
	const chunk = 500
	for start := 0; start < len(comps); start += chunk {
		end := min(start+chunk, len(comps))
		progress(fmt.Sprintf("OSV 취약점 DB 조회 중... (%d/%d)", end, len(comps)))
		queries := make([]osvQuery, 0, end-start)
		for _, c := range comps[start:end] {
			var q osvQuery
			q.Package.Name = c.Name
			q.Package.Ecosystem = c.Ecosystem
			q.Version = osvVersion(c)
			queries = append(queries, q)
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := cl.post(ctx, "/v1/querybatch", map[string]any{"queries": queries}, &resp); err != nil {
			return nil, fmt.Errorf("OSV 조회 실패: %w", err)
		}
		for i, r := range resp.Results {
			for _, v := range r.Vulns {
				ids[start+i] = append(ids[start+i], v.ID)
			}
		}
	}
	return ids, nil
}

// refineTargets makes sure the recommended fix version is not itself
// vulnerable (e.g. a regression introduced in the fixing release). If it is,
// the target is raised to the version fixing those advisories as well.
func (cl *Client) refineTargets(ctx context.Context, findings []Finding, progress func(string)) error {
	for round := 0; round < 4; round++ {
		var idx []int
		var probe []sbom.Component
		for i, f := range findings {
			if f.Fixable && !f.TargetVulnerable {
				c := f.Component
				c.Version = f.FixVersion
				idx = append(idx, i)
				probe = append(probe, c)
			}
		}
		if len(probe) == 0 {
			return nil
		}
		progress("권장 수정 버전의 안전성 확인 중...")
		ids, err := cl.queryIDs(ctx, probe, func(string) {})
		if err != nil {
			return err
		}
		need := map[string]bool{}
		for _, l := range ids {
			for _, id := range l {
				need[id] = true
			}
		}
		if len(need) == 0 {
			return nil
		}
		if err := cl.fetchAll(ctx, need); err != nil {
			return err
		}
		changed := false
		for k, i := range idx {
			if len(ids[k]) == 0 {
				continue
			}
			f := &findings[i]
			next := ""
			stuck := false
			for _, id := range ids[k] {
				ov := cl.cache[id]
				if ov == nil {
					continue
				}
				fx := fixedVersionFor(ov, probe[k])
				if fx == "" {
					stuck = true
					continue
				}
				if next == "" || CompareVersions(fx, next) > 0 {
					next = fx
				}
			}
			if next != "" && CompareVersions(next, f.FixVersion) > 0 {
				f.FixVersion = next
				changed = true
			} else if stuck {
				f.TargetVulnerable = true
			}
		}
		if !changed {
			return nil
		}
	}
	return nil
}

// dedupeAliases drops advisories that are aliases of another one already in
// the list (e.g. GO-2022-0001 and GHSA-xxxx describing the same issue),
// keeping the one with the most severity information.
func dedupeAliases(vs []Vulnerability) []Vulnerability {
	sort.SliceStable(vs, func(a, b int) bool {
		return SeverityRank(vs[a].Severity) > SeverityRank(vs[b].Severity)
	})
	seen := map[string]bool{}
	var out []Vulnerability
	for _, v := range vs {
		if seen[v.ID] {
			continue
		}
		seen[v.ID] = true
		for _, a := range v.Aliases {
			seen[a] = true
		}
		out = append(out, v)
	}
	return out
}

func (cl *Client) fetchAll(ctx context.Context, ids map[string]bool) error {
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for id := range ids {
		cl.mu.Lock()
		_, ok := cl.cache[id]
		cl.mu.Unlock()
		if ok {
			continue
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var v osvVuln
			if err := cl.get(ctx, "/v1/vulns/"+id, &v); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("취약점 %s 조회 실패: %w", id, err)
				}
				errMu.Unlock()
				return
			}
			cl.mu.Lock()
			cl.cache[id] = &v
			cl.mu.Unlock()
		}(id)
	}
	wg.Wait()
	return firstErr
}

func (cl *Client) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cl.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return cl.do(req, out)
}

func (cl *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cl.BaseURL+path, nil)
	if err != nil {
		return err
	}
	return cl.do(req, out)
}

func (cl *Client) do(req *http.Request, out any) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := cl.HTTP.Do(req)
		if err != nil {
			lastErr = err
		} else {
			func() {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
					return
				}
				lastErr = json.NewDecoder(resp.Body).Decode(out)
			}()
			if lastErr == nil || resp.StatusCode < 500 && resp.StatusCode != 429 {
				return lastErr
			}
		}
		if req.Context().Err() != nil {
			return req.Context().Err()
		}
		if req.GetBody != nil {
			req.Body, _ = req.GetBody()
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
	return lastErr
}

func summaryOf(v *osvVuln) string {
	if v.Summary != "" {
		return v.Summary
	}
	d := strings.TrimSpace(v.Details)
	if i := strings.IndexAny(d, "\n"); i > 0 {
		d = d[:i]
	}
	if len([]rune(d)) > 200 {
		d = string([]rune(d)[:200]) + "…"
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

func severityOf(v *osvVuln) string {
	if s, ok := v.DatabaseSpecific["severity"].(string); ok {
		if n := normSeverity(s); n != "" {
			return n
		}
	}
	for _, a := range v.Affected {
		for _, m := range []map[string]any{a.EcosystemSpecific, a.DatabaseSpecific} {
			if s, ok := m["severity"].(string); ok {
				if n := normSeverity(s); n != "" {
					return n
				}
			}
		}
	}
	for _, s := range v.Severity {
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
// component's current version, formatted for the component's ecosystem.
func fixedVersionFor(v *osvVuln, c sbom.Component) string {
	cur := osvVersion(c)
	best := ""
	for _, a := range v.Affected {
		if a.Package.Ecosystem != c.Ecosystem || !samePackage(c.Ecosystem, a.Package.Name, c.Name) {
			continue
		}
		for _, r := range a.Ranges {
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
