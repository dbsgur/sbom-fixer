package vuln

import (
	"context"
	"fmt"
	"sort"

	"sbomapp/internal/sbom"
)

// maxRefineRounds bounds how often a fix target is re-checked and raised.
const maxRefineRounds = 4

// Checker turns components into findings using an AdvisoryDB.
type Checker struct {
	DB AdvisoryDB
}

func NewChecker(db AdvisoryDB) *Checker { return &Checker{DB: db} }

// Check returns a Finding for every component with known advisories,
// most severe first.
func (ch *Checker) Check(ctx context.Context, comps []sbom.Component, progress func(string)) ([]Finding, error) {
	if progress == nil {
		progress = func(string) {}
	}
	progress(fmt.Sprintf("취약점 DB 조회 중... (컴포넌트 %d개)", len(comps)))
	ids, err := ch.DB.QueryIDs(ctx, comps)
	if err != nil {
		return nil, fmt.Errorf("취약점 조회 실패: %w", err)
	}
	advs, err := ch.DB.Advisories(ctx, uniqueIDs(ids))
	if err != nil {
		return nil, err
	}
	progress(fmt.Sprintf("취약점 상세 정보 %d건 분석 중...", len(advs)))

	var findings []Finding
	for i, c := range comps {
		if f, ok := buildFinding(c, ids[i], advs); ok {
			findings = append(findings, f)
		}
	}

	progress("권장 수정 버전의 안전성 확인 중...")
	if err := ch.refineTargets(ctx, findings); err != nil {
		return nil, err
	}
	for i := range findings {
		f := &findings[i]
		f.MajorBump = f.Fixable && MajorOf(f.FixVersion) != MajorOf(f.Component.Version)
	}
	sortFindings(findings)
	return findings, nil
}

func uniqueIDs(ids [][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range ids {
		for _, id := range l {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// buildFinding aggregates the advisories of one component.
func buildFinding(c sbom.Component, ids []string, advs map[string]*Advisory) (Finding, bool) {
	f := Finding{Component: c, Severity: SeverityUnknown}
	withFix := 0
	for _, id := range ids {
		a := advs[id]
		if a == nil {
			continue
		}
		v := a.toVulnerability(c)
		if v.FixedVersion != "" {
			withFix++
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
		return Finding{}, false
	}
	f.FullyFixed = withFix == len(f.Vulns)
	f.Vulns = dedupeAliases(f.Vulns)
	f.Fixable = f.FixVersion != ""
	return f, true
}

// dedupeAliases drops advisories that are aliases of one already listed
// (e.g. GO-2022-0001 and GHSA-xxxx describing the same issue), keeping the
// most severe record.
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

// refineTargets makes sure a recommended fix version is not itself
// vulnerable (e.g. a regression introduced in the fixing release). If it is,
// the target is raised to the version that also fixes those advisories.
func (ch *Checker) refineTargets(ctx context.Context, findings []Finding) error {
	for round := 0; round < maxRefineRounds; round++ {
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
		ids, err := ch.DB.QueryIDs(ctx, probe)
		if err != nil {
			return err
		}
		all := uniqueIDs(ids)
		if len(all) == 0 {
			return nil
		}
		advs, err := ch.DB.Advisories(ctx, all)
		if err != nil {
			return err
		}
		changed := false
		for k, i := range idx {
			if len(ids[k]) == 0 {
				continue
			}
			next, unfixable := "", false
			for _, id := range ids[k] {
				a := advs[id]
				if a == nil {
					continue
				}
				fx := a.fixedVersionFor(probe[k])
				if fx == "" {
					unfixable = true
				} else if next == "" || CompareVersions(fx, next) > 0 {
					next = fx
				}
			}
			f := &findings[i]
			switch {
			case next != "" && CompareVersions(next, f.FixVersion) > 0:
				f.FixVersion = next
				changed = true
			case unfixable:
				f.TargetVulnerable = true
			}
		}
		if !changed {
			return nil
		}
	}
	return nil
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(a, b int) bool {
		ra, rb := SeverityRank(fs[a].Severity), SeverityRank(fs[b].Severity)
		if ra != rb {
			return ra > rb
		}
		return fs[a].Component.Name < fs[b].Component.Name
	})
}
