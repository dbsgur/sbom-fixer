package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"sbomapp/internal/sbom"
)

// fakeDB is an in-memory AdvisoryDB. affects maps "name@version" to IDs.
type fakeDB struct {
	affects map[string][]string
	advs    map[string]*Advisory
	err     error
}

func (f *fakeDB) QueryIDs(_ context.Context, comps []sbom.Component) ([][]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([][]string, len(comps))
	for i, c := range comps {
		out[i] = f.affects[c.Name+"@"+c.Version]
	}
	return out, nil
}

func (f *fakeDB) Advisories(_ context.Context, ids []string) (map[string]*Advisory, error) {
	out := map[string]*Advisory{}
	for _, id := range ids {
		out[id] = f.advs[id]
	}
	return out, nil
}

// adv builds an advisory from compact JSON so tests read like OSV data.
func adv(t *testing.T, js string) *Advisory {
	t.Helper()
	var a Advisory
	if err := json.Unmarshal([]byte(js), &a); err != nil {
		t.Fatal(err)
	}
	return &a
}

func npm(name, ver string, direct bool) sbom.Component {
	return sbom.Component{Name: name, Version: ver, Ecosystem: sbom.EcosystemNpm, Direct: direct, Manifest: "package-lock.json"}
}

func TestChecker_BasicFinding(t *testing.T) {
	db := &fakeDB{
		affects: map[string][]string{"lodash@4.17.15": {"GHSA-a", "GHSA-b"}},
		advs: map[string]*Advisory{
			"GHSA-a": adv(t, `{"id":"GHSA-a","summary":"proto pollution","database_specific":{"severity":"HIGH"},
				"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.19"}]}]}]}`),
			"GHSA-b": adv(t, `{"id":"GHSA-b","summary":"cmd injection","database_specific":{"severity":"MODERATE"},
				"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`),
		},
	}
	fs, err := NewChecker(db).Check(context.Background(), []sbom.Component{npm("lodash", "4.17.15", true), npm("safe", "1.0.0", true)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.FixVersion != "4.17.21" || !f.Fixable || !f.FullyFixed || f.MajorBump || f.Severity != SeverityHigh {
		t.Errorf("finding = %+v", f)
	}
	if f.Vulns[0].ID != "GHSA-a" { // sorted by severity
		t.Errorf("vulns not sorted by severity: %+v", f.Vulns)
	}
}

func TestChecker_NoFixAvailable(t *testing.T) {
	db := &fakeDB{
		affects: map[string][]string{"x@1.0.0": {"A"}},
		advs: map[string]*Advisory{"A": adv(t, `{"id":"A","affected":[{"package":{"name":"x","ecosystem":"npm"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"9.9.9"}]}]}]}`)},
	}
	fs, _ := NewChecker(db).Check(context.Background(), []sbom.Component{npm("x", "1.0.0", true)}, nil)
	if len(fs) != 1 || fs[0].Fixable || fs[0].FullyFixed || fs[0].Severity != SeverityUnknown {
		t.Errorf("got %+v", fs)
	}
}

func TestChecker_RefinesVulnerableTarget(t *testing.T) {
	// 4.17.15 is fixed in 4.18.0, but 4.18.0 introduced a regression fixed in 4.18.1.
	db := &fakeDB{
		affects: map[string][]string{"lodash@4.17.15": {"OLD"}, "lodash@4.18.0": {"NEW"}},
		advs: map[string]*Advisory{
			"OLD": adv(t, `{"id":"OLD","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.18.0"}]}]}]}`),
			"NEW": adv(t, `{"id":"NEW","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"4.18.0"},{"fixed":"4.18.1"}]}]}]}`),
		},
	}
	fs, err := NewChecker(db).Check(context.Background(), []sbom.Component{npm("lodash", "4.17.15", true)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fs[0].FixVersion != "4.18.1" || fs[0].TargetVulnerable {
		t.Errorf("got %+v", fs[0])
	}
}

func TestChecker_TargetStillVulnerable(t *testing.T) {
	db := &fakeDB{
		affects: map[string][]string{"x@1.0.0": {"OLD"}, "x@2.0.0": {"UNFIXED"}},
		advs: map[string]*Advisory{
			"OLD":     adv(t, `{"id":"OLD","affected":[{"package":{"name":"x","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`),
			"UNFIXED": adv(t, `{"id":"UNFIXED","affected":[{"package":{"name":"x","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`),
		},
	}
	fs, _ := NewChecker(db).Check(context.Background(), []sbom.Component{npm("x", "1.0.0", true)}, nil)
	if !fs[0].TargetVulnerable || !fs[0].MajorBump || fs[0].FixVersion != "2.0.0" {
		t.Errorf("got %+v", fs[0])
	}
}

func TestChecker_DedupesAliases(t *testing.T) {
	db := &fakeDB{
		affects: map[string][]string{"golang.org/x/text@v0.3.5": {"GO-1", "GHSA-1"}},
		advs: map[string]*Advisory{
			"GO-1":   adv(t, `{"id":"GO-1","aliases":["GHSA-1","CVE-1"],"affected":[{"package":{"name":"golang.org/x/text","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.3.7"}]}]}]}`),
			"GHSA-1": adv(t, `{"id":"GHSA-1","aliases":["GO-1","CVE-1"],"database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"golang.org/x/text","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.3.7"}]}]}]}`),
		},
	}
	c := sbom.Component{Name: "golang.org/x/text", Version: "v0.3.5", Ecosystem: sbom.EcosystemGo}
	fs, _ := NewChecker(db).Check(context.Background(), []sbom.Component{c}, nil)
	if len(fs[0].Vulns) != 1 || fs[0].Vulns[0].ID != "GHSA-1" {
		t.Errorf("want only GHSA-1 (has severity), got %+v", fs[0].Vulns)
	}
	if fs[0].FixVersion != "v0.3.7" {
		t.Errorf("Go fix version should get v prefix, got %s", fs[0].FixVersion)
	}
}

func TestChecker_SortsBySeverity(t *testing.T) {
	db := &fakeDB{
		affects: map[string][]string{"a@1": {"L"}, "b@1": {"C"}},
		advs: map[string]*Advisory{
			"L": adv(t, `{"id":"L","database_specific":{"severity":"LOW"}}`),
			"C": adv(t, `{"id":"C","database_specific":{"severity":"CRITICAL"}}`),
		},
	}
	fs, _ := NewChecker(db).Check(context.Background(), []sbom.Component{npm("a", "1", true), npm("b", "1", true)}, nil)
	if fs[0].Component.Name != "b" {
		t.Errorf("critical should come first: %+v", fs)
	}
}

func TestChecker_PropagatesDBError(t *testing.T) {
	_, err := NewChecker(&fakeDB{err: errors.New("down")}).Check(context.Background(), []sbom.Component{npm("a", "1", true)}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAdvisorySeverity(t *testing.T) {
	cases := map[string]string{
		`{"database_specific":{"severity":"MODERATE"}}`:                                            SeverityMedium,
		`{"affected":[{"ecosystem_specific":{"severity":"low"}}]}`:                                 SeverityLow,
		`{"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`: SeverityCritical,
		`{"severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N"}]}`:                                SeverityUnknown,
	}
	for js, want := range cases {
		if got := adv(t, js).severity(); got != want {
			t.Errorf("%s => %s want %s", js, got, want)
		}
	}
}

func TestAdvisorySummaryFallsBackToDetails(t *testing.T) {
	a := adv(t, `{"details":"first line\nsecond line"}`)
	if a.summary() != "first line" {
		t.Errorf("got %q", a.summary())
	}
}

func TestFixedVersionFor_PyPINameNormalization(t *testing.T) {
	a := adv(t, `{"affected":[{"package":{"name":"Jinja2","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.10.1"}]},{"type":"GIT","events":[{"fixed":"abc123"}]}]}]}`)
	c := sbom.Component{Name: "jinja2", Version: "2.10", Ecosystem: sbom.EcosystemPyPI}
	if got := a.fixedVersionFor(c); got != "2.10.1" {
		t.Errorf("got %q", got)
	}
}
