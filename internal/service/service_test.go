package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"sbomapp/internal/fixer"
	"sbomapp/internal/sbom"
	"sbomapp/internal/vuln"
)

type fakeScanner struct {
	res   *sbom.Result
	err   error
	calls int
}

func (f *fakeScanner) Scan(string, func(string)) (*sbom.Result, error) {
	f.calls++
	return f.res, f.err
}

type fakeChecker struct {
	findings []vuln.Finding
	err      error
	called   bool
}

func (f *fakeChecker) Check(context.Context, []sbom.Component, func(string)) ([]vuln.Finding, error) {
	f.called = true
	return f.findings, f.err
}

type fakeFixer struct{ got []fixer.Request }

func (f *fakeFixer) Apply(_ context.Context, _ string, reqs []fixer.Request, _ func(string)) *fixer.Report {
	f.got = reqs
	return &fixer.Report{Results: []fixer.Result{{Request: reqs[0], Success: true}}}
}

type fakeGit struct{ watched []string }

func (f *fakeGit) Status(_ string, files []string) (bool, []string) {
	f.watched = files
	return true, []string{"go.mod"}
}

var (
	lodash = sbom.Component{Name: "lodash", Version: "4.17.15", Ecosystem: "npm", Manifest: "web/package-lock.json"}
	text   = sbom.Component{Name: "golang.org/x/text", Version: "v0.3.5", Ecosystem: "Go", Manifest: "go.mod"}
)

func newService(sc *fakeScanner, ch *fakeChecker) (*Service, *fakeGit) {
	t0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	calls := 0
	g := &fakeGit{}
	return &Service{
		Scanner: sc, Checker: ch, Fixer: &fakeFixer{}, Git: g,
		Now: func() time.Time { calls++; return t0.Add(time.Duration(calls-1) * 1500 * time.Millisecond) },
	}, g
}

func TestScan_BuildsReport(t *testing.T) {
	sc := &fakeScanner{res: &sbom.Result{
		Components: []sbom.Component{lodash, text},
		Manifests:  []string{"web/package-lock.json", "go.mod", "app/pnpm-lock.yaml", "ml/uv.lock"},
	}}
	ch := &fakeChecker{findings: []vuln.Finding{{Component: lodash, Severity: vuln.SeverityHigh}}}
	svc, git := newService(sc, ch)

	var progress []string
	rep, err := svc.Scan(context.Background(), t.TempDir(), func(s string) { progress = append(progress, s) })
	if err != nil {
		t.Fatal(err)
	}
	if rep.Ecosystems["npm"] != 1 || rep.Ecosystems["Go"] != 1 || rep.Severities[vuln.SeverityHigh] != 1 {
		t.Errorf("counts: %+v %+v", rep.Ecosystems, rep.Severities)
	}
	if !rep.GitRepo || len(rep.GitDirty) != 1 {
		t.Errorf("git: %v %v", rep.GitRepo, rep.GitDirty)
	}
	wantWatch := []string{"web/package-lock.json", "web/package.json", "go.mod", "go.sum", "app/pnpm-lock.yaml", "app/package.json", "ml/uv.lock", "ml/pyproject.toml"}
	if len(git.watched) != len(wantWatch) {
		t.Fatalf("watched = %v", git.watched)
	}
	for i := range wantWatch {
		if git.watched[i] != wantWatch[i] {
			t.Errorf("watched = %v, want %v", git.watched, wantWatch)
		}
	}
	if rep.DurationMs != 1500 || rep.ScannedAt != "2026-11-07 10:00:01" {
		t.Errorf("timing: %d %s", rep.DurationMs, rep.ScannedAt)
	}
	if progress[len(progress)-1] != "완료" {
		t.Errorf("progress = %v", progress)
	}
}

func TestScan_NoComponentsSkipsChecker(t *testing.T) {
	ch := &fakeChecker{}
	svc, _ := newService(&fakeScanner{res: &sbom.Result{}}, ch)
	rep, err := svc.Scan(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if ch.called || len(rep.Warnings) != 1 {
		t.Errorf("checker called=%v warnings=%v", ch.called, rep.Warnings)
	}
	// Empty slices (not null) so the UI can iterate safely.
	b, _ := json.Marshal(rep)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["components"] == nil || m["findings"] == nil {
		t.Errorf("components/findings must not be null: %s", b)
	}
}

func TestScan_Errors(t *testing.T) {
	svc, _ := newService(&fakeScanner{err: errors.New("walk")}, &fakeChecker{})
	if _, err := svc.Scan(context.Background(), t.TempDir(), nil); err == nil {
		t.Error("scanner error should propagate")
	}
	svc, _ = newService(&fakeScanner{res: &sbom.Result{Components: []sbom.Component{lodash}}}, &fakeChecker{err: errors.New("osv")})
	if _, err := svc.Scan(context.Background(), t.TempDir(), nil); err == nil {
		t.Error("checker error should propagate")
	}
	if _, err := svc.Scan(context.Background(), "/definitely/not/here", nil); err == nil {
		t.Error("missing root should fail")
	}
}

func TestFix_AppliesAndRescans(t *testing.T) {
	sc := &fakeScanner{res: &sbom.Result{Components: []sbom.Component{lodash}}}
	svc, _ := newService(sc, &fakeChecker{})
	fx := svc.Fixer.(*fakeFixer)
	req := fixer.Request{Ecosystem: "npm", Name: "lodash", TargetVersion: "4.17.21", Manifest: "web/package-lock.json"}
	fr, err := svc.Fix(context.Background(), t.TempDir(), []fixer.Request{req}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fx.got) != 1 || fr.Fix == nil || fr.Rescan == nil || sc.calls != 1 {
		t.Errorf("fix=%+v rescan=%v scans=%d", fr.Fix, fr.Rescan, sc.calls)
	}
}

func TestFix_KeepsResultWhenRescanFails(t *testing.T) {
	svc, _ := newService(&fakeScanner{err: errors.New("x")}, &fakeChecker{})
	fr, err := svc.Fix(context.Background(), t.TempDir(), []fixer.Request{{Name: "a"}}, nil)
	if err != nil || fr.Fix == nil || fr.Rescan != nil {
		t.Errorf("fr=%+v err=%v", fr, err)
	}
}

func TestFix_RequiresSelection(t *testing.T) {
	svc, _ := newService(&fakeScanner{}, &fakeChecker{})
	if _, err := svc.Fix(context.Background(), t.TempDir(), nil, nil); err == nil {
		t.Error("expected error")
	}
}

func TestCycloneDX_IncludesFindings(t *testing.T) {
	rep := &ScanReport{
		Root:       "/tmp/proj",
		Components: []sbom.Component{lodash},
		Findings: []vuln.Finding{{Component: lodash, Vulns: []vuln.Vulnerability{
			{ID: "GHSA-x", Severity: vuln.SeverityHigh, FixedVersion: "4.17.21"},
		}}},
	}
	data, err := CycloneDX(rep)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata struct {
			Component map[string]string `json:"component"`
		} `json:"metadata"`
		Vulnerabilities []struct {
			Ratings []struct {
				Severity string `json:"severity"`
			} `json:"ratings"`
		} `json:"vulnerabilities"`
	}
	_ = json.Unmarshal(data, &doc)
	if doc.Metadata.Component["name"] != "proj" || len(doc.Vulnerabilities) != 1 || doc.Vulnerabilities[0].Ratings[0].Severity != "high" {
		t.Errorf("doc = %s", data)
	}
}
