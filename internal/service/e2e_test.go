//go:build e2e

// End-to-end test against the real world: OSV.dev, npm and the go tool.
// Run with `make test-e2e`. Not part of `make test` / CI because it needs
// network access and is slower.
package service

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sbomapp/internal/fixer"
	"sbomapp/internal/gitutil"
	"sbomapp/internal/sbom"
	"sbomapp/internal/shellenv"
	"sbomapp/internal/vuln"
)

// Fixture files carry a ".fixture" suffix so GitHub's dependency graph does
// not report the intentionally vulnerable versions as real alerts.
const fixtureSuffix = ".fixture"

func copyFixture(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, strings.TrimSuffix(rel, fixtureSuffix))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestE2E_ScanFixRescan(t *testing.T) {
	shellenv.EnsureLoginPath()
	for _, tool := range []string{"npm", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	root := copyFixture(t, "testdata/vulnerable")
	svc := &Service{
		Scanner: sbom.NewScanner(),
		Checker: vuln.NewChecker(vuln.NewOSVClient()),
		Fixer:   fixer.DefaultService(),
		Git:     gitutil.Git{},
	}
	ctx := context.Background()

	rep, err := svc.Scan(ctx, root, logf(t))
	if err != nil {
		t.Fatal(err)
	}
	// Packages pinned to known-vulnerable versions in the fixture.
	want := map[string]bool{"lodash": false, "minimist": false, "golang.org/x/text": false, "jinja2": false, "requests": false}
	var reqs []fixer.Request
	for _, f := range rep.Findings {
		if _, ok := want[f.Component.Name]; ok {
			want[f.Component.Name] = true
		}
		if !f.Fixable {
			continue
		}
		reqs = append(reqs, fixer.Request{
			Ecosystem: f.Component.Ecosystem, Name: f.Component.Name,
			CurrentVersion: f.Component.Version, TargetVersion: f.FixVersion,
			Manifest: f.Component.Manifest, Direct: f.Component.Direct,
		})
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected %s to be reported as vulnerable", name)
		}
	}

	fr, err := svc.Fix(ctx, root, reqs, logf(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range fr.Fix.Results {
		if !r.Success {
			t.Errorf("fix %s failed: %s", r.Request.Name, r.Message)
		}
	}
	if fr.Rescan == nil {
		t.Fatal("rescan missing")
	}
	for _, f := range fr.Rescan.Findings {
		if f.Fixable {
			t.Errorf("still fixable after fix: %s@%s -> %s", f.Component.Name, f.Component.Version, f.FixVersion)
		}
	}
}

func logf(t *testing.T) func(string) {
	return func(s string) { t.Log(s) }
}
