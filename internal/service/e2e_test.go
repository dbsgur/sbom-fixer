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
	// Packages pinned to known-vulnerable versions, per manifest. The same
	// npm project exists once per JS package manager.
	want := map[string]bool{
		"svc/go.mod|golang.org/x/text": false,
		"ml/requirements.txt|jinja2":   false,
		"ml/requirements.txt|requests": false,
	}
	for _, lock := range []string{"web/package-lock.json", "web-yarn/yarn.lock", "web-berry/yarn.lock", "web-pnpm/pnpm-lock.yaml"} {
		want[lock+"|lodash"] = false
		want[lock+"|minimist"] = false
	}
	var reqs []fixer.Request
	for _, f := range rep.Findings {
		k := f.Component.Manifest + "|" + f.Component.Name
		if _, ok := want[k]; ok {
			want[k] = true
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
	for k, found := range want {
		if !found {
			t.Errorf("expected %s to be reported as vulnerable", k)
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
			t.Errorf("still fixable after fix: %s %s@%s -> %s", f.Component.Manifest, f.Component.Name, f.Component.Version, f.FixVersion)
		}
	}
	for _, c := range fr.Fix.Commands {
		t.Logf("[%s] $ %s (ok=%v)", c.Dir, c.Command, c.Success)
	}
}

func logf(t *testing.T) func(string) {
	return func(s string) { t.Log(s) }
}
