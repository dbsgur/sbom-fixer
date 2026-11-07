package fixer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner records commands and lets a test simulate their effect.
type fakeRunner struct {
	calls  []string
	handle func(dir, cmd string) error
}

func (f *fakeRunner) Run(_ context.Context, dir string, _ []string, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	if f.handle != nil {
		if err := f.handle(dir, cmd); err != nil {
			return "boom", err
		}
	}
	return "ok", nil
}

func setup(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const pkgJSON = "{\n  \"name\": \"web\",\n  \"dependencies\": {\n    \"lodash\": \"4.17.15\",\n    \"mkdirp\": \"0.5.1\"\n  }\n}\n"

func lockWith(lodash, minimist string) string {
	return `{"lockfileVersion":3,"packages":{"":{},` +
		`"node_modules/lodash":{"version":"` + lodash + `"},` +
		`"node_modules/mkdirp":{"version":"0.5.1"},` +
		`"node_modules/minimist":{"version":"` + minimist + `"}}}`
}

func TestNpmFixer_Success(t *testing.T) {
	root := setup(t, map[string]string{"web/package.json": pkgJSON, "web/package-lock.json": lockWith("4.17.15", "0.0.8")})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		// Simulate npm regenerating the lock file from package.json.
		return os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockWith("4.17.21", "0.2.4")), 0o644)
	}}
	rep := NewService(run, NpmFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "npm", Name: "lodash", CurrentVersion: "4.17.15", TargetVersion: "4.17.21", Manifest: "web/package-lock.json", Direct: true},
		{Ecosystem: "npm", Name: "minimist", CurrentVersion: "0.0.8", TargetVersion: "0.2.4", Manifest: "web/package-lock.json"},
	}, nil)

	for _, r := range rep.Results {
		if !r.Success {
			t.Errorf("%s failed: %s", r.Request.Name, r.Message)
		}
	}
	if len(run.calls) != 1 || !strings.HasPrefix(run.calls[0], "npm install --package-lock-only") {
		t.Errorf("npm should run once per manifest: %v", run.calls)
	}
	pj := read(t, root, "web/package.json")
	if !strings.Contains(pj, `"lodash": "4.17.21"`) || !strings.Contains(pj, `"overrides": {`+"\n"+`    "minimist": "0.2.4"`) {
		t.Errorf("package.json = %s", pj)
	}
	if strings.Join(rep.ChangedFiles, ",") != "web/package-lock.json,web/package.json" {
		t.Errorf("changed = %v", rep.ChangedFiles)
	}
	if len(rep.Commands) != 1 || rep.Commands[0].Dir != "web" || !rep.Commands[0].Success {
		t.Errorf("commands = %+v", rep.Commands)
	}
}

func TestNpmFixer_RestoresOnFailure(t *testing.T) {
	lock := lockWith("4.17.15", "0.0.8")
	root := setup(t, map[string]string{"package.json": pkgJSON, "package-lock.json": lock})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		_ = os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("garbage"), 0o644)
		return errors.New("exit 1")
	}}
	rep := NewService(run, NpmFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "npm", Name: "lodash", CurrentVersion: "4.17.15", TargetVersion: "4.17.21", Manifest: "package-lock.json", Direct: true},
	}, nil)
	if rep.Results[0].Success || !strings.Contains(rep.Results[0].Message, "되돌렸습니다") {
		t.Errorf("result = %+v", rep.Results[0])
	}
	if read(t, root, "package.json") != pkgJSON || read(t, root, "package-lock.json") != lock {
		t.Error("files were not restored")
	}
	if len(rep.ChangedFiles) != 0 {
		t.Errorf("changed = %v", rep.ChangedFiles)
	}
}

func TestNpmFixer_DetectsStaleLock(t *testing.T) {
	root := setup(t, map[string]string{"package.json": pkgJSON, "package-lock.json": lockWith("4.17.15", "0.0.8")})
	run := &fakeRunner{} // npm "succeeds" but does not change the lock
	rep := NewService(run, NpmFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "npm", Name: "lodash", CurrentVersion: "4.17.15", TargetVersion: "4.17.21", Manifest: "package-lock.json", Direct: true},
	}, nil)
	if rep.Results[0].Success || !strings.Contains(rep.Results[0].Message, "남아 있습니다") {
		t.Errorf("result = %+v", rep.Results[0])
	}
}

const goMod = "module x\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.5\n"

func TestGoFixer_Success(t *testing.T) {
	root := setup(t, map[string]string{"svc/go.mod": goMod})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		if strings.HasPrefix(cmd, "go get") {
			return os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\ngo 1.25.0\n\nrequire golang.org/x/text v0.21.0\n"), 0o644)
		}
		return nil
	}}
	rep := NewService(run, GoFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "Go", Name: "golang.org/x/text", CurrentVersion: "v0.3.5", TargetVersion: "0.21.0", Manifest: "svc/go.mod", Direct: true},
	}, nil)
	r := rep.Results[0]
	if !r.Success {
		t.Fatalf("failed: %s", r.Message)
	}
	if strings.Join(run.calls, " | ") != "go get golang.org/x/text@v0.21.0 | go mod tidy" {
		t.Errorf("calls = %v", run.calls)
	}
	if !strings.Contains(r.Message, "1.22 → 1.25.0") {
		t.Errorf("should mention go directive bump: %s", r.Message)
	}
}

func TestGoFixer_TidyFailureRestores(t *testing.T) {
	root := setup(t, map[string]string{"go.mod": goMod})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		if strings.HasPrefix(cmd, "go get") {
			return os.WriteFile(filepath.Join(dir, "go.mod"), []byte("changed"), 0o644)
		}
		return errors.New("tidy failed")
	}}
	rep := NewService(run, GoFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "Go", Name: "golang.org/x/text", CurrentVersion: "v0.3.5", TargetVersion: "v0.21.0", Manifest: "go.mod"},
	}, nil)
	if rep.Results[0].Success || read(t, root, "go.mod") != goMod {
		t.Errorf("expected rollback, result=%+v go.mod=%q", rep.Results[0], read(t, root, "go.mod"))
	}
	if _, err := os.Stat(filepath.Join(root, "go.sum")); !os.IsNotExist(err) {
		t.Error("go.sum did not exist before and should not exist after rollback")
	}
}

func TestGoFixer_GetFailure(t *testing.T) {
	root := setup(t, map[string]string{"go.mod": goMod})
	run := &fakeRunner{handle: func(string, string) error { return errors.New("no such version") }}
	rep := NewService(run, GoFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "Go", Name: "golang.org/x/text", CurrentVersion: "v0.3.5", TargetVersion: "v9.9.9", Manifest: "go.mod"},
	}, nil)
	if rep.Results[0].Success || len(run.calls) != 1 {
		t.Errorf("result=%+v calls=%v", rep.Results[0], run.calls)
	}
}

func TestPythonFixer(t *testing.T) {
	orig := "requests==2.19.0\nflask>=2\nJinja2 == 2.10 ; python_version>'3'  # web\n"
	root := setup(t, map[string]string{"requirements.txt": orig})
	rep := NewService(&fakeRunner{}, PythonFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "PyPI", Name: "jinja2", CurrentVersion: "2.10", TargetVersion: "3.1.6", Manifest: "requirements.txt"},
		{Ecosystem: "PyPI", Name: "requests", CurrentVersion: "2.0.0", TargetVersion: "2.33.0", Manifest: "requirements.txt"},
	}, nil)
	if !rep.Results[0].Success || rep.Results[1].Success {
		t.Errorf("results = %+v", rep.Results)
	}
	want := "requests==2.19.0\nflask>=2\nJinja2 == 3.1.6 ; python_version>'3'  # web\n"
	if got := read(t, root, "requirements.txt"); got != want {
		t.Errorf("got %q", got)
	}
}

func TestService_ValidatesRequests(t *testing.T) {
	root := setup(t, map[string]string{"go.mod": goMod})
	run := &fakeRunner{}
	rep := NewService(run, GoFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "Go", Name: "-evil", TargetVersion: "v1", Manifest: "go.mod"},
		{Ecosystem: "Go", Name: "a", TargetVersion: "", Manifest: "go.mod"},
		{Ecosystem: "Go", Name: "a", TargetVersion: "v1", Manifest: "../outside/go.mod"},
		{Ecosystem: "Go", Name: "a", TargetVersion: "v1", Manifest: "missing/go.mod"},
		{Ecosystem: "Cargo", Name: "a", TargetVersion: "1", Manifest: "go.mod"},
	}, nil)
	if len(rep.Results) != 5 {
		t.Fatalf("want 5 results, got %d", len(rep.Results))
	}
	for _, r := range rep.Results {
		if r.Success {
			t.Errorf("%+v should fail", r)
		}
	}
	if len(run.calls) != 0 {
		t.Errorf("no command should run: %v", run.calls)
	}
}
