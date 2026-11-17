package fixer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sbomapp/internal/sbom"
)

const pipfileFixer = `[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
requests = "==2.19.0"  # pinned for py2 compat
Jinja2 = {version = ">=2.10,<4", extras = ["i18n"]}
celery = {extras = ["redis"], markers = "sys_platform != 'win32'"}
mylib = {path = "../mylib", editable = true}
"zope.interface" = '~=5.0'

[dev-packages]
pytest = "*"
requests = ">=2.0"

[packages.Django]
version = "==3.2.0"
index = "pypi"

[requires]
python_version = "3.10"
`

func TestSetPipfileVersion(t *testing.T) {
	cases := []struct {
		section, name, spec, want string
	}{
		{"packages", "requests", "==2.33.0", `requests = "==2.33.0"  # pinned for py2 compat`},
		{"packages", "jinja2", ">=3.1.6,<4", `Jinja2 = {version = ">=3.1.6,<4", extras = ["i18n"]}`},
		{"packages", "celery", ">=5.2.2", `celery = {version = ">=5.2.2", extras = ["redis"], markers = "sys_platform != 'win32'"}`},
		{"packages", "zope-interface", ">=5.4.0,<6", `"zope.interface" = '>=5.4.0,<6'`},
		{"dev-packages", "pytest", ">=9.0.3", `pytest = ">=9.0.3"`},
		{"dev-packages", "requests", ">=2.33.0", `requests = ">=2.33.0"` + "\n\n[packages.Django]"},
		{"packages", "django", "==3.2.25", "[packages.Django]\nversion = \"==3.2.25\"\nindex = \"pypi\""},
	}
	for _, c := range cases {
		got, err := setPipfileVersion(pipfileFixer, c.section, c.name, c.spec)
		if err != nil {
			t.Errorf("%s/%s: %v", c.section, c.name, err)
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s/%s: want line %q in\n%s", c.section, c.name, c.want, got)
		}
		// exactly one line changes (or one added for a missing version)
		if d := lineDiff(pipfileFixer, got); d != 1 {
			t.Errorf("%s/%s: %d lines changed", c.section, c.name, d)
		}
	}

	// [packages] requests must not touch [dev-packages] requests
	got, _ := setPipfileVersion(pipfileFixer, "packages", "requests", "==2.33.0")
	if !strings.Contains(got, `requests = ">=2.0"`) {
		t.Error("dev-packages entry changed")
	}
	// sub-table without a version gets one
	got, err := setPipfileVersion("[packages.flask]\nindex = \"pypi\"\n", "packages", "flask", ">=2.2.5")
	if err != nil || got != "[packages.flask]\nversion = \">=2.2.5\"\nindex = \"pypi\"\n" {
		t.Errorf("sub-table insert: %q %v", got, err)
	}
	// empty inline table
	got, _ = setPipfileVersion("[packages]\nflask = {}\n", "packages", "flask", ">=2.2.5")
	if got != "[packages]\nflask = {version = \">=2.2.5\"}\n" {
		t.Errorf("empty inline table: %q", got)
	}
	// [[source]] after a section does not belong to it
	src := "[packages]\nrequests = \"*\"\n\n[[source]]\nname = \"pypi\"\n"
	if _, err := setPipfileVersion(src, "packages", "name", "==1"); err == nil {
		t.Error("[[source]] keys must not be treated as packages")
	}
	if _, err := setPipfileVersion(pipfileFixer, "packages", "flask", "==1"); err == nil || !strings.Contains(err.Error(), "찾지 못했습니다") {
		t.Errorf("missing package: %v", err)
	}
}

func lineDiff(a, b string) int {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	if len(al) != len(bl) {
		return len(bl) - len(al)
	}
	n := 0
	for i := range al {
		if al[i] != bl[i] {
			n++
		}
	}
	return n
}

func TestPipfileUpgrade(t *testing.T) {
	decls, err := sbom.ParsePipfile([]byte(pipfileFixer))
	if err != nil {
		t.Fatal(err)
	}
	// declared in both sections → both raised, each keeping its form
	got, changes, err := pipfileUpgrade(pipfileFixer, decls, "Requests", "2.33.0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `requests = "==2.33.0"  # pinned`) || !strings.Contains(got, `requests = ">=2.33.0"`) {
		t.Errorf("got\n%s", got)
	}
	if want := []string{`[packages] "==2.33.0"`, `[dev-packages] ">=2.33.0"`}; !reflect.DeepEqual(changes, want) {
		t.Errorf("changes = %v", changes)
	}

	for name, msg := range map[string]string{
		"mylib": "git·경로",
		"flask": "찾지 못했습니다",
	} {
		if _, _, err := pipfileUpgrade(pipfileFixer, decls, name, "9.9.9"); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: err = %v, want %q", name, err, msg)
		}
	}
	// upper bound that excludes the fix is refused, not widened
	if _, _, err := pipfileUpgrade(pipfileFixer, decls, "jinja2", "4.0.0"); err == nil || !strings.Contains(err.Error(), "상한") {
		t.Errorf("jinja2 upper bound: %v", err)
	}
}

const pipfileLockFor = `{
  "_meta": {"hash": {"sha256": "x"}, "pipfile-spec": 6, "requires": {}, "sources": []},
  "default": {
    "requests": {"version": "==%REQ%"},
    "urllib3": {"version": "==%URL%"}
  },
  "develop": {
    "pytest": {"version": "==%PYT%"},
    "urllib3": {"version": "==%URL%"}
  }
}`

func pipfileLockWith(req, urllib, pytest string) string {
	return strings.NewReplacer("%REQ%", req, "%URL%", urllib, "%PYT%", pytest).Replace(pipfileLockFor)
}

const pipfileSimple = `[packages]
requests = "==2.19.0"

[dev-packages]
pytest = "~=7.0"
`

func TestPythonFixer_PipenvDirectBeforeTransitive(t *testing.T) {
	root := setup(t, map[string]string{"api/Pipfile": pipfileSimple, "api/Pipfile.lock": pipfileLockWith("2.19.0", "1.23", "7.0.0")})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		pf, _ := os.ReadFile(filepath.Join(dir, "Pipfile"))
		switch cmd {
		case "pipenv upgrade requests --lock-only":
			if !strings.Contains(string(pf), `requests = "==2.33.0"`) {
				return errors.New("Pipfile must be rewritten before pipenv runs")
			}
			return os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(pipfileLockWith("2.33.0", "1.23", "7.0.0")), 0o644)
		case "pipenv upgrade pytest --lock-only":
			return os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(pipfileLockWith("2.33.0", "1.23", "7.2.6")), 0o644)
		case "pipenv upgrade urllib3 --lock-only":
			return os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(pipfileLockWith("2.33.0", "2.8.0", "7.2.6")), 0o644)
		}
		return errors.New("unexpected " + cmd)
	}}
	rep := NewService(run, PythonFixer{}).Apply(context.Background(), root, []Request{
		// transitive listed first on purpose
		{Ecosystem: "PyPI", Name: "urllib3", CurrentVersion: "1.23", TargetVersion: "2.8.0", Manifest: "api/Pipfile.lock"},
		{Ecosystem: "PyPI", Name: "requests", CurrentVersion: "2.19.0", TargetVersion: "2.33.0", Manifest: "api/Pipfile.lock", Direct: true},
		{Ecosystem: "PyPI", Name: "pytest", CurrentVersion: "7.0.0", TargetVersion: "7.2.6", Manifest: "api/Pipfile.lock", Direct: true},
	}, nil)
	want := []string{"pipenv upgrade requests --lock-only", "pipenv upgrade pytest --lock-only", "pipenv upgrade urllib3 --lock-only"}
	if !reflect.DeepEqual(run.calls, want) {
		t.Errorf("calls = %v, want %v", run.calls, want)
	}
	for _, r := range rep.Results {
		if !r.Success {
			t.Errorf("%s: %s", r.Request.Name, r.Message)
		}
	}
	if rep.Results[0].Request.Name != "urllib3" || !strings.HasPrefix(rep.Results[0].Message, "간접 의존성") {
		t.Errorf("results must keep request order: %+v", rep.Results[0])
	}
	pf := read(t, root, "api/Pipfile")
	if pf != "[packages]\nrequests = \"==2.33.0\"\n\n[dev-packages]\npytest = \">=7.2.6,<8\"\n" {
		t.Errorf("Pipfile =\n%s", pf)
	}
	if !reflect.DeepEqual(rep.ChangedFiles, []string{"api/Pipfile", "api/Pipfile.lock"}) {
		t.Errorf("changed = %v", rep.ChangedFiles)
	}
}

func TestPythonFixer_PipenvTransitiveBlockedByParent(t *testing.T) {
	lock := pipfileLockWith("2.19.0", "1.23", "7.0.0")
	root := setup(t, map[string]string{"Pipfile": pipfileSimple, "Pipfile.lock": lock})
	run := &fakeRunner{} // pipenv succeeds but cannot move urllib3
	rep := NewService(run, PythonFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "PyPI", Name: "urllib3", CurrentVersion: "1.23", TargetVersion: "2.8.0", Manifest: "Pipfile.lock"},
	}, nil)
	r := rep.Results[0]
	if r.Success || !strings.Contains(r.Message, "남아 있습니다") || !strings.Contains(r.Message, "상위 패키지") {
		t.Errorf("result = %+v", r)
	}
	if read(t, root, "Pipfile") != pipfileSimple {
		t.Error("transitive fix must not touch the Pipfile")
	}
}

func TestPythonFixer_PipenvFailureUndoesOnlyThatPackage(t *testing.T) {
	root := setup(t, map[string]string{"Pipfile": pipfileSimple, "Pipfile.lock": pipfileLockWith("2.19.0", "1.23", "7.0.0")})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		if strings.Contains(cmd, "pytest") {
			_ = os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte("half-written"), 0o644)
			return errors.New("ResolutionFailure")
		}
		return os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(pipfileLockWith("2.33.0", "2.8.0", "7.0.0")), 0o644)
	}}
	rep := NewService(run, PythonFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "PyPI", Name: "requests", CurrentVersion: "2.19.0", TargetVersion: "2.33.0", Manifest: "Pipfile.lock", Direct: true},
		{Ecosystem: "PyPI", Name: "pytest", CurrentVersion: "7.0.0", TargetVersion: "7.2.6", Manifest: "Pipfile.lock", Direct: true},
	}, nil)
	if !rep.Results[0].Success || rep.Results[1].Success || !strings.Contains(rep.Results[1].Message, "pipenv 실행 실패") {
		t.Errorf("results = %+v", rep.Results)
	}
	if pf := read(t, root, "Pipfile"); !strings.Contains(pf, `requests = "==2.33.0"`) || !strings.Contains(pf, `pytest = "~=7.0"`) {
		t.Errorf("only the failed package should be undone:\n%s", pf)
	}
	if read(t, root, "Pipfile.lock") != pipfileLockWith("2.33.0", "2.8.0", "7.0.0") {
		t.Error("lock should be the state after the last successful command")
	}
}

func TestPythonFixer_PipenvAllFailRestores(t *testing.T) {
	lock := pipfileLockWith("2.19.0", "1.23", "7.0.0")
	root := setup(t, map[string]string{"Pipfile": pipfileSimple, "Pipfile.lock": lock})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		_ = os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte("half-written"), 0o644)
		return errors.New("pipenv: command not found")
	}}
	rep := NewService(run, PythonFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "PyPI", Name: "requests", CurrentVersion: "2.19.0", TargetVersion: "2.33.0", Manifest: "Pipfile.lock", Direct: true},
		{Ecosystem: "PyPI", Name: "urllib3", CurrentVersion: "1.23", TargetVersion: "2.8.0", Manifest: "Pipfile.lock"},
	}, nil)
	if rep.Results[0].Success || rep.Results[1].Success || !strings.Contains(rep.Results[1].Message, "상위 패키지") {
		t.Errorf("results = %+v", rep.Results)
	}
	if read(t, root, "Pipfile.lock") != lock || read(t, root, "Pipfile") != pipfileSimple || len(rep.ChangedFiles) != 0 {
		t.Errorf("expected rollback, changed=%v", rep.ChangedFiles)
	}
}

func TestPythonFixer_PipenvRefusesWithoutRunning(t *testing.T) {
	root := setup(t, map[string]string{"Pipfile": pipfileFixer, "Pipfile.lock": pipfileLockWith("2.19.0", "1.23", "7.0.0")})
	run := &fakeRunner{}
	rep := NewService(run, PythonFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "PyPI", Name: "mylib", CurrentVersion: "0.1.0", TargetVersion: "0.2.0", Manifest: "Pipfile.lock", Direct: true},
		{Ecosystem: "PyPI", Name: "jinja2", CurrentVersion: "2.10", TargetVersion: "4.0.0", Manifest: "Pipfile.lock", Direct: true},
	}, nil)
	if len(run.calls) != 0 || rep.Results[0].Success || rep.Results[1].Success {
		t.Errorf("calls=%v results=%+v", run.calls, rep.Results)
	}

	noPipfile := setup(t, map[string]string{"Pipfile.lock": pipfileLockWith("2.19.0", "1.23", "7.0.0")})
	rep = NewService(run, PythonFixer{}).Apply(context.Background(), noPipfile, []Request{
		{Ecosystem: "PyPI", Name: "requests", CurrentVersion: "2.19.0", TargetVersion: "2.33.0", Manifest: "Pipfile.lock", Direct: true},
	}, nil)
	if rep.Results[0].Success || !strings.Contains(rep.Results[0].Message, "Pipfile을 찾을 수 없습니다") {
		t.Errorf("result = %+v", rep.Results[0])
	}
}
