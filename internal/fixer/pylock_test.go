package fixer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const pep621Pyproject = `[project]
name = "app"
dependencies = [
    "requests[socks]==2.19.0 ; python_version > '3'",
    "Jinja2>=2.10",
]

[project.optional-dependencies]
docs = ["sphinx~=7.0"]

[dependency-groups]
dev = ["pytest==7.0.0", {include-group = "lint"}]
lint = ["ruff"]
`

const poetryPyprojectFixer = `[tool.poetry.dependencies]
python = "^3.10"
requests = "2.19.0"
jinja2 = "^2.10"
celery = { version = "^4.0", extras = ["redis"], markers = "sys_platform != 'win32'" }

[tool.poetry.group.dev.dependencies]
pytest = "~7.0"

[tool.poetry.dev-dependencies]
black = "*"
`

func TestFindPyDecl(t *testing.T) {
	cases := []struct {
		name, pyproject, pkg string
		want                 pyDecl
	}{
		{"pep621 extras+marker", pep621Pyproject, "requests",
			pyDecl{found: true, spec: "==2.19.0", extras: "[socks]", marker: "; python_version > '3'"}},
		{"pep621 normalized name", pep621Pyproject, "jinja2", pyDecl{found: true, spec: ">=2.10"}},
		{"optional extra", pep621Pyproject, "sphinx", pyDecl{found: true, args: []string{"--optional", "docs"}, spec: "~=7.0"}},
		{"dependency group", pep621Pyproject, "pytest", pyDecl{found: true, args: []string{"--group", "dev"}, spec: "==7.0.0"}},
		{"bare name", pep621Pyproject, "ruff", pyDecl{found: true, args: []string{"--group", "lint"}}},
		{"poetry main", poetryPyprojectFixer, "requests", pyDecl{found: true, spec: "2.19.0"}},
		{"poetry table is complex", poetryPyprojectFixer, "celery", pyDecl{found: true, complex: true}},
		{"poetry group", poetryPyprojectFixer, "pytest", pyDecl{found: true, args: []string{"--group", "dev"}, spec: "~7.0"}},
		{"poetry legacy dev", poetryPyprojectFixer, "black", pyDecl{found: true, args: []string{"--group", "dev"}, spec: "*"}},
		{"not declared", poetryPyprojectFixer, "urllib3", pyDecl{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := findPyDecl([]byte(c.pyproject), c.pkg)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
	if _, err := findPyDecl([]byte("[project\n"), "x"); err == nil {
		t.Error("invalid TOML should fail")
	}
}

func TestNewPySpec(t *testing.T) {
	for old, want := range map[string]string{
		"==2.19.0": "==2.33.0", "===1": "===2.33.0", "~=2.19": "~=2.33.0",
		"^2.19": "^2.33.0", "~2.19": "~2.33.0", "2.19.0": "==2.33.0",
		">=2.0": ">=2.33.0", ">=2,<3": ">=2.33.0", "*": ">=2.33.0", "": ">=2.33.0",
	} {
		if got := newPySpec(old, "2.33.0"); got != want {
			t.Errorf("newPySpec(%q) = %q want %q", old, got, want)
		}
	}
}

func TestPyDeclRequirement(t *testing.T) {
	d := pyDecl{found: true, spec: "==2.19.0", extras: "[socks]", marker: "; python_version > '3'"}
	if got := d.requirement("requests", "2.33.0"); got != "requests[socks]==2.33.0 ; python_version > '3'" {
		t.Errorf("got %q", got)
	}
}

const poetryLockFor = `[[package]]
name = "requests"
version = "%REQ%"
groups = ["main"]

[[package]]
name = "urllib3"
version = "%URL%"
groups = ["main"]
`

func poetryLockWith(req, urllib string) string {
	return strings.NewReplacer("%REQ%", req, "%URL%", urllib).Replace(poetryLockFor)
}

func TestPythonFixer_PoetryDirectBeforeTransitive(t *testing.T) {
	root := setup(t, map[string]string{"ml/pyproject.toml": poetryPyprojectFixer, "ml/poetry.lock": poetryLockWith("2.19.0", "1.23")})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		if strings.HasPrefix(cmd, "poetry update urllib3") {
			return os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(poetryLockWith("2.33.0", "2.8.0")), 0o644)
		}
		return nil
	}}
	rep := NewService(run, PythonFixer{}).Apply(context.Background(), root, []Request{
		// transitive listed first on purpose
		{Ecosystem: "PyPI", Name: "urllib3", CurrentVersion: "1.23", TargetVersion: "2.8.0", Manifest: "ml/poetry.lock"},
		{Ecosystem: "PyPI", Name: "requests", CurrentVersion: "2.19.0", TargetVersion: "2.33.0", Manifest: "ml/poetry.lock", Direct: true},
	}, nil)
	want := []string{"poetry add requests==2.33.0 --lock", "poetry update urllib3 --lock"}
	if !reflect.DeepEqual(run.calls, want) {
		t.Errorf("calls = %v, want %v", run.calls, want)
	}
	for _, r := range rep.Results {
		if !r.Success {
			t.Errorf("%s: %s", r.Request.Name, r.Message)
		}
	}
	if rep.Results[0].Request.Name != "urllib3" {
		t.Error("results must keep request order")
	}
}

func TestPythonFixer_PoetryTransitiveBlockedByParent(t *testing.T) {
	lock := poetryLockWith("2.19.0", "1.23")
	root := setup(t, map[string]string{"pyproject.toml": poetryPyprojectFixer, "poetry.lock": lock})
	run := &fakeRunner{} // poetry update succeeds but cannot move urllib3
	rep := NewService(run, PythonFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "PyPI", Name: "urllib3", CurrentVersion: "1.23", TargetVersion: "2.8.0", Manifest: "poetry.lock"},
	}, nil)
	r := rep.Results[0]
	if r.Success || !strings.Contains(r.Message, "남아 있습니다") || !strings.Contains(r.Message, "상위 패키지") {
		t.Errorf("result = %+v", r)
	}
}

func TestPythonFixer_PoetryComplexDeclarationSkipped(t *testing.T) {
	root := setup(t, map[string]string{"pyproject.toml": poetryPyprojectFixer, "poetry.lock": poetryLockWith("2.19.0", "1.23")})
	run := &fakeRunner{}
	rep := NewService(run, PythonFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "PyPI", Name: "celery", CurrentVersion: "4.0.0", TargetVersion: "5.2.2", Manifest: "poetry.lock", Direct: true},
	}, nil)
	if rep.Results[0].Success || !strings.Contains(rep.Results[0].Message, "표 형식") || len(run.calls) != 0 {
		t.Errorf("result=%+v calls=%v", rep.Results[0], run.calls)
	}
}

const uvLockFor = `version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "requests"
version = "%REQ%"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "%PYT%"
source = { registry = "https://pypi.org/simple" }
`

func TestPythonFixer_UvCommands(t *testing.T) {
	lock := strings.NewReplacer("%REQ%", "2.19.0", "%PYT%", "7.0.0").Replace(uvLockFor)
	root := setup(t, map[string]string{"pyproject.toml": pep621Pyproject, "uv.lock": lock})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		if strings.HasPrefix(cmd, "uv lock") {
			return errors.New("No solution found")
		}
		fixed := strings.NewReplacer("%REQ%", "2.33.0", "%PYT%", "9.0.3").Replace(uvLockFor)
		return os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(fixed), 0o644)
	}}
	rep := NewService(run, PythonFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "PyPI", Name: "requests", CurrentVersion: "2.19.0", TargetVersion: "2.33.0", Manifest: "uv.lock", Direct: true},
		{Ecosystem: "PyPI", Name: "pytest", CurrentVersion: "7.0.0", TargetVersion: "9.0.3", Manifest: "uv.lock", Direct: true},
		{Ecosystem: "PyPI", Name: "urllib3", CurrentVersion: "1.23", TargetVersion: "2.8.0", Manifest: "uv.lock"},
	}, nil)
	want := []string{
		"uv add requests[socks]==2.33.0 ; python_version > '3' --no-sync",
		"uv add pytest==9.0.3 --no-sync --group dev",
		"uv lock --upgrade-package urllib3==2.8.0",
	}
	if !reflect.DeepEqual(run.calls, want) {
		t.Errorf("calls =\n%s\nwant\n%s", strings.Join(run.calls, "\n"), strings.Join(want, "\n"))
	}
	if !rep.Results[0].Success || !rep.Results[1].Success {
		t.Errorf("direct results = %+v", rep.Results[:2])
	}
	if r := rep.Results[2]; r.Success || !strings.Contains(r.Message, "상위 패키지의 버전 제약과 충돌") {
		t.Errorf("transitive result = %+v", r)
	}
}

func TestPythonFixer_AllCommandsFailRestores(t *testing.T) {
	lock := poetryLockWith("2.19.0", "1.23")
	root := setup(t, map[string]string{"pyproject.toml": poetryPyprojectFixer, "poetry.lock": lock})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		_ = os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte("half-written"), 0o644)
		return errors.New("resolver failed")
	}}
	rep := NewService(run, PythonFixer{}).Apply(context.Background(), root, []Request{
		{Ecosystem: "PyPI", Name: "requests", CurrentVersion: "2.19.0", TargetVersion: "2.33.0", Manifest: "poetry.lock", Direct: true},
	}, nil)
	if rep.Results[0].Success || read(t, root, "poetry.lock") != lock || read(t, root, "pyproject.toml") != poetryPyprojectFixer {
		t.Errorf("expected rollback, result=%+v", rep.Results[0])
	}
}
