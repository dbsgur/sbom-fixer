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

func TestFindPyDeclSectionArgs(t *testing.T) {
	cases := []struct {
		name, pyproject, pkg string
		args                 []string
		errContains          string
	}{
		{"pep621 main", pep621Pyproject, "requests", nil, ""},
		{"optional extra", pep621Pyproject, "sphinx", []string{"--optional", "docs"}, ""},
		{"dependency group", pep621Pyproject, "pytest", []string{"--group", "dev"}, ""},
		{"poetry group", poetryPyprojectFixer, "pytest", []string{"--group", "dev"}, ""},
		{"poetry legacy dev refused", poetryPyprojectFixer, "black", nil, "구버전"},
		{"uv legacy dev", "[tool.uv]\ndev-dependencies = [\"pytest==7.0.0\"]\n", "pytest", []string{"--dev"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reqs, err := sbom.ParsePyproject([]byte(c.pyproject))
			if err != nil {
				t.Fatal(err)
			}
			d := findPyDecl(reqs, c.pkg)
			if !d.found {
				t.Fatal("not found")
			}
			args, err := d.sectionArgs()
			if c.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), c.errContains) {
					t.Errorf("err = %v", err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(args, c.args) {
				t.Errorf("args = %v err = %v, want %v", args, err, c.args)
			}
		})
	}
	reqs, _ := sbom.ParsePyproject([]byte(poetryPyprojectFixer))
	if findPyDecl(reqs, "urllib3").found {
		t.Error("undeclared package should not be found")
	}
	if d := findPyDecl(reqs, "celery"); !d.Table {
		t.Error("celery is a table declaration")
	}
}

func TestNewPySpec(t *testing.T) {
	ok := map[string]string{
		// exact pins and Poetry operators keep their form
		"==2.19.0": "==2.33.0", "===1": "===2.33.0", "2.19.0": "==2.33.0",
		"^2.19": "^2.33.0", "~2.19": "~2.33.0",
		// open lower bounds are raised
		">=2.0": ">=2.33.0", ">2.0": ">=2.33.0", "*": ">=2.33.0", "": ">=2.33.0",
		// upper bounds and exclusions survive (review #3)
		">=2.0,<3": ">=2.33.0,<3", ">=2, <=2.40": ">=2.33.0,<=2.40", "!=2.20,>=2": ">=2.33.0,!=2.20",
		// compatible release keeps its original range instead of narrowing it (review #4)
		"~=2.19": ">=2.33.0,<3", "~=2.19.0": ">=2.33.0,<2.34",
	}
	for old, want := range ok {
		got, err := newPySpec(old, "2.33.0")
		if err != nil || got != want {
			t.Errorf("newPySpec(%q) = %q, %v; want %q", old, got, err, want)
		}
	}
	// ~=7.0 allows <8; target inside that range keeps the bound
	if got, _ := newPySpec("~=7.0", "7.2.6"); got != ">=7.2.6,<8" {
		t.Errorf("~=7.0 -> %q", got)
	}
	// target beyond the old compatible range: same precision, re-anchored
	if got, _ := newPySpec("~=7.0", "8.1.2"); got != ">=8.1.2,<9" {
		t.Errorf("~=7.0 beyond range -> %q", got)
	}
	bad := map[string]string{
		">=2.0,<2.30":       "상한",
		"<=2.20":            "상한",
		"!=2.33.0,>=2":      "제외",
		"==2.*":             "와일드카드",
		"@ https://x/y.whl": "URL",
		">>2":               "해석",
	}
	for old, msg := range bad {
		if _, err := newPySpec(old, "2.33.0"); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("newPySpec(%q) err = %v, want containing %q", old, err, msg)
		}
	}
}

func TestPyDeclRequirement(t *testing.T) {
	d := pyDecl{found: true, PyRequirement: sbom.PyRequirement{Spec: "==2.19.0", Extras: "[socks]", Marker: "; python_version > '3'"}}
	if got, _ := d.requirement("requests", "2.33.0"); got != "requests[socks]==2.33.0 ; python_version > '3'" {
		t.Errorf("got %q", got)
	}
	// Poetry caret/tilde use the name@constraint form every Poetry version accepts (review #1)
	caret := pyDecl{found: true, PyRequirement: sbom.PyRequirement{Spec: "^2.10", Extras: "[i18n]"}}
	if got, _ := caret.requirement("jinja2", "3.1.6"); got != "jinja2[i18n]@^3.1.6" {
		t.Errorf("caret: got %q", got)
	}
	url := pyDecl{found: true, PyRequirement: sbom.PyRequirement{Spec: "@ https://x/y.whl", URL: true}}
	if _, err := url.requirement("y", "1.0"); err == nil {
		t.Error("URL requirement must not be rewritten")
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
