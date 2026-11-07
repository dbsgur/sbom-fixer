package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFiles creates files (relative path -> content) under a temp dir.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func byName(cs []Component) map[string]Component {
	m := map[string]Component{}
	for _, c := range cs {
		m[c.Name+"@"+c.Version] = c
	}
	return m
}

func TestNpmLockParser_V3(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"package.json": `{"dependencies":{"lodash":"^4.17.15"},"devDependencies":{"jest":"29.0.0"}}`,
		"package-lock.json": `{
		  "lockfileVersion": 3,
		  "packages": {
		    "": {"dependencies":{"lodash":"^4.17.15"}},
		    "node_modules/lodash": {"version":"4.17.15"},
		    "node_modules/jest": {"version":"29.0.0","dev":true},
		    "node_modules/@scope/pkg": {"version":"1.0.0"},
		    "node_modules/a/node_modules/lodash": {"version":"3.10.1"},
		    "node_modules/linked": {"link":true},
		    "packages/workspace-a": {"version":"0.1.0"}
		  }
		}`,
	})
	res, err := NpmLockParser{}.Parse(filepath.Join(root, "package-lock.json"), "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	got := byName(res.Components)
	if len(got) != 4 {
		t.Fatalf("want 4 components, got %d: %v", len(got), got)
	}
	cases := []struct {
		key         string
		direct, dev bool
	}{
		{"lodash@4.17.15", true, false},
		{"lodash@3.10.1", false, false}, // nested copy is not the direct one
		{"jest@29.0.0", true, true},
		{"@scope/pkg@1.0.0", false, false},
	}
	for _, c := range cases {
		comp, ok := got[c.key]
		if !ok {
			t.Errorf("%s missing", c.key)
			continue
		}
		if comp.Direct != c.direct || comp.Dev != c.dev {
			t.Errorf("%s: direct=%v dev=%v, want %v %v", c.key, comp.Direct, comp.Dev, c.direct, c.dev)
		}
	}
	if p := got["@scope/pkg@1.0.0"].PURL; p != "pkg:npm/%40scope/pkg@1.0.0" {
		t.Errorf("scoped purl = %s", p)
	}
}

func TestNpmLockParser_V1(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"package.json": `{"dependencies":{"mkdirp":"0.5.1"}}`,
		"package-lock.json": `{"lockfileVersion":1,"dependencies":{
		   "mkdirp":{"version":"0.5.1","dependencies":{"minimist":{"version":"0.0.8"}}}}}`,
	})
	res, err := NpmLockParser{}.Parse(filepath.Join(root, "package-lock.json"), "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	got := byName(res.Components)
	if !got["mkdirp@0.5.1"].Direct || got["minimist@0.0.8"].Direct {
		t.Errorf("direct flags wrong: %+v", got)
	}
}

func TestNpmLockParser_InvalidJSON(t *testing.T) {
	root := writeFiles(t, map[string]string{"package-lock.json": `{nope`})
	if _, err := (NpmLockParser{}).Parse(filepath.Join(root, "package-lock.json"), "package-lock.json"); err == nil {
		t.Fatal("expected error")
	}
}

func TestNpmManifestCheck(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"a/package.json":      `{}`,
		"b/package.json":      `{}`,
		"b/package-lock.json": `{}`,
	})
	withoutLock, _ := NpmManifestCheck{}.Parse(filepath.Join(root, "a/package.json"), "a/package.json")
	withLock, _ := NpmManifestCheck{}.Parse(filepath.Join(root, "b/package.json"), "b/package.json")
	if len(withoutLock.Warnings) != 1 || len(withLock.Warnings) != 0 {
		t.Errorf("warnings: without=%v with=%v", withoutLock.Warnings, withLock.Warnings)
	}
}

func TestGoModParser(t *testing.T) {
	root := writeFiles(t, map[string]string{"go.mod": `module x

go 1.22

require (
	golang.org/x/text v0.3.5
	github.com/foo/bar v1.0.0 // indirect
)

replace github.com/foo/bar => github.com/foo/bar v1.2.0
`})
	res, err := GoModParser{}.Parse(filepath.Join(root, "go.mod"), "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	got := byName(res.Components)
	if c := got["golang.org/x/text@v0.3.5"]; !c.Direct || c.PURL != "pkg:golang/golang.org/x/text@v0.3.5" {
		t.Errorf("x/text = %+v", c)
	}
	if c, ok := got["github.com/foo/bar@v1.2.0"]; !ok || c.Direct {
		t.Errorf("replace not honoured or indirect flag wrong: %+v", got)
	}
}

func TestParseRequirementLine(t *testing.T) {
	cases := []struct {
		line, name, ver string
		ok              bool
	}{
		{"requests==2.19.0", "requests", "2.19.0", true},
		{"Jinja2 == 2.10 ; python_version>'3'", "Jinja2", "2.10", true},
		{"uvicorn[standard]==0.20.0  # comment", "uvicorn", "0.20.0", true},
		{"pkg===1.0", "pkg", "1.0", true},
		{"flask>=2.0", "", "", false},
		{"# requests==1.0", "", "", false},
		{"-r other.txt", "", "", false},
	}
	for _, c := range cases {
		n, v, ok := ParseRequirementLine(c.line)
		if n != c.name || v != c.ver || ok != c.ok {
			t.Errorf("%q => (%q,%q,%v), want (%q,%q,%v)", c.line, n, v, ok, c.name, c.ver, c.ok)
		}
	}
}

func TestRequirementsParser(t *testing.T) {
	root := writeFiles(t, map[string]string{"requirements-dev.txt": "Requests_Toolbelt==1.0.0\nflask>=2\n-e .\n"})
	res, err := RequirementsParser{}.Parse(filepath.Join(root, "requirements-dev.txt"), "requirements-dev.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Components) != 1 || res.Components[0].Name != "requests-toolbelt" {
		t.Fatalf("components = %+v", res.Components)
	}
	if len(res.Warnings) != 1 {
		t.Errorf("want 1 unpinned warning, got %v", res.Warnings)
	}
}

func TestNormalizePyPIName(t *testing.T) {
	for in, want := range map[string]string{"Foo_Bar": "foo-bar", "a.b--c": "a-b-c", " X ": "x"} {
		if got := NormalizePyPIName(in); got != want {
			t.Errorf("%q => %q want %q", in, got, want)
		}
	}
}

func TestScanner_WalksAndSkips(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"go.mod":                   "module x\nrequire golang.org/x/text v0.3.5\n",
		"svc/requirements.txt":     "requests==2.19.0\n",
		"node_modules/x/go.mod":    "module y\nrequire a.b/c v1.0.0\n",
		".venv/requirements.txt":   "django==1.0\n",
		"broken/package-lock.json": "{",
		"README.md":                "ignored",
		"web/package.json":         `{}`,
	})
	var progress []string
	res, err := NewScanner().Scan(root, func(s string) { progress = append(progress, s) })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Components) != 2 {
		t.Fatalf("want 2 components, got %+v", res.Components)
	}
	// sorted by ecosystem then name
	if res.Components[0].Ecosystem != EcosystemGo || res.Components[1].Ecosystem != EcosystemPyPI {
		t.Errorf("unexpected order: %+v", res.Components)
	}
	if strings.Join(res.Manifests, ",") != "go.mod,svc/requirements.txt" {
		t.Errorf("manifests = %v", res.Manifests)
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "broken/package-lock.json: 파싱 실패") || !strings.Contains(joined, "web/package.json") {
		t.Errorf("warnings = %v", res.Warnings)
	}
	if len(progress) == 0 {
		t.Error("expected progress callbacks")
	}
}

// fakeParser lets us check the Scanner only depends on the Parser interface.
type fakeParser struct{}

func (fakeParser) Match(n string) bool { return n == "deps.lock" }
func (fakeParser) Label() string       { return "" }
func (fakeParser) Parse(_, rel string) (ParseResult, error) {
	return ParseResult{Components: []Component{{Name: "z", Version: "1", Ecosystem: "X", Manifest: rel}}}, nil
}

func TestScanner_CustomParser(t *testing.T) {
	root := writeFiles(t, map[string]string{"deps.lock": "", "go.mod": "module x\nrequire a.b/c v1.0.0\n"})
	s := &Scanner{Parsers: []Parser{fakeParser{}}}
	res, err := s.Scan(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Components) != 1 || res.Components[0].Name != "z" {
		t.Errorf("got %+v", res.Components)
	}
}

func TestScanner_ParseFile(t *testing.T) {
	root := writeFiles(t, map[string]string{"go.mod": "module x\nrequire a.b/c v1.0.0\n", "x.txt": ""})
	s := NewScanner()
	if cs, err := s.ParseFile(filepath.Join(root, "go.mod"), "go.mod"); err != nil || len(cs) != 1 {
		t.Errorf("go.mod: %v %v", cs, err)
	}
	if _, err := s.ParseFile(filepath.Join(root, "x.txt"), "x.txt"); err == nil {
		t.Error("expected error for unsupported file")
	}
}

func TestCycloneDX(t *testing.T) {
	comps := []Component{{Name: "lodash", Version: "4.17.15", Ecosystem: EcosystemNpm, PURL: "pkg:npm/lodash@4.17.15", Manifest: "package-lock.json", Dev: true}}
	data, err := CycloneDX("proj", comps, []CycloneDXVuln{{ID: "GHSA-1", Severity: "high", BomRef: comps[0].Key(), FixedIn: "4.17.21"}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			BomRef string `json:"bom-ref"`
			PURL   string `json:"purl"`
			Scope  string `json:"scope"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID             string `json:"id"`
			Recommendation string `json:"recommendation"`
			Affects        []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BomFormat != "CycloneDX" || doc.SpecVersion != "1.5" || len(doc.Components) != 1 || doc.Components[0].Scope != "optional" {
		t.Errorf("doc = %+v", doc)
	}
	if len(doc.Vulnerabilities) != 1 || doc.Vulnerabilities[0].Affects[0].Ref != doc.Components[0].BomRef ||
		doc.Vulnerabilities[0].Recommendation != "Upgrade to 4.17.21" {
		t.Errorf("vulns = %+v", doc.Vulnerabilities)
	}
}
