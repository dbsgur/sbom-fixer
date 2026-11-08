package fixer

import (
	"strings"
	"testing"
)

func TestNewSpec(t *testing.T) {
	cases := []struct {
		old, want string
		err       bool
	}{
		{"^4.17.15", "^4.17.21", false},
		{"~4.17.15", "~4.17.21", false},
		{">=4.0.0", ">=4.17.21", false},
		{"4.17.15", "4.17.21", false},
		{"4.x", "^4.17.21", false},
		{"*", "^4.17.21", false},
		{"latest", "^4.17.21", false},
		{"file:../lodash", "", true},
		{"git+https://github.com/x/y", "", true},
		{"npm:other@1", "", true},
		{"workspace:*", "", true},
	}
	for _, c := range cases {
		got, err := newSpec(c.old, "4.17.21")
		if (err != nil) != c.err || got != c.want {
			t.Errorf("newSpec(%q) = %q, %v; want %q (err=%v)", c.old, got, err, c.want, c.err)
		}
	}
}

func mustParse(t *testing.T, s string) *orderedObject {
	t.Helper()
	o, err := parseOrdered([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func render(t *testing.T, o *orderedObject) string {
	t.Helper()
	b, err := o.marshalCompact()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplyNpmChange_Direct(t *testing.T) {
	pkg := mustParse(t, `{"name":"x","devDependencies":{"jest":"^29.0.0","lodash":"~4.17.15"}}`)
	msg, err := applyNpmChange(pkg, Request{Name: "lodash", TargetVersion: "4.17.21", Direct: true}, []string{"overrides"})
	if err != nil {
		t.Fatal(err)
	}
	if got := render(t, pkg); got != `{"name":"x","devDependencies":{"jest":"^29.0.0","lodash":"~4.17.21"}}` {
		t.Errorf("got %s", got)
	}
	if !strings.Contains(msg, "devDependencies") {
		t.Errorf("message should name the section: %s", msg)
	}
}

func TestApplyNpmChange_TransitiveAddsOverride(t *testing.T) {
	pkg := mustParse(t, `{"dependencies":{"mkdirp":"0.5.1"}}`)
	if _, err := applyNpmChange(pkg, Request{Name: "minimist", TargetVersion: "0.2.4"}, []string{"overrides"}); err != nil {
		t.Fatal(err)
	}
	if got := render(t, pkg); got != `{"dependencies":{"mkdirp":"0.5.1"},"overrides":{"minimist":"0.2.4"}}` {
		t.Errorf("got %s", got)
	}
}

func TestApplyNpmChange_DirectButNotDeclaredFallsBackToOverride(t *testing.T) {
	pkg := mustParse(t, `{"peerDependencies":{"react":"^18"}}`)
	if _, err := applyNpmChange(pkg, Request{Name: "react", TargetVersion: "18.3.1", Direct: true}, []string{"overrides"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(render(t, pkg), `"overrides":{"react":"18.3.1"}`) {
		t.Errorf("got %s", render(t, pkg))
	}
}

func TestApplyNpmChange_NestedOverride(t *testing.T) {
	pkg := mustParse(t, `{"overrides":{"foo":{"bar":"1.0.0"}}}`)
	if _, err := applyNpmChange(pkg, Request{Name: "foo", TargetVersion: "2.0.0"}, []string{"overrides"}); err != nil {
		t.Fatal(err)
	}
	if got := render(t, pkg); got != `{"overrides":{"foo":{"bar":"1.0.0",".":"2.0.0"}}}` {
		t.Errorf("got %s", got)
	}
}

func TestApplyNpmChange_UnsupportedSpec(t *testing.T) {
	pkg := mustParse(t, `{"dependencies":{"x":"file:../x"}}`)
	if _, err := applyNpmChange(pkg, Request{Name: "x", TargetVersion: "1.0.0", Direct: true}, []string{"overrides"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRenderPackageJSON_PreservesOrderIndentAndNewline(t *testing.T) {
	orig := "{\n    \"z\": 1,\n    \"a\": {\"k\": \"<v>\"}\n}\n"
	out, err := renderPackageJSON(mustParse(t, orig), []byte(orig))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n    \"z\": 1,\n    \"a\": {\n        \"k\": \"<v>\"\n    }\n}\n"
	if string(out) != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}

func TestParseOrdered_RejectsNonObject(t *testing.T) {
	if _, err := parseOrdered([]byte(`[1,2]`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestDetectIndent(t *testing.T) {
	cases := map[string]string{
		"{\n  \"a\": 1\n}":  "  ",
		"{\n\t\"a\": 1\n}":  "\t",
		"{\"a\": 1}":        "  ",
		"{\n\n    \"a\":1}": "    ",
	}
	for in, want := range cases {
		if got := detectIndent([]byte(in)); got != want {
			t.Errorf("detectIndent(%q) = %q want %q", in, got, want)
		}
	}
}

func TestApplyNpmChange_OverridePathForYarnAndPnpm(t *testing.T) {
	yarn := mustParse(t, `{"name":"x"}`)
	if _, err := applyNpmChange(yarn, Request{Name: "minimist", TargetVersion: "0.2.4"}, []string{"resolutions"}); err != nil {
		t.Fatal(err)
	}
	if got := render(t, yarn); got != `{"name":"x","resolutions":{"minimist":"0.2.4"}}` {
		t.Errorf("yarn: %s", got)
	}

	pnpm := mustParse(t, `{"pnpm":{"onlyBuiltDependencies":["esbuild"]}}`)
	msg, err := applyNpmChange(pnpm, Request{Name: "minimist", TargetVersion: "0.2.4"}, []string{"pnpm", "overrides"})
	if err != nil {
		t.Fatal(err)
	}
	if got := render(t, pnpm); got != `{"pnpm":{"onlyBuiltDependencies":["esbuild"],"overrides":{"minimist":"0.2.4"}}}` {
		t.Errorf("pnpm: %s", got)
	}
	if !strings.Contains(msg, "pnpm.overrides") {
		t.Errorf("message should name the field: %s", msg)
	}
}
