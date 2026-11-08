package fixer

import (
	"fmt"
	"strings"

	"sbomapp/internal/sbom"
	"sbomapp/internal/vuln"
)

// Pure helpers that decide how to re-declare a Python dependency with
// `poetry add` / `uv add` without losing its section, extras or markers.

// pyDecl is where and how a dependency is declared in pyproject.toml.
type pyDecl struct {
	sbom.PyRequirement
	found bool
}

// findPyDecl locates a dependency among the parsed declarations.
// Production sections come first, so a package declared in both stays there.
func findPyDecl(reqs []sbom.PyRequirement, name string) pyDecl {
	want := sbom.NormalizePyPIName(name)
	for _, r := range reqs {
		if r.Name == want {
			return pyDecl{PyRequirement: r, found: true}
		}
	}
	return pyDecl{}
}

// sectionArgs selects the same section for `poetry add` / `uv add`.
func (d pyDecl) sectionArgs() ([]string, error) {
	switch d.Kind {
	case sbom.PyOptional:
		return []string{"--optional", d.Section}, nil
	case sbom.PyGroup:
		return []string{"--group", d.Section}, nil
	case sbom.PyPoetryGroup:
		if d.Section == "main" {
			return nil, nil
		}
		return []string{"--group", d.Section}, nil
	case sbom.PyUvLegacyDev:
		return []string{"--dev"}, nil // uv updates [tool.uv] dev-dependencies in place
	case sbom.PyPoetryLegacyDev:
		return nil, fmt.Errorf("구버전 [tool.poetry.dev-dependencies] 섹션에 선언되어 있어 자동 수정하지 않습니다 (poetry add가 새 그룹에 중복 선언을 만듭니다). [tool.poetry.group.dev.dependencies]로 옮긴 뒤 다시 시도하세요")
	}
	return nil, nil
}

// newPySpec rewrites a version constraint so it requires at least target
// while keeping the rest of its meaning:
//
//	==X / ===X / bare X (Poetry) → exact pin on target
//	^X / ~X (Poetry)             → same operator on target
//	>=, > clauses                → replaced by >=target
//	<, <=, != clauses            → kept (error if they exclude target)
//	~=X                          → >=target plus its original upper bound
//
// URL references and wildcards are refused rather than guessed.
func newPySpec(old, target string) (string, error) {
	s := strings.TrimSpace(old)
	switch {
	case strings.HasPrefix(s, "@"):
		return "", fmt.Errorf("URL·경로로 지정된 의존성(%s)은 자동 수정하지 않습니다", s)
	case s == "" || s == "*":
		return ">=" + target, nil
	case strings.HasPrefix(s, "^"), strings.HasPrefix(s, "~") && !strings.HasPrefix(s, "~="):
		return s[:1] + target, nil
	case s[0] >= '0' && s[0] <= '9' && !strings.ContainsAny(s, ",<>=!~*"):
		return "==" + target, nil // bare version = exact pin (Poetry)
	}

	var kept []string
	for _, clause := range strings.Split(s, ",") {
		c := strings.TrimSpace(clause)
		op, v := splitPyOp(c)
		switch {
		case op == "":
			return "", fmt.Errorf("버전 제약 %q을(를) 해석할 수 없어 자동 수정하지 않습니다", s)
		case strings.Contains(v, "*"):
			return "", fmt.Errorf("와일드카드 제약(%s)은 자동 수정하지 않습니다", c)
		case op == "==" || op == "===":
			return op + target, nil
		case op == ">=" || op == ">":
			// replaced by the new lower bound
		case op == "~=":
			kept = append(kept, "<"+compatibleUpper(v, target))
		case op == "<" && vuln.CompareVersions(target, v) >= 0,
			op == "<=" && vuln.CompareVersions(target, v) > 0:
			return "", fmt.Errorf("상한 제약(%s) 때문에 %s(으)로 올릴 수 없습니다. 상한을 직접 조정하세요", c, target)
		case op == "!=" && vuln.CompareVersions(target, v) == 0:
			return "", fmt.Errorf("제외 제약(%s)이 수정 버전 %s을(를) 막고 있습니다", c, target)
		default: // <, <=, != that still allow target
			kept = append(kept, op+v)
		}
	}
	return strings.Join(append([]string{">=" + target}, kept...), ","), nil
}

var pyOps = []string{"===", "==", "~=", "!=", ">=", "<=", ">", "<"}

func splitPyOp(clause string) (op, version string) {
	for _, o := range pyOps {
		if strings.HasPrefix(clause, o) {
			v := strings.TrimSpace(clause[len(o):])
			if v == "" || strings.ContainsAny(v, "<>=!~") {
				return "", ""
			}
			return o, v
		}
	}
	return "", ""
}

// compatibleUpper is the exclusive upper bound of "~=v" (PEP 440: drop the
// last release segment, bump the one before). If target is already past it,
// the same precision is re-anchored on target.
func compatibleUpper(v, target string) string {
	upper := bumpPrefix(v, v)
	if vuln.CompareVersions(target, upper) >= 0 {
		upper = bumpPrefix(v, target)
	}
	return upper
}

// bumpPrefix takes as many release segments from base as "~=spec" fixes
// (all but the last) and increments the last of them: (~=2.19, 2.19) → 3.
func bumpPrefix(spec, base string) string {
	n := len(releaseSegments(spec)) - 1
	segs := releaseSegments(base)
	if n < 1 {
		n = 1
	}
	for len(segs) < n {
		segs = append(segs, "0")
	}
	segs = segs[:n]
	last := 0
	fmt.Sscanf(segs[n-1], "%d", &last)
	segs[n-1] = fmt.Sprint(last + 1)
	return strings.Join(segs, ".")
}

// releaseSegments returns the numeric release part: "2.19.0rc1" → [2 19 0].
func releaseSegments(v string) []string {
	var out []string
	notDigit := func(r rune) bool { return r < '0' || r > '9' }
	for _, p := range strings.Split(strings.TrimPrefix(v, "v"), ".") {
		if i := strings.IndexFunc(p, notDigit); i >= 0 {
			p = p[:i] // "0rc1" → "0"
		}
		if p == "" {
			break
		}
		out = append(out, p)
	}
	return out
}

// requirement renders the new declaration for poetry/uv add:
// "name[extras]<spec> ; marker", or "name[extras]@^x" for Poetry's caret
// and tilde operators (the form every Poetry version accepts).
func (d pyDecl) requirement(name, target string) (string, error) {
	if d.URL {
		return "", fmt.Errorf("URL·경로로 지정된 의존성은 자동 수정하지 않습니다")
	}
	spec, err := newPySpec(d.Spec, target)
	if err != nil {
		return "", err
	}
	r := name + d.Extras
	if strings.HasPrefix(spec, "^") || (strings.HasPrefix(spec, "~") && !strings.HasPrefix(spec, "~=")) {
		r += "@" + spec
	} else {
		r += spec
	}
	if d.Marker != "" {
		r += " " + d.Marker
	}
	return r, nil
}
