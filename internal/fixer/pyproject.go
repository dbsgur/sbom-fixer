package fixer

import (
	"fmt"
	"strings"

	"sbomapp/internal/sbom"
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

// newPySpec keeps the constraint style of the old spec while moving it to
// target: ==, ~=, ^ and ~ (poetry) are kept; anything else becomes >=.
func newPySpec(old, target string) string {
	s := strings.TrimSpace(old)
	for _, op := range []string{"===", "==", "~=", "^", "~"} {
		if strings.HasPrefix(s, op) {
			return op + target
		}
	}
	// A bare version in poetry ("2.19.0") is an exact pin.
	if s != "" && s[0] >= '0' && s[0] <= '9' && !strings.ContainsAny(s, ",<>*") {
		return "==" + target
	}
	return ">=" + target
}

// requirement renders "name[extras]<spec>; marker" for poetry/uv add.
func (d pyDecl) requirement(name, target string) string {
	r := name + d.Extras + newPySpec(d.Spec, target)
	if d.Marker != "" {
		r += " " + d.Marker
	}
	return r
}
