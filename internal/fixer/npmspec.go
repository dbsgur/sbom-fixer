package fixer

import (
	"bytes"
	"fmt"
	"strings"
)

// Pure package.json editing logic, kept free of I/O so it is easy to test.

var depSections = []string{"dependencies", "devDependencies", "optionalDependencies"}

// newSpec keeps the range style of the existing spec while raising its floor.
func newSpec(old, target string) (string, error) {
	s := strings.TrimSpace(old)
	for _, p := range []string{"npm:", "file:", "link:", "workspace:", "git", "http:", "https:", "github:"} {
		if strings.HasPrefix(s, p) {
			return "", fmt.Errorf("버전 지정 방식(%s)은 자동 수정할 수 없습니다", s)
		}
	}
	switch {
	case strings.HasPrefix(s, "^"), strings.HasPrefix(s, "~"):
		return s[:1] + target, nil
	case strings.HasPrefix(s, ">="):
		return ">=" + target, nil
	case s != "" && s[0] >= '0' && s[0] <= '9' && !strings.ContainsAny(s, " |<>xX*"):
		return target, nil // exact pin stays exact
	}
	return "^" + target, nil
}

// applyNpmChange edits the parsed package.json for one request and returns a
// human readable description of the change.
func applyNpmChange(pkg *orderedObject, r Request) (string, error) {
	if r.Direct {
		for _, sec := range depSections {
			deps, err := pkg.child(sec)
			if err != nil {
				return "", fmt.Errorf("%s 파싱 실패: %w", sec, err)
			}
			old, ok := deps.getString(r.Name)
			if !ok {
				continue
			}
			spec, err := newSpec(old, r.TargetVersion)
			if err != nil {
				return "", err
			}
			deps.setString(r.Name, spec)
			if err := pkg.setChild(sec, deps); err != nil {
				return "", err
			}
			return fmt.Sprintf("%s의 버전을 %q → %q 로 변경", sec, old, spec), nil
		}
	}
	// Transitive (or not declared directly): force the version via overrides.
	ov, err := pkg.child("overrides")
	if err != nil {
		return "", fmt.Errorf("overrides 파싱 실패: %w", err)
	}
	if raw, ok := ov.values[r.Name]; ok && bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		nested, err := ov.child(r.Name)
		if err != nil {
			return "", err
		}
		nested.setString(".", r.TargetVersion)
		if err := ov.setChild(r.Name, nested); err != nil {
			return "", err
		}
	} else {
		ov.setString(r.Name, r.TargetVersion)
	}
	if err := pkg.setChild("overrides", ov); err != nil {
		return "", err
	}
	return fmt.Sprintf("간접 의존성이므로 package.json overrides에 %q: %q 추가", r.Name, r.TargetVersion), nil
}

// renderPackageJSON serialises pkg using the original file's indentation and
// trailing newline.
func renderPackageJSON(pkg *orderedObject, original []byte) ([]byte, error) {
	out, err := pkg.marshalIndent(detectIndent(original))
	if err != nil {
		return nil, err
	}
	if bytes.HasSuffix(original, []byte("\n")) {
		out = append(out, '\n')
	}
	return out, nil
}
