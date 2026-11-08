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
// human readable description of the change. Direct dependencies get their
// range raised; anything else is forced via the object at overridePath
// (e.g. ["overrides"] for npm, ["resolutions"] for yarn, ["pnpm","overrides"]).
func applyNpmChange(pkg *orderedObject, r Request, overridePath []string) (string, error) {
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
	// Transitive (or not declared directly): force the version.
	err := updateAt(pkg, overridePath, func(ov *orderedObject) error {
		raw, ok := ov.values[r.Name]
		if !ok || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
			ov.setString(r.Name, r.TargetVersion)
			return nil
		}
		// npm nested override object: {"pkg": {".": "1.2.3", "child": "..."}}
		return updateAt(ov, []string{r.Name}, func(nested *orderedObject) error {
			nested.setString(".", r.TargetVersion)
			return nil
		})
	})
	if err != nil {
		return "", fmt.Errorf("%s 수정 실패: %w", strings.Join(overridePath, "."), err)
	}
	return fmt.Sprintf("간접 의존성이므로 package.json %s에 %q: %q 추가", strings.Join(overridePath, "."), r.Name, r.TargetVersion), nil
}

// updateAt applies fn to the object at path (creating missing levels) and
// writes every level back into its parent.
func updateAt(obj *orderedObject, path []string, fn func(*orderedObject) error) error {
	if len(path) == 0 {
		return fn(obj)
	}
	child, err := obj.child(path[0])
	if err != nil {
		return err
	}
	if err := updateAt(child, path[1:], fn); err != nil {
		return err
	}
	return obj.setChild(path[0], child)
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
