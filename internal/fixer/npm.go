package fixer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sbomapp/internal/sbom"
	"sbomapp/internal/vuln"
)

var depSections = []string{"dependencies", "devDependencies", "optionalDependencies"}

// newSpec keeps the range style of the existing spec while raising the floor.
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

func (fc *fixCtx) fixNpm(g []Request) []Result {
	lockPath := filepath.Join(fc.root, g[0].Manifest)
	dir := filepath.Dir(lockPath)
	pkgPath := filepath.Join(dir, "package.json")
	relDir, _ := filepath.Rel(fc.root, dir)
	fc.progress("npm 패키지 수정 중: " + relDir)

	orig, err := os.ReadFile(pkgPath)
	if err != nil {
		return failAll(g, "package.json을 읽을 수 없습니다: "+err.Error())
	}
	pkg, err := parseOrdered(orig)
	if err != nil {
		return failAll(g, "package.json 파싱 실패: "+err.Error())
	}
	bk := takeBackup(pkgPath, lockPath)

	results := make([]Result, len(g))
	var applied []int
	for i, r := range g {
		results[i].Request = r
		how, err := applyNpmChange(pkg, r)
		if err != nil {
			results[i].Message = err.Error()
			continue
		}
		results[i].Message = how
		applied = append(applied, i)
	}
	if len(applied) == 0 {
		return results
	}

	newData, err := pkg.marshalIndent(detectIndent(orig))
	if err != nil {
		return failAll(g, "package.json 생성 실패: "+err.Error())
	}
	if bytes.HasSuffix(orig, []byte("\n")) {
		newData = append(newData, '\n')
	}
	if err := os.WriteFile(pkgPath, newData, 0o644); err != nil {
		return failAll(g, "package.json 저장 실패: "+err.Error())
	}

	if _, err := fc.run(dir, nil, "npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"); err != nil {
		bk.restore()
		for _, i := range applied {
			results[i].Message = "npm install 실패로 변경을 되돌렸습니다 (명령 로그 참고)"
		}
		return results
	}

	// Verify against the regenerated lock file.
	comps, perr := sbom.ScanFile(lockPath, g[0].Manifest)
	for _, i := range applied {
		r := g[i]
		if perr != nil {
			results[i].Message += " (lock 파일 검증 실패: " + perr.Error() + ")"
			continue
		}
		var stale []string
		for _, c := range comps {
			if c.Name == r.Name && vuln.CompareVersions(c.Version, r.TargetVersion) < 0 &&
				vuln.MajorOf(c.Version) == vuln.MajorOf(r.CurrentVersion) {
				stale = append(stale, c.Version)
			}
		}
		if len(stale) > 0 {
			results[i].Message += fmt.Sprintf(" — 하지만 lock 파일에 여전히 %s@%s 이(가) 남아 있습니다", r.Name, strings.Join(stale, ", "))
			continue
		}
		results[i].Success = true
	}
	fc.recordChanged(bk)
	return results
}

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
	if raw, ok := ov.values[r.Name]; ok && len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '{' {
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
