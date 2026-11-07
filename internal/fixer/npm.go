package fixer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sbomapp/internal/sbom"
	"sbomapp/internal/vuln"
)

// NpmFixer edits package.json (direct deps or overrides) and regenerates
// package-lock.json with `npm install --package-lock-only`.
type NpmFixer struct{}

func (NpmFixer) Ecosystem() string { return sbom.EcosystemNpm }

func (NpmFixer) Fix(ws *Workspace, g []Request) []Result {
	lockPath := ws.Abs(g[0].Manifest)
	dir := filepath.Dir(lockPath)
	pkgPath := filepath.Join(dir, "package.json")
	ws.Progress("npm 패키지 수정 중: " + ws.Rel(dir))

	orig, err := os.ReadFile(pkgPath)
	if err != nil {
		return failAll(g, "package.json을 읽을 수 없습니다: "+err.Error())
	}
	pkg, err := parseOrdered(orig)
	if err != nil {
		return failAll(g, "package.json 파싱 실패: "+err.Error())
	}
	bk := ws.TakeBackup(pkgPath, lockPath)

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

	data, err := renderPackageJSON(pkg, orig)
	if err == nil {
		err = os.WriteFile(pkgPath, data, 0o644)
	}
	if err != nil {
		bk.Restore()
		return failAll(g, "package.json 저장 실패: "+err.Error())
	}

	if _, err := ws.Run(dir, nil, "npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"); err != nil {
		bk.Restore()
		for _, i := range applied {
			results[i].Message = "npm install 실패로 변경을 되돌렸습니다 (명령 로그 참고)"
		}
		return results
	}

	lock, verr := sbom.NpmLockParser{}.Parse(lockPath, g[0].Manifest)
	for _, i := range applied {
		if verr != nil {
			results[i].Message += " (lock 파일 검증 실패: " + verr.Error() + ")"
			continue
		}
		if stale := staleVersions(lock.Components, g[i]); len(stale) > 0 {
			results[i].Message += fmt.Sprintf(" — 하지만 lock 파일에 여전히 %s@%s 이(가) 남아 있습니다", g[i].Name, strings.Join(stale, ", "))
			continue
		}
		results[i].Success = true
	}
	ws.RecordChanged(bk)
	return results
}

// staleVersions lists versions of r.Name still below the target within the
// same major line (other majors are separate dependency trees).
func staleVersions(comps []sbom.Component, r Request) []string {
	var stale []string
	for _, c := range comps {
		if c.Name == r.Name && vuln.CompareVersions(c.Version, r.TargetVersion) < 0 &&
			vuln.MajorOf(c.Version) == vuln.MajorOf(r.CurrentVersion) {
			stale = append(stale, c.Version)
		}
	}
	return stale
}
