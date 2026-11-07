package fixer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"sbomapp/internal/sbom"
	"sbomapp/internal/vuln"
)

func (fc *fixCtx) fixGo(g []Request) []Result {
	modPath := filepath.Join(fc.root, g[0].Manifest)
	dir := filepath.Dir(modPath)
	relDir, _ := filepath.Rel(fc.root, dir)
	fc.progress("Go 모듈 수정 중: " + relDir)
	bk := takeBackup(modPath, filepath.Join(dir, "go.sum"))
	goBefore := goDirective(bk[modPath])
	env := []string{"GOFLAGS=-mod=mod"}

	results := make([]Result, len(g))
	var ok []int
	for i, r := range g {
		results[i].Request = r
		target := r.TargetVersion
		if !strings.HasPrefix(target, "v") {
			target = "v" + target
		}
		if _, err := fc.run(dir, env, "go", "get", r.Name+"@"+target); err != nil {
			results[i].Message = "go get 실패 (명령 로그 참고)"
			continue
		}
		results[i].Message = fmt.Sprintf("go get %s@%s", r.Name, target)
		ok = append(ok, i)
	}
	if len(ok) == 0 {
		bk.restore()
		return results
	}
	if _, err := fc.run(dir, env, "go", "mod", "tidy"); err != nil {
		bk.restore()
		for _, i := range ok {
			results[i].Message = "go mod tidy 실패로 변경을 되돌렸습니다 (명령 로그 참고)"
		}
		return results
	}

	comps, perr := sbom.ScanFile(modPath, g[0].Manifest)
	for _, i := range ok {
		r := g[i]
		if perr != nil {
			results[i].Message += " (go.mod 검증 실패: " + perr.Error() + ")"
			continue
		}
		found := false
		for _, c := range comps {
			if c.Name == r.Name {
				found = true
				if vuln.CompareVersions(c.Version, r.TargetVersion) < 0 {
					results[i].Message += fmt.Sprintf(" — 하지만 go.mod에는 여전히 %s 입니다", c.Version)
				} else {
					results[i].Success = true
				}
			}
		}
		if !found { // removed by tidy => no longer a dependency
			results[i].Success = true
			results[i].Message += " (go mod tidy 후 더 이상 사용되지 않아 제거됨)"
		}
	}
	if now, err := os.ReadFile(modPath); err == nil {
		if goAfter := goDirective(now); goAfter != goBefore && len(ok) > 0 {
			results[ok[0]].Message += fmt.Sprintf(" ※ 새 버전이 요구하여 go.mod의 go 버전이 %s → %s 로 올라갔습니다", goBefore, goAfter)
		}
	}
	fc.recordChanged(bk)
	return results
}

func goDirective(data []byte) string {
	f, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil || f.Go == nil {
		return ""
	}
	return f.Go.Version
}
