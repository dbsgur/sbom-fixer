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

// GoFixer runs `go get module@version` followed by `go mod tidy`.
type GoFixer struct{}

func (GoFixer) Ecosystem() string { return sbom.EcosystemGo }

func (GoFixer) Fix(ws *Workspace, g []Request) []Result {
	modPath := ws.Abs(g[0].Manifest)
	dir := filepath.Dir(modPath)
	ws.Progress("Go 모듈 수정 중: " + ws.Rel(dir))
	bk := ws.TakeBackup(modPath, filepath.Join(dir, "go.sum"))
	goBefore := goDirective(bk[modPath])
	env := []string{"GOFLAGS=-mod=mod"}

	results := make([]Result, len(g))
	var ok []int
	for i, r := range g {
		results[i].Request = r
		target := goVersion(r.TargetVersion)
		if _, err := ws.Run(dir, env, "go", "get", r.Name+"@"+target); err != nil {
			results[i].Message = "go get 실패 (명령 로그 참고)"
			continue
		}
		results[i].Message = fmt.Sprintf("go get %s@%s", r.Name, target)
		ok = append(ok, i)
	}
	if len(ok) == 0 {
		bk.Restore()
		return results
	}
	if _, err := ws.Run(dir, env, "go", "mod", "tidy"); err != nil {
		bk.Restore()
		for _, i := range ok {
			results[i].Message = "go mod tidy 실패로 변경을 되돌렸습니다 (명령 로그 참고)"
		}
		return results
	}

	mod, verr := sbom.GoModParser{}.Parse(modPath, g[0].Manifest)
	for _, i := range ok {
		if verr != nil {
			results[i].Message += " (go.mod 검증 실패: " + verr.Error() + ")"
			continue
		}
		results[i].Success, results[i].Message = verifyGoModule(mod.Components, g[i], results[i].Message)
	}
	if now, err := os.ReadFile(modPath); err == nil {
		if goAfter := goDirective(now); goAfter != goBefore {
			results[ok[0]].Message += fmt.Sprintf(" ※ 새 버전이 요구하여 go.mod의 go 버전이 %s → %s 로 올라갔습니다", goBefore, goAfter)
		}
	}
	ws.RecordChanged(bk)
	return results
}

func goVersion(v string) string {
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// verifyGoModule checks go.mod now requires at least the target version.
func verifyGoModule(comps []sbom.Component, r Request, msg string) (bool, string) {
	for _, c := range comps {
		if c.Name != r.Name {
			continue
		}
		if vuln.CompareVersions(c.Version, r.TargetVersion) < 0 {
			return false, msg + fmt.Sprintf(" — 하지만 go.mod에는 여전히 %s 입니다", c.Version)
		}
		return true, msg
	}
	return true, msg + " (go mod tidy 후 더 이상 사용되지 않아 제거됨)"
}

func goDirective(data []byte) string {
	f, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil || f.Go == nil {
		return ""
	}
	return f.Go.Version
}
