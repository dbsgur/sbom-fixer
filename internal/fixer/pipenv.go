package fixer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sbomapp/internal/sbom"
)

// pipenvEnv keeps pipenv non-interactive (no prompts, no spinner).
var pipenvEnv = []string{"PIPENV_YES=1", "PIPENV_NOSPIN=1"}

// pipenvUpgrade re-resolves one package in Pipfile.lock only. pipenv picks
// the newest version allowed by the Pipfile and the other locked packages
// (with --lock-only a "name==X" argument does not pin X), leaves the Pipfile
// untouched and keeps every unrelated pin, unlike `pipenv lock`, which
// re-resolves the whole lock.
func pipenvUpgrade(name string) []string { return []string{"upgrade", name, "--lock-only"} }

// fixPipenv upgrades packages of a pipenv project.
//
//   - Direct: the constraint in the Pipfile is rewritten in place (form,
//     extras and markers kept), then `pipenv upgrade <name> --lock-only`.
//   - Transitive: pipenv has no override mechanism, so only
//     `pipenv upgrade <name> --lock-only`, i.e. within the parents' ranges.
//     The Pipfile is not touched; a vulnerable version that stays locked is
//     reported instead of being forced by a new top-level declaration.
//
// Direct dependencies go first so that their new versions can unlock
// transitive upgrades.
func fixPipenv(ws *Workspace, g []Request) []Result {
	lockPath := ws.Abs(g[0].Manifest)
	dir := filepath.Dir(lockPath)
	pipfilePath := filepath.Join(dir, "Pipfile")
	ws.Progress("pipenv 패키지 수정 중: " + ws.Rel(dir))

	bk := ws.TakeBackup(pipfilePath, lockPath)
	if bk[pipfilePath] == nil {
		return failAll(g, "Pipfile을 찾을 수 없습니다")
	}
	decls, err := sbom.ParsePipfile(bk[pipfilePath])
	if err != nil {
		return failAll(g, "Pipfile 파싱 실패: "+err.Error())
	}
	text := string(bk[pipfilePath])

	results := make([]Result, len(g))
	var ran []int
	for _, i := range directFirst(g) {
		r := g[i]
		results[i].Request = r
		args := pipenvUpgrade(r.Name)
		cmd := "pipenv " + strings.Join(args, " ")
		how := "간접 의존성: " + cmd
		edited := text
		switch decl := findPyDecl(decls, r.Name); {
		case r.Direct && decl.found:
			newText, changes, err := pipfileUpgrade(text, decls, r.Name, r.TargetVersion)
			if err != nil {
				results[i].Message = err.Error()
				continue
			}
			if err := os.WriteFile(pipfilePath, []byte(newText), 0o644); err != nil {
				results[i].Message = "Pipfile 저장 실패: " + err.Error()
				continue
			}
			edited = newText
			how = fmt.Sprintf("Pipfile %s 선언을 %s(으)로 변경 (%s)", r.Name, strings.Join(changes, ", "), cmd)
		case r.Direct:
			how = cmd // marked direct but not in the Pipfile: upgrade within ranges
		}
		prevLock, _ := os.ReadFile(lockPath)
		if _, err := ws.Run(dir, pipenvEnv, "pipenv", args...); err != nil {
			results[i].Message = "pipenv 실행 실패 (명령 로그 참고)"
			if !r.Direct {
				results[i].Message += " — " + parentConstraintNote
			}
			// Undo this package only; earlier successful steps stay.
			_ = os.WriteFile(pipfilePath, []byte(text), 0o644)
			if prevLock != nil {
				_ = os.WriteFile(lockPath, prevLock, 0o644)
			}
			continue
		}
		text = edited
		results[i].Message = how
		ran = append(ran, i)
	}
	if len(ran) == 0 {
		bk.Restore()
		return results
	}
	verifyPyLock(sbom.PipfileLockParser{}, lockPath, g, ran, results, parentConstraintNote)
	ws.RecordChanged(bk)
	return results
}
