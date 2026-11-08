package fixer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sbomapp/internal/sbom"
)

// pyTool describes how poetry and uv are driven; the flow is shared.
type pyTool struct {
	name   string
	parser sbom.Parser
	// addDirect re-declares a direct dependency at the target version.
	addDirect func(req string, sectionArgs []string) []string
	// upgradeTransitive moves a transitive dependency within the existing
	// constraints of its parents.
	upgradeTransitive func(name, target string) []string
	// transitiveNote explains a transitive upgrade that did not reach target.
	transitiveNote string
}

var poetryTool = pyTool{
	name:   "poetry",
	parser: sbom.PoetryLockParser{},
	addDirect: func(req string, section []string) []string {
		return append([]string{"add", req, "--lock"}, section...)
	},
	// poetry has no override mechanism: update within the parents' ranges.
	upgradeTransitive: func(name, _ string) []string { return []string{"update", name, "--lock"} },
	transitiveNote:    "상위 패키지의 버전 제약 때문에 올리지 못했습니다. 이 패키지를 사용하는 상위 패키지를 먼저 수정하세요",
}

var uvTool = pyTool{
	name:   "uv",
	parser: sbom.UvLockParser{},
	addDirect: func(req string, section []string) []string {
		return append([]string{"add", req, "--no-sync"}, section...)
	},
	upgradeTransitive: func(name, target string) []string {
		return []string{"lock", "--upgrade-package", name + "==" + target}
	},
	transitiveNote: "상위 패키지의 버전 제약과 충돌합니다. 이 패키지를 사용하는 상위 패키지를 먼저 수정하세요",
}

// fixPyLock upgrades packages of a poetry/uv project. Direct dependencies are
// handled first so that their new versions can unlock transitive upgrades.
func fixPyLock(ws *Workspace, g []Request, tool pyTool) []Result {
	lockPath := ws.Abs(g[0].Manifest)
	dir := filepath.Dir(lockPath)
	pyprojectPath := filepath.Join(dir, "pyproject.toml")
	ws.Progress(tool.name + " 패키지 수정 중: " + ws.Rel(dir))

	pyproject, err := os.ReadFile(pyprojectPath)
	if err != nil {
		return failAll(g, "pyproject.toml을 읽을 수 없습니다: "+err.Error())
	}
	bk := ws.TakeBackup(pyprojectPath, lockPath)

	order := make([]int, len(g))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return g[order[a]].Direct && !g[order[b]].Direct })

	results := make([]Result, len(g))
	var ran []int
	for _, i := range order {
		r := g[i]
		results[i].Request = r
		args, how, err := pyCommand(tool, pyproject, r)
		if err != nil {
			results[i].Message = err.Error()
			continue
		}
		if _, err := ws.Run(dir, nil, tool.name, args...); err != nil {
			results[i].Message = tool.name + " 실행 실패 (명령 로그 참고)"
			if !r.Direct {
				results[i].Message += " — " + tool.transitiveNote
			}
			continue
		}
		results[i].Message = how
		ran = append(ran, i)
		if r.Direct { // later `add` calls must see the updated declarations
			if updated, err := os.ReadFile(pyprojectPath); err == nil {
				pyproject = updated
			}
		}
	}
	if len(ran) == 0 {
		bk.Restore()
		return results
	}

	lock, verr := tool.parser.Parse(lockPath, g[0].Manifest)
	for _, i := range ran {
		if verr != nil {
			results[i].Message += " (lock 파일 검증 실패: " + verr.Error() + ")"
			continue
		}
		if stale := staleVersions(lock.Components, g[i]); len(stale) > 0 {
			results[i].Message += fmt.Sprintf(" — 하지만 lock 파일에 여전히 %s %s 이(가) 남아 있습니다", g[i].Name, strings.Join(stale, ", "))
			if !g[i].Direct {
				results[i].Message += ". " + tool.transitiveNote
			}
			continue
		}
		results[i].Success = true
	}
	ws.RecordChanged(bk)
	return results
}

// pyCommand builds the tool arguments for one request and a description.
func pyCommand(tool pyTool, pyproject []byte, r Request) ([]string, string, error) {
	if !r.Direct {
		args := tool.upgradeTransitive(r.Name, r.TargetVersion)
		return args, fmt.Sprintf("간접 의존성: %s %s", tool.name, strings.Join(args, " ")), nil
	}
	decl, err := findPyDecl(pyproject, r.Name)
	if err != nil {
		return nil, "", err
	}
	if !decl.found {
		// Listed as direct by the lock but not in pyproject (e.g. a workspace
		// member's dependency): treat like a transitive upgrade.
		args := tool.upgradeTransitive(r.Name, r.TargetVersion)
		return args, fmt.Sprintf("%s %s", tool.name, strings.Join(args, " ")), nil
	}
	if decl.complex {
		return nil, "", fmt.Errorf("pyproject.toml에 표 형식({version=..., markers=...})으로 선언되어 있어 자동 수정하지 않습니다. 직접 %s 이상으로 수정하세요", r.TargetVersion)
	}
	req := decl.requirement(r.Name, r.TargetVersion)
	args := tool.addDirect(req, decl.args)
	where := "의존성"
	if len(decl.args) == 2 {
		where = decl.args[1] + " 그룹"
		if decl.args[0] == "--optional" {
			where = decl.args[1] + " extra"
		}
	}
	return args, fmt.Sprintf("%s 선언을 %q 로 변경 (%s %s)", where, req, tool.name, strings.Join(args, " ")), nil
}
