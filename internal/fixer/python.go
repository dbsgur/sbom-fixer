package fixer

import (
	"os"
	"regexp"
	"strings"

	"sbomapp/internal/sbom"
)

// PythonFixer rewrites exact pins in requirements files.
type PythonFixer struct{}

func (PythonFixer) Ecosystem() string { return sbom.EcosystemPyPI }

func (PythonFixer) Fix(ws *Workspace, g []Request) []Result {
	path := ws.Abs(g[0].Manifest)
	ws.Progress("Python 의존성 수정 중: " + g[0].Manifest)
	orig, err := os.ReadFile(path)
	if err != nil {
		return failAll(g, "파일을 읽을 수 없습니다: "+err.Error())
	}
	bk := ws.TakeBackup(path)

	text := string(orig)
	results := make([]Result, len(g))
	for i, r := range g {
		results[i].Request = r
		var hit bool
		text, hit = replacePin(text, r.Name, r.CurrentVersion, r.TargetVersion)
		if hit {
			results[i].Success = true
			results[i].Message = r.Name + "==" + r.CurrentVersion + " → ==" + r.TargetVersion + " (가상환경에서 pip install -r 로 재설치하세요)"
		} else {
			results[i].Message = "해당 버전으로 고정된 줄을 찾지 못했습니다"
		}
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		bk.Restore()
		return failAll(g, "파일 저장 실패: "+err.Error())
	}
	ws.RecordChanged(bk)
	return results
}

var pinRe = regexp.MustCompile(`(===?\s*)([^\s;#,]+)`)

// replacePin rewrites "name==from" to "name==to" on every matching line,
// preserving extras, markers and comments.
func replacePin(text, name, from, to string) (string, bool) {
	want := sbom.NormalizePyPIName(name)
	lines := strings.Split(text, "\n")
	hit := false
	for i, line := range lines {
		n, v, ok := sbom.ParseRequirementLine(line)
		if !ok || sbom.NormalizePyPIName(n) != want || v != from {
			continue
		}
		loc := pinRe.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		lines[i] = line[:loc[4]] + to + line[loc[5]:]
		hit = true
	}
	return strings.Join(lines, "\n"), hit
}
