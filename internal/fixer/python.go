package fixer

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"sbomapp/internal/sbom"
)

var pinRe = regexp.MustCompile(`(===?\s*)([^\s;#,]+)`)

func (fc *fixCtx) fixPython(g []Request) []Result {
	path := filepath.Join(fc.root, g[0].Manifest)
	fc.progress("Python 의존성 수정 중: " + g[0].Manifest)
	orig, err := os.ReadFile(path)
	if err != nil {
		return failAll(g, "파일을 읽을 수 없습니다: "+err.Error())
	}
	bk := takeBackup(path)

	lines := strings.Split(string(orig), "\n")
	results := make([]Result, len(g))
	for i, r := range g {
		results[i].Request = r
		hit := false
		for li, line := range lines {
			name, ver, ok := sbom.ParseRequirementLine(line)
			if !ok || sbom.NormalizePyPIName(name) != sbom.NormalizePyPIName(r.Name) || ver != r.CurrentVersion {
				continue
			}
			loc := pinRe.FindStringSubmatchIndex(line)
			if loc == nil {
				continue
			}
			lines[li] = line[:loc[4]] + r.TargetVersion + line[loc[5]:]
			hit = true
		}
		if hit {
			results[i].Success = true
			results[i].Message = r.Name + "==" + r.CurrentVersion + " → ==" + r.TargetVersion + " (가상환경에서 pip install -r 로 재설치하세요)"
		} else {
			results[i].Message = "해당 버전으로 고정된 줄을 찾지 못했습니다"
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		bk.restore()
		return failAll(g, "파일 저장 실패: "+err.Error())
	}
	fc.recordChanged(bk)
	return results
}
