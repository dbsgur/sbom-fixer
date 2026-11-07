package sbom

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// reqLine matches "name[extras] == version" (only exact pins can be checked).
var reqLine = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*===?\s*([^\s;#,]+)`)

// ParseRequirementLine returns name and pinned version of a requirements line.
func ParseRequirementLine(line string) (name, version string, ok bool) {
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	m := reqLine.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	return m[1], m[3], true
}

func parseRequirements(absPath, relPath string) ([]Component, []string, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var out []Component
	unpinned := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		name, ver, ok := ParseRequirementLine(line)
		if !ok {
			unpinned++
			continue
		}
		out = append(out, Component{
			Name:      NormalizePyPIName(name),
			Version:   ver,
			Ecosystem: EcosystemPyPI,
			PURL:      makePURL(EcosystemPyPI, name, ver),
			Manifest:  relPath,
			Direct:    true,
		})
	}
	var warns []string
	if unpinned > 0 {
		warns = append(warns, relPath+": '=='로 고정되지 않은 패키지 "+strconv.Itoa(unpinned)+"개는 버전을 알 수 없어 분석에서 제외되었습니다")
	}
	return out, warns, sc.Err()
}
