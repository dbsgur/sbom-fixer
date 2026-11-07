package sbom

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// RequirementsParser reads pip requirements*.txt files. Only exact pins
// ("==" / "===") have a known version and are reported.
type RequirementsParser struct{}

var requirementsFile = regexp.MustCompile(`^requirements.*\.txt$`)

func (RequirementsParser) Match(name string) bool { return requirementsFile.MatchString(name) }
func (RequirementsParser) Label() string          { return "Python 의존성 분석" }

// reqLine matches "name[extras] == version".
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

func (RequirementsParser) Parse(absPath, relPath string) (ParseResult, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return ParseResult{}, err
	}
	defer f.Close()

	c := newCollector(EcosystemPyPI, relPath)
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
		c.add(NormalizePyPIName(name), ver, true, false)
	}
	res := ParseResult{Components: c.out}
	if unpinned > 0 {
		res.Warnings = append(res.Warnings, relPath+": '=='로 고정되지 않은 패키지 "+strconv.Itoa(unpinned)+"개는 버전을 알 수 없어 분석에서 제외되었습니다")
	}
	return res, sc.Err()
}
