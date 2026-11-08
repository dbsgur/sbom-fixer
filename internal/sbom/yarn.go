package sbom

import (
	"bufio"
	"os"
	"strings"
)

// YarnLockParser reads yarn.lock files of both Yarn classic (v1) and
// Yarn berry (v2+). Both formats are "unindented key line + indented
// fields", so one line-based parser handles them:
//
//	classic:  "lodash@^4.17.0", lodash@^4.17.15:      berry:  "lodash@npm:^4.17.15":
//	            version "4.17.21"                               version: 4.17.21
type YarnLockParser struct{}

func (YarnLockParser) Match(name string) bool { return name == "yarn.lock" }
func (YarnLockParser) Label() string          { return "yarn 의존성 분석" }

func (YarnLockParser) Parse(absPath, relPath string) (ParseResult, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return ParseResult{}, err
	}
	defer f.Close()

	decl := readNpmDeclared(absPath)
	c := newCollector(EcosystemNpm, relPath)

	var name string // package of the entry being read ("" = skip entry)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] != ' ' { // entry key
			name = yarnEntryName(strings.TrimSuffix(strings.TrimSpace(line), ":"))
			continue
		}
		if name == "" {
			continue
		}
		if v, ok := yarnVersion(line); ok {
			c.add(name, v, decl.direct[name], decl.dev[name])
			name = ""
		}
	}
	return ParseResult{Components: c.out}, sc.Err()
}

// yarnEntryName extracts the package name from an entry key such as
// `"@babel/core@^7.0.0", "@babel/core@^7.1.0"` or `"lodash@npm:^4.17.15"`.
// Returns "" for metadata, workspace, link and patch entries.
func yarnEntryName(key string) string {
	first := strings.TrimSpace(strings.SplitN(key, ",", 2)[0])
	first = strings.Trim(first, `"`)
	if first == "__metadata" {
		return ""
	}
	// Package names never contain '@' except a leading scope, so the
	// separator is the first '@' after position 0. (Specs can contain more,
	// e.g. "fsevents@patch:fsevents@npm%3A2.3.3#...".)
	at := strings.IndexByte(first[min(1, len(first)):], '@') + 1
	if at <= 0 { // no version part (or only a scope '@')
		return ""
	}
	name, spec := first[:at], first[at+1:]
	// Protocols that do not point at a registry release.
	for _, p := range []string{"workspace:", "link:", "portal:", "file:", "patch:", "exec:"} {
		if strings.HasPrefix(spec, p) || strings.HasPrefix(name, p) {
			return ""
		}
	}
	return name
}

// yarnVersion parses `  version "1.2.3"` (classic) or `  version: 1.2.3` (berry).
func yarnVersion(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "version") {
		return "", false
	}
	v := strings.TrimSpace(strings.TrimPrefix(t, "version"))
	v = strings.TrimSpace(strings.TrimPrefix(v, ":"))
	v = strings.Trim(v, `"`)
	if v == "" || strings.HasSuffix(v, "-use.local") {
		return "", false
	}
	return v, true
}
