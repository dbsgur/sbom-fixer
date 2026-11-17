package sbom

import (
	"os"
	"regexp"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// GoStdlib is the OSV package name for the Go standard library (and the go
// command), whose vulnerabilities are tracked under the Go ecosystem.
const GoStdlib = "stdlib"

// GoModParser reads go.mod require directives (honouring same-path replaces)
// and reports the Go standard library at the version go.mod asks for.
type GoModParser struct{}

func (GoModParser) Match(name string) bool { return name == "go.mod" }
func (GoModParser) Label() string          { return "Go 모듈 분석" }

func (GoModParser) Parse(absPath, relPath string) (ParseResult, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ParseResult{}, err
	}
	f, err := modfile.Parse(absPath, data, nil) // Parse (not ParseLax): ParseLax drops replace directives
	if err != nil {
		return ParseResult{}, err
	}
	replaced := map[string]string{}
	for _, r := range f.Replace {
		if r.New.Version != "" && r.New.Path == r.Old.Path {
			replaced[r.Old.Path] = r.New.Version
		}
	}
	c := newCollector(EcosystemGo, relPath)
	for _, r := range f.Require {
		v := r.Mod.Version
		if rv, ok := replaced[r.Mod.Path]; ok {
			v = rv
		}
		c.add(r.Mod.Path, v, !r.Indirect, false)
	}
	if v := GoStdlibVersion(f); v != "" {
		c.add(GoStdlib, v, true, false)
	}
	return ParseResult{Components: c.out}, nil
}

var goVersionRe = regexp.MustCompile(`^(?:go)?(\d+)\.(\d+)(?:\.(\d+))?(?:(rc|beta)(\d+))?$`)

// GoStdlibVersion returns the Go release go.mod selects as a module-style
// version ("v1.22.3"): the toolchain directive if it is newer than the go
// directive, else the go directive. "" when neither is present.
func GoStdlibVersion(f *modfile.File) string {
	var best string
	if f.Go != nil {
		best = normalizeGoRelease(f.Go.Version)
	}
	if f.Toolchain != nil {
		if t := normalizeGoRelease(f.Toolchain.Name); t != "" && (best == "" || semver.Compare(best, t) < 0) {
			best = t
		}
	}
	return best
}

// normalizeGoRelease turns "1.22", "1.22.3", "go1.21rc2" into semver
// ("v1.22.0", "v1.22.3", "v1.21.0-rc.2"). Unknown forms give "".
func normalizeGoRelease(s string) string {
	m := goVersionRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ""
	}
	patch := m[3]
	if patch == "" {
		patch = "0"
	}
	v := "v" + m[1] + "." + m[2] + "." + patch
	if m[4] != "" {
		v += "-" + m[4] + "." + m[5]
	}
	return v
}
