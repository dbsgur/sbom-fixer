package sbom

import (
	"os"

	"golang.org/x/mod/modfile"
)

// GoModParser reads go.mod require directives (honouring same-path replaces).
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
	return ParseResult{Components: c.out}, nil
}
