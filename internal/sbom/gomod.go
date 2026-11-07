package sbom

import (
	"os"

	"golang.org/x/mod/modfile"
)

func parseGoMod(absPath, relPath string) ([]Component, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	f, err := modfile.ParseLax(absPath, data, nil)
	if err != nil {
		return nil, err
	}
	// Respect replace directives that pin a different version of the same module.
	replaced := map[string]string{}
	for _, r := range f.Replace {
		if r.New.Version != "" && r.New.Path == r.Old.Path {
			replaced[r.Old.Path] = r.New.Version
		}
	}
	var out []Component
	for _, r := range f.Require {
		v := r.Mod.Version
		if rv, ok := replaced[r.Mod.Path]; ok {
			v = rv
		}
		out = append(out, Component{
			Name:      r.Mod.Path,
			Version:   v,
			Ecosystem: EcosystemGo,
			PURL:      makePURL(EcosystemGo, r.Mod.Path, v),
			Manifest:  relPath,
			Direct:    !r.Indirect,
		})
	}
	return out, nil
}
