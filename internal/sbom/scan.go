package sbom

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, ".next": true, ".idea": true, ".vscode": true, "site-packages": true,
}

var requirementsFile = regexp.MustCompile(`^requirements.*\.txt$`)

// Result is the outcome of scanning a directory tree.
type Result struct {
	Components []Component `json:"components"`
	Manifests  []string    `json:"manifests"`
	Warnings   []string    `json:"warnings"`
}

// Scan walks root and parses every supported manifest it finds.
// progress (optional) is called with a human readable status line.
func Scan(root string, progress func(string)) (*Result, error) {
	if progress == nil {
		progress = func(string) {}
	}
	res := &Result{}
	seen := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable directories are skipped, not fatal.
			if d != nil && d.IsDir() && path != root {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || (len(d.Name()) > 1 && d.Name()[0] == '.')) {
				return fs.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		name := d.Name()

		var comps []Component
		var warns []string
		var perr error
		switch {
		case name == "package-lock.json":
			progress("npm 의존성 분석: " + rel)
			comps, perr = parseNpmLock(path, rel)
		case name == "package.json":
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), "package-lock.json")); err != nil {
				warns = append(warns, rel+": package-lock.json이 없어 npm 의존성을 분석하지 못했습니다 (npm install 후 다시 스캔하세요. yarn/pnpm은 아직 지원하지 않습니다)")
			}
		case name == "go.mod":
			progress("Go 모듈 분석: " + rel)
			comps, perr = parseGoMod(path, rel)
		case requirementsFile.MatchString(name):
			progress("Python 의존성 분석: " + rel)
			comps, warns, perr = parseRequirements(path, rel)
		default:
			return nil
		}
		if perr != nil {
			res.Warnings = append(res.Warnings, rel+": 파싱 실패 - "+perr.Error())
			return nil
		}
		res.Warnings = append(res.Warnings, warns...)
		if name != "package.json" {
			res.Manifests = append(res.Manifests, rel)
		}
		for _, c := range comps {
			if seen[c.Key()] {
				continue
			}
			seen[c.Key()] = true
			res.Components = append(res.Components, c)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(res.Components, func(i, j int) bool {
		a, b := res.Components[i], res.Components[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Manifest < b.Manifest
	})
	return res, nil
}

// ScanFile parses a single manifest file (used to verify a fix).
func ScanFile(absPath, relPath string) ([]Component, error) {
	switch name := filepath.Base(absPath); {
	case name == "package-lock.json":
		return parseNpmLock(absPath, relPath)
	case name == "go.mod":
		return parseGoMod(absPath, relPath)
	case requirementsFile.MatchString(name):
		c, _, err := parseRequirements(absPath, relPath)
		return c, err
	}
	return nil, os.ErrInvalid
}
