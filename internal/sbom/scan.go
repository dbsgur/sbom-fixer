package sbom

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// DefaultSkipDirs are directories never descended into.
var DefaultSkipDirs = map[string]bool{
	"node_modules": true, "vendor": true, "venv": true,
	"__pycache__": true, "site-packages": true,
}

// Result is the outcome of scanning a directory tree.
type Result struct {
	Components []Component `json:"components"`
	Manifests  []string    `json:"manifests"`
	Warnings   []string    `json:"warnings"`
}

// Scanner walks a directory tree and delegates each file to its Parser.
type Scanner struct {
	Parsers  []Parser
	SkipDirs map[string]bool
}

// NewScanner returns a scanner with all built-in parsers.
func NewScanner() *Scanner {
	return &Scanner{Parsers: DefaultParsers(), SkipDirs: DefaultSkipDirs}
}

func (s *Scanner) parserFor(name string) Parser {
	for _, p := range s.Parsers {
		if p.Match(name) {
			return p
		}
	}
	return nil
}

func (s *Scanner) skip(name string) bool {
	// Hidden directories (.git, .venv, .next, ...) are skipped too.
	return s.SkipDirs[name] || (len(name) > 1 && name[0] == '.')
}

// Scan walks root and parses every supported file it finds.
// progress (optional) receives human readable status lines.
func (s *Scanner) Scan(root string, progress func(string)) (*Result, error) {
	if progress == nil {
		progress = func(string) {}
	}
	res := &Result{}
	seen := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() && path != root {
				return fs.SkipDir // unreadable directory: skip, not fatal
			}
			return nil
		}
		if d.IsDir() {
			if path != root && s.skip(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		p := s.parserFor(d.Name())
		if p == nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if l := p.Label(); l != "" {
			progress(l + ": " + rel)
		}
		pr, perr := p.Parse(path, rel)
		if perr != nil {
			res.Warnings = append(res.Warnings, rel+": 파싱 실패 - "+perr.Error())
			return nil
		}
		res.Warnings = append(res.Warnings, pr.Warnings...)
		if len(pr.Components) > 0 {
			res.Manifests = append(res.Manifests, rel)
		}
		for _, c := range pr.Components {
			if !seen[c.Key()] {
				seen[c.Key()] = true
				res.Components = append(res.Components, c)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortComponents(res.Components)
	return res, nil
}

// ParseFile parses a single file with the matching parser.
func (s *Scanner) ParseFile(absPath, relPath string) ([]Component, error) {
	p := s.parserFor(filepath.Base(absPath))
	if p == nil {
		return nil, os.ErrInvalid
	}
	pr, err := p.Parse(absPath, relPath)
	return pr.Components, err
}

func sortComponents(cs []Component) {
	sort.Slice(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Manifest < b.Manifest
	})
}
