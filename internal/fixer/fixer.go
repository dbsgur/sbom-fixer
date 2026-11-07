// Package fixer upgrades vulnerable packages in a repository's manifests.
//
// Each ecosystem implements the Fixer interface; Service groups requests by
// manifest and dispatches them. External commands go through the Runner
// interface so fixers can be tested without npm/go installed.
package fixer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Request asks for one package to be moved to TargetVersion.
type Request struct {
	Ecosystem      string `json:"ecosystem"`
	Name           string `json:"name"`
	CurrentVersion string `json:"currentVersion"`
	TargetVersion  string `json:"targetVersion"`
	Manifest       string `json:"manifest"` // relative to root
	Direct         bool   `json:"direct"`
}

// Result is the outcome for one Request.
type Result struct {
	Request Request `json:"request"`
	Success bool    `json:"success"`
	Message string  `json:"message"`
}

// CommandLog records an external command run while fixing.
type CommandLog struct {
	Dir     string `json:"dir"`
	Command string `json:"command"`
	Output  string `json:"output"`
	Success bool   `json:"success"`
}

// Report is the outcome of Service.Apply.
type Report struct {
	Results      []Result     `json:"results"`
	Commands     []CommandLog `json:"commands"`
	ChangedFiles []string     `json:"changedFiles"`
}

// Fixer applies upgrades for one ecosystem. Fix receives every request that
// targets the same manifest and must return one Result per request.
type Fixer interface {
	Ecosystem() string
	Fix(ws *Workspace, reqs []Request) []Result
}

// Service dispatches requests to the registered Fixers.
type Service struct {
	fixers map[string]Fixer
	runner Runner
}

// NewService builds a Service with the given runner and fixers.
func NewService(runner Runner, fixers ...Fixer) *Service {
	s := &Service{fixers: map[string]Fixer{}, runner: runner}
	for _, f := range fixers {
		s.fixers[f.Ecosystem()] = f
	}
	return s
}

// DefaultService returns a Service with all built-in fixers using real commands.
func DefaultService() *Service {
	return NewService(ExecRunner{}, NpmFixer{}, GoFixer{}, PythonFixer{})
}

// Apply performs the requested upgrades.
func (s *Service) Apply(ctx context.Context, root string, reqs []Request, progress func(string)) *Report {
	ws := newWorkspace(ctx, root, s.runner, progress)
	rep := &Report{}

	var order []string
	groups := map[string][]Request{}
	for _, r := range reqs {
		if err := validate(root, r); err != nil {
			rep.Results = append(rep.Results, Result{Request: r, Message: err.Error()})
			continue
		}
		k := r.Ecosystem + "|" + r.Manifest
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}

	for _, k := range order {
		g := groups[k]
		f, ok := s.fixers[g[0].Ecosystem]
		if !ok {
			rep.Results = append(rep.Results, failAll(g, "지원하지 않는 생태계입니다: "+g[0].Ecosystem)...)
			continue
		}
		rep.Results = append(rep.Results, f.Fix(ws, g)...)
	}
	rep.Commands = ws.commands
	rep.ChangedFiles = ws.changed
	sort.Strings(rep.ChangedFiles)
	return rep
}

func validate(root string, r Request) error {
	if r.Name == "" || strings.HasPrefix(r.Name, "-") || strings.ContainsAny(r.Name, " \t\n") {
		return fmt.Errorf("잘못된 패키지 이름: %q", r.Name)
	}
	if r.TargetVersion == "" || strings.HasPrefix(r.TargetVersion, "-") || strings.ContainsAny(r.TargetVersion, " \t\n") {
		return fmt.Errorf("수정 가능한 버전이 없습니다")
	}
	abs := filepath.Join(root, r.Manifest)
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("매니페스트 경로가 프로젝트 밖에 있습니다: %s", r.Manifest)
	}
	if _, err := os.Stat(abs); err != nil {
		return fmt.Errorf("매니페스트를 찾을 수 없습니다: %s", r.Manifest)
	}
	return nil
}

func failAll(g []Request, msg string) []Result {
	out := make([]Result, len(g))
	for i, r := range g {
		out[i] = Result{Request: r, Message: msg}
	}
	return out
}
