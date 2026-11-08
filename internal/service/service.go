// Package service orchestrates scan → vulnerability check → fix. It knows
// nothing about Wails, so the whole workflow can be unit-tested with fakes;
// the Wails App in package main is a thin adapter over it.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sbomapp/internal/fixer"
	"sbomapp/internal/sbom"
	"sbomapp/internal/vuln"
)

// Dependencies (satisfied by the real packages, replaceable in tests).
type (
	Scanner interface {
		Scan(root string, progress func(string)) (*sbom.Result, error)
	}
	Checker interface {
		Check(ctx context.Context, comps []sbom.Component, progress func(string)) ([]vuln.Finding, error)
	}
	Fixer interface {
		Apply(ctx context.Context, root string, reqs []fixer.Request, progress func(string)) *fixer.Report
	}
	GitInspector interface {
		Status(dir string, files []string) (isRepo bool, dirty []string)
	}
)

// ScanReport is what the UI shows after analysing a repository.
type ScanReport struct {
	Root       string           `json:"root"`
	Components []sbom.Component `json:"components"`
	Findings   []vuln.Finding   `json:"findings"`
	Manifests  []string         `json:"manifests"`
	Warnings   []string         `json:"warnings"`
	Ecosystems map[string]int   `json:"ecosystems"`
	Severities map[string]int   `json:"severities"`
	GitRepo    bool             `json:"gitRepo"`
	GitDirty   []string         `json:"gitDirty"`
	ScannedAt  string           `json:"scannedAt"`
	DurationMs int64            `json:"durationMs"`
}

// FixReport is returned after applying fixes; Rescan is the fresh analysis
// (nil if the rescan itself failed).
type FixReport struct {
	Fix    *fixer.Report `json:"fix"`
	Rescan *ScanReport   `json:"rescan"`
}

// Service wires the steps together.
type Service struct {
	Scanner Scanner
	Checker Checker
	Fixer   Fixer
	Git     GitInspector
	Now     func() time.Time
}

// Scan builds the SBOM for root and checks it for vulnerabilities.
func (s *Service) Scan(ctx context.Context, root string, progress func(string)) (*ScanReport, error) {
	if progress == nil {
		progress = func(string) {}
	}
	now := s.now()
	start := now()
	root, err := ValidateRoot(root)
	if err != nil {
		return nil, err
	}

	progress("의존성 파일 탐색 중...")
	res, err := s.Scanner.Scan(root, progress)
	if err != nil {
		return nil, err
	}
	rep := &ScanReport{
		Root:       root,
		Components: nonNil(res.Components),
		Manifests:  res.Manifests,
		Warnings:   res.Warnings,
		Ecosystems: map[string]int{},
		Severities: map[string]int{},
		Findings:   []vuln.Finding{},
	}
	for _, c := range res.Components {
		rep.Ecosystems[c.Ecosystem]++
	}
	if len(res.Components) == 0 {
		rep.Warnings = append(rep.Warnings, "지원하는 의존성 파일(package-lock.json, go.mod, requirements*.txt)을 찾지 못했습니다")
	} else {
		findings, err := s.Checker.Check(ctx, res.Components, progress)
		if err != nil {
			return nil, err
		}
		rep.Findings = nonNil(findings)
		for _, f := range findings {
			rep.Severities[f.Severity]++
		}
	}
	if s.Git != nil {
		rep.GitRepo, rep.GitDirty = s.Git.Status(root, watchedFiles(rep.Manifests))
	}
	end := now()
	rep.ScannedAt = end.Format("2006-01-02 15:04:05")
	rep.DurationMs = end.Sub(start).Milliseconds()
	progress("완료")
	return rep, nil
}

// Fix applies the requested upgrades and rescans.
func (s *Service) Fix(ctx context.Context, root string, reqs []fixer.Request, progress func(string)) (*FixReport, error) {
	if len(reqs) == 0 {
		return nil, errors.New("선택된 패키지가 없습니다")
	}
	root, err := ValidateRoot(root)
	if err != nil {
		return nil, err
	}
	if progress == nil {
		progress = func(string) {}
	}
	fr := s.Fixer.Apply(ctx, root, reqs, progress)
	progress("수정 후 다시 분석 중...")
	rescan, err := s.Scan(ctx, root, progress)
	if err != nil {
		// The fix itself happened; don't lose its results because of the rescan.
		return &FixReport{Fix: fr}, nil
	}
	return &FixReport{Fix: fr, Rescan: rescan}, nil
}

// ValidateRoot returns the absolute path of an existing directory.
func ValidateRoot(root string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return "", fmt.Errorf("폴더를 찾을 수 없습니다: %s", abs)
	}
	return abs, nil
}

// watchedFiles lists the files a fix may touch for the given manifests.
func watchedFiles(manifests []string) []string {
	var out []string
	for _, m := range manifests {
		dir := filepath.Dir(m)
		out = append(out, m)
		switch filepath.Base(m) {
		case "package-lock.json":
			out = append(out, filepath.Join(dir, "package.json"))
		case "go.mod":
			out = append(out, filepath.Join(dir, "go.sum"))
		}
	}
	return out
}

func (s *Service) now() func() time.Time {
	if s.Now != nil {
		return s.Now
	}
	return time.Now
}

func nonNil[T any](xs []T) []T {
	if xs == nil {
		return []T{}
	}
	return xs
}
