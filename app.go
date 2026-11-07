package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"sbomapp/internal/fixer"
	"sbomapp/internal/sbom"
	"sbomapp/internal/shellenv"
	"sbomapp/internal/vuln"
)

// App is bound to the frontend; its exported methods are callable from JS.
type App struct {
	ctx     context.Context
	checker *vuln.Checker
	fixer   *fixer.Service
	mu      sync.Mutex
	last    *ScanReport
}

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

func NewApp() *App {
	return &App{checker: vuln.NewChecker(vuln.NewOSVClient()), fixer: fixer.DefaultService()}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go shellenv.EnsureLoginPath() // so npm/go are found when launched from Finder
}

func (a *App) progress(msg string) {
	runtime.EventsEmit(a.ctx, "progress", msg)
}

// InitialPath returns a folder passed on the command line (sbomapp <dir>), if any.
func (a *App) InitialPath() string {
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if st, err := os.Stat(arg); err == nil && st.IsDir() {
			abs, _ := filepath.Abs(arg)
			return abs
		}
	}
	return ""
}

// ResolveDroppedPath turns a dropped file/folder into the folder to scan.
func (a *App) ResolveDroppedPath(p string) string {
	st, err := os.Stat(p)
	if err != nil {
		return ""
	}
	if !st.IsDir() {
		return filepath.Dir(p)
	}
	return p
}

// SelectFolder opens a native directory picker. Returns "" if cancelled.
func (a *App) SelectFolder() (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "분석할 레포지토리(폴더)를 선택하세요",
	})
}

// Scan builds the SBOM for root and checks it against OSV.
func (a *App) Scan(root string) (*ScanReport, error) {
	start := time.Now()
	root, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("폴더를 찾을 수 없습니다: %s", root)
	}

	a.progress("의존성 파일 탐색 중...")
	res, err := sbom.NewScanner().Scan(root, a.progress)
	if err != nil {
		return nil, err
	}
	rep := &ScanReport{
		Root:       root,
		Components: res.Components,
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
		findings, err := a.checker.Check(a.ctx, res.Components, a.progress)
		if err != nil {
			return nil, err
		}
		rep.Findings = findings
		for _, f := range findings {
			rep.Severities[f.Severity]++
		}
	}
	rep.GitRepo, rep.GitDirty = gitStatus(root, rep.Manifests)
	rep.ScannedAt = time.Now().Format("2006-01-02 15:04:05")
	rep.DurationMs = time.Since(start).Milliseconds()

	a.mu.Lock()
	a.last = rep
	a.mu.Unlock()
	a.progress("완료")
	return rep, nil
}

// FixReport is returned after applying fixes; it includes a fresh scan.
type FixReport struct {
	Fix    *fixer.Report `json:"fix"`
	Rescan *ScanReport   `json:"rescan"`
}

// ApplyFixes upgrades the selected packages, then rescans the repository.
func (a *App) ApplyFixes(root string, reqs []fixer.Request) (*FixReport, error) {
	if len(reqs) == 0 {
		return nil, errors.New("선택된 패키지가 없습니다")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	shellenv.EnsureLoginPath() // waits if the startup lookup is still running
	fr := a.fixer.Apply(a.ctx, root, reqs, a.progress)
	a.progress("수정 후 다시 분석 중...")
	rescan, err := a.Scan(root)
	if err != nil {
		// The fix itself succeeded; report the rescan problem without losing results.
		return &FixReport{Fix: fr}, nil
	}
	return &FixReport{Fix: fr, Rescan: rescan}, nil
}

// ExportSBOM writes the last scan as a CycloneDX JSON file chosen by the user.
// Returns the saved path ("" if cancelled).
func (a *App) ExportSBOM() (string, error) {
	a.mu.Lock()
	rep := a.last
	a.mu.Unlock()
	if rep == nil {
		return "", errors.New("먼저 분석을 실행하세요")
	}
	project := filepath.Base(rep.Root)
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "SBOM 저장 (CycloneDX JSON)",
		DefaultFilename: project + ".cdx.json",
		Filters:         []runtime.FileFilter{{DisplayName: "CycloneDX JSON", Pattern: "*.json"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	var vs []sbom.CycloneDXVuln
	for _, f := range rep.Findings {
		for _, v := range f.Vulns {
			vs = append(vs, sbom.CycloneDXVuln{
				ID: v.ID, Severity: strings.ToLower(v.Severity), Summary: v.Summary,
				BomRef: f.Component.Key(), FixedIn: v.FixedVersion,
			})
		}
	}
	data, err := sbom.CycloneDX(project, rep.Components, vs)
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o644)
}

// OpenInFinder reveals the folder in the OS file manager.
func (a *App) OpenInFinder(path string) {
	_ = exec.Command("open", path).Start()
}

// gitStatus reports whether root is in a git repo and which manifest-related
// files have uncommitted changes (so the user can review fixes with git diff).
func gitStatus(root string, manifests []string) (bool, []string) {
	if err := exec.Command("git", "-C", root, "rev-parse", "--is-inside-work-tree").Run(); err != nil {
		return false, nil
	}
	out, err := exec.Command("git", "-C", root, "diff", "--name-only", "--relative", "HEAD").Output()
	if err != nil {
		return true, nil
	}
	watch := map[string]bool{}
	for _, m := range manifests {
		dir := filepath.Dir(m)
		watch[m] = true
		watch[filepath.Join(dir, "package.json")] = true
		watch[filepath.Join(dir, "go.sum")] = true
	}
	var dirty []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if watch[f] {
			dirty = append(dirty, f)
		}
	}
	return true, dirty
}
