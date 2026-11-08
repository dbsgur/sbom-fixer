package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"sbomapp/internal/fixer"
	"sbomapp/internal/gitutil"
	"sbomapp/internal/sbom"
	"sbomapp/internal/service"
	"sbomapp/internal/shellenv"
	"sbomapp/internal/vuln"
)

// App adapts service.Service to Wails: it owns the runtime context, native
// dialogs and progress events. Business logic lives in internal/service.
type App struct {
	ctx  context.Context
	svc  *service.Service
	mu   sync.Mutex
	last *service.ScanReport
}

func NewApp() *App {
	return &App{svc: &service.Service{
		Scanner: sbom.NewScanner(),
		Checker: vuln.NewChecker(vuln.NewOSVClient()),
		Fixer:   fixer.DefaultService(),
		Git:     gitutil.Git{},
	}}
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
		if abs, err := service.ValidateRoot(arg); err == nil {
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

// Scan builds the SBOM for root and checks it for vulnerabilities.
func (a *App) Scan(root string) (*service.ScanReport, error) {
	rep, err := a.svc.Scan(a.ctx, root, a.progress)
	if err == nil {
		a.remember(rep)
	}
	return rep, err
}

// ApplyFixes upgrades the selected packages, then rescans the repository.
func (a *App) ApplyFixes(root string, reqs []fixer.Request) (*service.FixReport, error) {
	shellenv.EnsureLoginPath() // waits if the startup lookup is still running
	fr, err := a.svc.Fix(a.ctx, root, reqs, a.progress)
	if err == nil && fr.Rescan != nil {
		a.remember(fr.Rescan)
	}
	return fr, err
}

// ExportFormats lists the files that can be exported (for the UI buttons).
func (a *App) ExportFormats() []service.ExportFormat {
	return service.ExportFormats
}

// Export saves the last scan in the given format (see ExportFormats) to a
// file chosen by the user. Returns the saved path ("" if cancelled).
func (a *App) Export(formatID string) (string, error) {
	a.mu.Lock()
	rep := a.last
	a.mu.Unlock()
	if rep == nil {
		return "", errors.New("먼저 분석을 실행하세요")
	}
	f, err := service.FindExportFormat(formatID)
	if err != nil {
		return "", err
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           f.DialogTitle,
		DefaultFilename: f.DefaultFilename(rep),
		Filters:         []runtime.FileFilter{{DisplayName: f.FilterName, Pattern: "*.json"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	data, err := f.Render(rep, time.Now())
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o644)
}

// OpenInFinder reveals the folder in the OS file manager.
func (a *App) OpenInFinder(path string) {
	_ = exec.Command("open", path).Start()
}

func (a *App) remember(rep *service.ScanReport) {
	a.mu.Lock()
	a.last = rep
	a.mu.Unlock()
}
