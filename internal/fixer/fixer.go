// Package fixer upgrades vulnerable packages in a repository's manifests.
package fixer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"sbomapp/internal/sbom"
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

// Report is the outcome of Apply.
type Report struct {
	Results      []Result     `json:"results"`
	Commands     []CommandLog `json:"commands"`
	ChangedFiles []string     `json:"changedFiles"`
}

type fixCtx struct {
	ctx      context.Context
	root     string
	report   *Report
	progress func(string)
}

// Apply performs the requested upgrades. Requests are grouped per manifest;
// if the package manager fails, that manifest's files are restored.
func Apply(ctx context.Context, root string, reqs []Request, progress func(string)) (*Report, error) {
	if progress == nil {
		progress = func(string) {}
	}
	ensureLoginPath()

	groups := map[string][]Request{}
	var order []string
	rep := &Report{}
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

	fc := &fixCtx{ctx: ctx, root: root, report: rep, progress: progress}
	for _, k := range order {
		g := groups[k]
		var results []Result
		switch g[0].Ecosystem {
		case sbom.EcosystemNpm:
			results = fc.fixNpm(g)
		case sbom.EcosystemGo:
			results = fc.fixGo(g)
		case sbom.EcosystemPyPI:
			results = fc.fixPython(g)
		default:
			for _, r := range g {
				results = append(results, Result{Request: r, Message: "지원하지 않는 생태계입니다: " + r.Ecosystem})
			}
		}
		rep.Results = append(rep.Results, results...)
	}
	sort.Strings(rep.ChangedFiles)
	return rep, nil
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

// ---------- helpers ----------

type backup map[string][]byte // abs path -> content (nil = did not exist)

func takeBackup(paths ...string) backup {
	b := backup{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			b[p] = nil
		} else {
			b[p] = data
		}
	}
	return b
}

func (b backup) restore() {
	for p, data := range b {
		if data == nil {
			_ = os.Remove(p)
		} else {
			_ = os.WriteFile(p, data, 0o644)
		}
	}
}

// changed records files whose contents differ from the backup.
func (fc *fixCtx) recordChanged(b backup) {
	for p, old := range b {
		now, err := os.ReadFile(p)
		if err != nil || bytes.Equal(now, old) {
			continue
		}
		rel, _ := filepath.Rel(fc.root, p)
		fc.report.ChangedFiles = append(fc.report.ChangedFiles, rel)
	}
}

func (fc *fixCtx) run(dir string, env []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(fc.ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	rel, _ := filepath.Rel(fc.root, dir)
	text := strings.TrimSpace(string(out))
	if err != nil {
		var ee *exec.Error
		if errors.As(err, &ee) {
			text = fmt.Sprintf("'%s' 명령을 찾을 수 없습니다. 설치되어 있고 PATH에 있는지 확인하세요. (%v)", name, err)
		} else if text == "" {
			text = err.Error()
		}
	}
	fc.report.Commands = append(fc.report.Commands, CommandLog{
		Dir:     rel,
		Command: name + " " + strings.Join(args, " "),
		Output:  text,
		Success: err == nil,
	})
	if err != nil {
		return text, fmt.Errorf("%s 실패", name)
	}
	return text, nil
}

func failAll(g []Request, msg string) []Result {
	out := make([]Result, len(g))
	for i, r := range g {
		out[i] = Result{Request: r, Message: msg}
	}
	return out
}

var pathOnce sync.Once

// ensureLoginPath makes npm/go reachable when the app is launched from Finder,
// where the PATH is minimal and doesn't include Homebrew/nvm/Go locations.
func ensureLoginPath() {
	pathOnce.Do(func() {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/zsh"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, shell, "-ilc", `printf "__SBOMAPP_PATH__%s" "$PATH"`).Output()
		parts := []string{}
		if err == nil {
			if i := bytes.LastIndex(out, []byte("__SBOMAPP_PATH__")); i >= 0 {
				parts = append(parts, strings.TrimSpace(string(out[i+len("__SBOMAPP_PATH__"):])))
			}
		}
		home, _ := os.UserHomeDir()
		parts = append(parts, os.Getenv("PATH"), "/opt/homebrew/bin", "/usr/local/bin", "/usr/local/go/bin", filepath.Join(home, "go", "bin"))
		seen := map[string]bool{}
		var merged []string
		for _, p := range parts {
			for _, d := range filepath.SplitList(p) {
				if d != "" && !seen[d] {
					seen[d] = true
					merged = append(merged, d)
				}
			}
		}
		_ = os.Setenv("PATH", strings.Join(merged, string(filepath.ListSeparator)))
	})
}
