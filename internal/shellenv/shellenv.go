// Package shellenv makes developer tools reachable from a GUI app.
//
// Apps launched from Finder get a minimal PATH (/usr/bin:/bin:...), so npm
// installed via nvm/Homebrew or the Go toolchain would not be found.
package shellenv

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const marker = "__SBOMAPP_PATH__"

var once sync.Once

// EnsureLoginPath merges the user's login-shell PATH and common tool
// locations into this process's PATH. Safe to call multiple times.
func EnsureLoginPath() {
	once.Do(func() {
		home, _ := os.UserHomeDir()
		merged := MergePaths(
			loginShellPath(),
			os.Getenv("PATH"),
			"/opt/homebrew/bin", "/usr/local/bin", "/usr/local/go/bin",
			filepath.Join(home, "go", "bin"),
		)
		_ = os.Setenv("PATH", merged)
	})
}

func loginShellPath() string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/zsh"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, shell, "-ilc", `printf "`+marker+`%s" "$PATH"`).Output()
	if err != nil {
		return ""
	}
	return ExtractMarked(out)
}

// ExtractMarked returns the text after the last marker (interactive shells
// may print banners before it).
func ExtractMarked(out []byte) string {
	i := bytes.LastIndex(out, []byte(marker))
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(string(out[i+len(marker):]))
}

// MergePaths joins PATH-style lists in order, dropping empties and duplicates.
func MergePaths(lists ...string) string {
	seen := map[string]bool{}
	var merged []string
	for _, l := range lists {
		for _, d := range filepath.SplitList(l) {
			if d != "" && !seen[d] {
				seen[d] = true
				merged = append(merged, d)
			}
		}
	}
	return strings.Join(merged, string(filepath.ListSeparator))
}
