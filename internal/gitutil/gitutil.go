// Package gitutil answers the few git questions the app needs.
package gitutil

import (
	"os/exec"
	"strings"
)

// Git inspects a working tree using the git CLI.
type Git struct{}

// Status reports whether dir is inside a git work tree and which of the
// given dir-relative files have uncommitted changes.
func (Git) Status(dir string, files []string) (isRepo bool, dirty []string) {
	if err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Run(); err != nil {
		return false, nil
	}
	out, err := exec.Command("git", "-C", dir, "diff", "--name-only", "--relative", "HEAD").Output()
	if err != nil {
		return true, nil // e.g. no commits yet
	}
	return true, Intersect(strings.Split(strings.TrimSpace(string(out)), "\n"), files)
}

// Intersect returns the entries of changed that appear in watch, in order.
func Intersect(changed, watch []string) []string {
	set := make(map[string]bool, len(watch))
	for _, w := range watch {
		set[w] = true
	}
	var out []string
	for _, c := range changed {
		if c != "" && set[c] {
			out = append(out, c)
		}
	}
	return out
}
