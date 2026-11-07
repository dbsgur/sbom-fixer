package gitutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIntersect(t *testing.T) {
	got := Intersect([]string{"a", "", "b", "c"}, []string{"c", "a", "z"})
	if !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Errorf("got %v", got)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@t", "-c", "user.name=t"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestStatus(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	plain := t.TempDir()
	if isRepo, _ := (Git{}).Status(plain, nil); isRepo {
		t.Error("temp dir should not be a repo")
	}

	repo := t.TempDir()
	git(t, repo, "init", "-q")
	sub := filepath.Join(repo, "svc")
	_ = os.MkdirAll(sub, 0o755)
	for _, f := range []string{"go.mod", "go.sum", "other.txt"} {
		_ = os.WriteFile(filepath.Join(sub, f), []byte("v1"), 0o644)
	}
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-qm", "init")
	for _, f := range []string{"go.mod", "other.txt"} {
		_ = os.WriteFile(filepath.Join(sub, f), []byte("v2"), 0o644)
	}

	// Paths are relative to the scanned dir (a sub-directory of the repo).
	isRepo, dirty := (Git{}).Status(sub, []string{"go.mod", "go.sum"})
	if !isRepo || !reflect.DeepEqual(dirty, []string{"go.mod"}) {
		t.Errorf("isRepo=%v dirty=%v", isRepo, dirty)
	}
}
