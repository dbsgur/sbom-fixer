package fixer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// Workspace is the per-Apply context handed to Fixers: it runs commands,
// takes backups and records what changed.
type Workspace struct {
	Ctx      context.Context
	Root     string
	runner   Runner
	progress func(string)
	commands []CommandLog
	changed  []string
}

func newWorkspace(ctx context.Context, root string, r Runner, progress func(string)) *Workspace {
	if progress == nil {
		progress = func(string) {}
	}
	return &Workspace{Ctx: ctx, Root: root, runner: r, progress: progress}
}

// Abs resolves a root-relative path.
func (ws *Workspace) Abs(rel string) string { return filepath.Join(ws.Root, rel) }

// Rel converts an absolute path to root-relative.
func (ws *Workspace) Rel(abs string) string {
	r, err := filepath.Rel(ws.Root, abs)
	if err != nil {
		return abs
	}
	return r
}

// Progress reports a status line to the UI.
func (ws *Workspace) Progress(msg string) { ws.progress(msg) }

// Run executes a command in dir and records it in the report.
func (ws *Workspace) Run(dir string, env []string, name string, args ...string) (string, error) {
	out, err := ws.runner.Run(ws.Ctx, dir, env, name, args...)
	cmd := name
	for _, a := range args {
		cmd += " " + a
	}
	ws.commands = append(ws.commands, CommandLog{Dir: ws.Rel(dir), Command: cmd, Output: out, Success: err == nil})
	if err != nil {
		return out, fmt.Errorf("%s 실패: %w", name, err)
	}
	return out, nil
}

// Backup snapshots files so a failed fix can be rolled back.
type Backup map[string][]byte // abs path -> content (nil = did not exist)

// TakeBackup snapshots the given absolute paths.
func (ws *Workspace) TakeBackup(paths ...string) Backup {
	b := Backup{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			data = nil
		}
		b[p] = data
	}
	return b
}

// Restore writes the snapshot back (deleting files that did not exist).
func (b Backup) Restore() {
	for p, data := range b {
		if data == nil {
			_ = os.Remove(p)
		} else {
			_ = os.WriteFile(p, data, 0o644)
		}
	}
}

// RecordChanged adds files whose content differs from the backup.
func (ws *Workspace) RecordChanged(b Backup) {
	for p, old := range b {
		now, err := os.ReadFile(p)
		if err != nil || bytes.Equal(now, old) {
			continue
		}
		ws.changed = append(ws.changed, ws.Rel(p))
	}
}
