package fixer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Runner executes an external command and returns its combined output.
type Runner interface {
	Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error)
}

// ExecRunner runs real processes.
type ExecRunner struct {
	Timeout time.Duration // default 10 minutes
}

func (r ExecRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		var ee *exec.Error
		if errors.As(err, &ee) {
			text = fmt.Sprintf("'%s' 명령을 찾을 수 없습니다. 설치되어 있고 PATH에 있는지 확인하세요. (%v)", name, err)
		} else if text == "" {
			text = err.Error()
		}
	}
	return text, err
}
