package fixer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func onPath(tools ...string) func(string) bool {
	set := map[string]bool{}
	for _, t := range tools {
		set[t] = true
	}
	return func(n string) bool { return set[n] }
}

const berryLock = "# generated\n\n__metadata:\n  version: 8\n"

func TestJSCommands(t *testing.T) {
	cases := []struct {
		name string
		pm   string
		env  jsEnv
		want string
	}{
		{"npm", "package-lock.json", jsEnv{has: onPath()}, "npm install --package-lock-only --ignore-scripts --no-audit --no-fund"},

		{"yarn classic on PATH", "yarn.lock", jsEnv{lock: []byte("# yarn lockfile v1\n"), has: onPath("yarn", "corepack")},
			"yarn install --ignore-scripts --non-interactive --no-progress"},
		{"yarn classic via corepack", "yarn.lock", jsEnv{lock: []byte("# yarn lockfile v1\n"), has: onPath("corepack")},
			"corepack yarn@1 install --ignore-scripts --non-interactive --no-progress"},
		{"yarn classic pinned", "yarn.lock", jsEnv{lock: []byte("# yarn lockfile v1\n"), packageManager: "yarn@1.22.22+sha1.abc", has: onPath("yarn", "corepack")},
			"corepack yarn@1.22.22 install --ignore-scripts --non-interactive --no-progress"},
		{"yarn berry pinned", "yarn.lock", jsEnv{lock: []byte(berryLock), packageManager: "yarn@4.5.3+sha512.x", has: onPath("yarn", "corepack")},
			"corepack yarn@4.5.3 install --mode=update-lockfile"},
		{"yarn berry unpinned never uses global classic", "yarn.lock", jsEnv{lock: []byte(berryLock), has: onPath("yarn", "corepack")},
			"corepack yarn@stable install --mode=update-lockfile"},

		{"pnpm on PATH", "pnpm-lock.yaml", jsEnv{lock: []byte("lockfileVersion: '9.0'\n"), has: onPath("pnpm")},
			"pnpm install --lockfile-only --ignore-scripts"},
		{"pnpm pinned", "pnpm-lock.yaml", jsEnv{lock: []byte("lockfileVersion: '9.0'\n"), packageManager: "pnpm@9.15.0", has: onPath("pnpm", "corepack")},
			"corepack pnpm@9.15.0 install --lockfile-only --ignore-scripts"},
		{"pnpm v6 lock keeps format", "pnpm-lock.yaml", jsEnv{lock: []byte("lockfileVersion: '6.0'\n"), has: onPath("corepack")},
			"corepack pnpm@8 install --lockfile-only --ignore-scripts"},
		{"pnpm v5 lock keeps format", "pnpm-lock.yaml", jsEnv{lock: []byte("lockfileVersion: 5.4\n"), has: onPath("corepack")},
			"corepack pnpm@7 install --lockfile-only --ignore-scripts"},
		{"pnpm pin for other tool ignored", "pnpm-lock.yaml", jsEnv{lock: []byte("lockfileVersion: '9.0'\n"), packageManager: "yarn@4.0.0", has: onPath("corepack")},
			"corepack pnpm@9 install --lockfile-only --ignore-scripts"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pm, ok := jsManagerFor(c.pm)
			if !ok {
				t.Fatal("no manager")
			}
			cmd := pm.command(c.env)
			if got := cmd.String(); got != c.want {
				t.Errorf("got  %s\nwant %s", got, c.want)
			}
			if cmd.name == "corepack" && !strings.Contains(strings.Join(cmd.env, " "), corepackEnv) {
				t.Errorf("corepack must not prompt: env=%v", cmd.env)
			}
		})
	}
}

const yarnPkgJSON = "{\n  \"name\": \"web\",\n  \"packageManager\": \"yarn@1.22.22\",\n  \"dependencies\": {\n    \"lodash\": \"4.17.15\",\n    \"mkdirp\": \"0.5.1\"\n  }\n}\n"

func yarnLockWith(lodash, minimist string) string {
	return "# yarn lockfile v1\n\nlodash@4.17.15:\n  version \"" + lodash + "\"\n\nminimist@0.0.8:\n  version \"" + minimist + "\"\n"
}

func TestNpmFixer_Yarn(t *testing.T) {
	root := setup(t, map[string]string{"package.json": yarnPkgJSON, "yarn.lock": yarnLockWith("4.17.15", "0.0.8")})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		return os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(yarnLockWith("4.17.21", "0.2.4")), 0o644)
	}}
	rep := NewService(run, NpmFixer{LookPath: onPath("corepack")}).Apply(context.Background(), root, []Request{
		{Ecosystem: "npm", Name: "lodash", CurrentVersion: "4.17.15", TargetVersion: "4.17.21", Manifest: "yarn.lock", Direct: true},
		{Ecosystem: "npm", Name: "minimist", CurrentVersion: "0.0.8", TargetVersion: "0.2.4", Manifest: "yarn.lock"},
	}, nil)
	for _, r := range rep.Results {
		if !r.Success {
			t.Errorf("%s: %s", r.Request.Name, r.Message)
		}
	}
	if len(run.calls) != 1 || run.calls[0] != "corepack yarn@1.22.22 install --ignore-scripts --non-interactive --no-progress" {
		t.Errorf("calls = %v", run.calls)
	}
	pj := read(t, root, "package.json")
	if !strings.Contains(pj, `"lodash": "4.17.21"`) || !strings.Contains(pj, "\"resolutions\": {\n    \"minimist\": \"0.2.4\"") {
		t.Errorf("package.json = %s", pj)
	}
}

const pnpmPkgJSON = "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.15\"\n  }\n}\n"

func pnpmLockWith(lodash, minimist string) string {
	return "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.15\n        version: " + lodash +
		"\n\npackages:\n\n  lodash@" + lodash + ":\n    resolution: {integrity: x}\n\n  minimist@" + minimist + ":\n    resolution: {integrity: y}\n"
}

func TestNpmFixer_Pnpm(t *testing.T) {
	root := setup(t, map[string]string{"app/package.json": pnpmPkgJSON, "app/pnpm-lock.yaml": pnpmLockWith("4.17.15", "0.0.8")})
	run := &fakeRunner{handle: func(dir, cmd string) error {
		return os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(pnpmLockWith("4.17.21", "0.2.4")), 0o644)
	}}
	rep := NewService(run, NpmFixer{LookPath: onPath("pnpm")}).Apply(context.Background(), root, []Request{
		{Ecosystem: "npm", Name: "lodash", CurrentVersion: "4.17.15", TargetVersion: "4.17.21", Manifest: "app/pnpm-lock.yaml", Direct: true},
		{Ecosystem: "npm", Name: "minimist", CurrentVersion: "0.0.8", TargetVersion: "0.2.4", Manifest: "app/pnpm-lock.yaml"},
	}, nil)
	for _, r := range rep.Results {
		if !r.Success {
			t.Errorf("%s: %s", r.Request.Name, r.Message)
		}
	}
	if len(run.calls) != 1 || run.calls[0] != "pnpm install --lockfile-only --ignore-scripts" {
		t.Errorf("calls = %v", run.calls)
	}
	pj := read(t, root, "app/package.json")
	if !strings.Contains(pj, `"lodash": "^4.17.21"`) || !strings.Contains(pj, "\"pnpm\": {\n    \"overrides\": {\n      \"minimist\": \"0.2.4\"") {
		t.Errorf("package.json = %s", pj)
	}
	if strings.Join(rep.ChangedFiles, ",") != "app/package.json,app/pnpm-lock.yaml" {
		t.Errorf("changed = %v", rep.ChangedFiles)
	}
}

func TestNpmFixer_PnpmFailureRestores(t *testing.T) {
	lock := pnpmLockWith("4.17.15", "0.0.8")
	root := setup(t, map[string]string{"package.json": pnpmPkgJSON, "pnpm-lock.yaml": lock})
	run := &fakeRunner{handle: func(string, string) error { return os.ErrPermission }}
	rep := NewService(run, NpmFixer{LookPath: onPath("pnpm")}).Apply(context.Background(), root, []Request{
		{Ecosystem: "npm", Name: "lodash", CurrentVersion: "4.17.15", TargetVersion: "4.17.21", Manifest: "pnpm-lock.yaml", Direct: true},
	}, nil)
	if rep.Results[0].Success || !strings.Contains(rep.Results[0].Message, "pnpm install 실패") {
		t.Errorf("result = %+v", rep.Results[0])
	}
	if read(t, root, "package.json") != pnpmPkgJSON || read(t, root, "pnpm-lock.yaml") != lock {
		t.Error("files were not restored")
	}
}
