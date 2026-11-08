package fixer

import (
	"bytes"
	"regexp"
	"strings"

	"sbomapp/internal/sbom"
)

// jsPackageManager describes what differs between npm, yarn and pnpm when
// upgrading a package. Everything else (package.json editing, rollback,
// verification) is shared by NpmFixer.
type jsPackageManager struct {
	name     string
	lockFile string
	// overridePath is where package.json forces transitive versions.
	overridePath []string
	parser       sbom.Parser
	// command picks the executable and arguments that regenerate the lock.
	command func(env jsEnv) toolCmd
}

// jsEnv is the input to command selection (kept pure for testing).
type jsEnv struct {
	lock           []byte            // current lock file contents
	packageManager string            // package.json "packageManager", e.g. "pnpm@9.15.0+sha512..."
	has            func(string) bool // whether an executable is on PATH
}

type toolCmd struct {
	name string
	args []string
	env  []string
}

func (c toolCmd) String() string { return strings.Join(append([]string{c.name}, c.args...), " ") }

var jsManagers = []jsPackageManager{
	{
		name: "npm", lockFile: "package-lock.json", overridePath: []string{"overrides"},
		parser: sbom.NpmLockParser{},
		command: func(jsEnv) toolCmd {
			return toolCmd{name: "npm", args: []string{"install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"}}
		},
	},
	{
		name: "yarn", lockFile: "yarn.lock", overridePath: []string{"resolutions"},
		parser: sbom.YarnLockParser{}, command: yarnCommand,
	},
	{
		name: "pnpm", lockFile: "pnpm-lock.yaml", overridePath: []string{"pnpm", "overrides"},
		parser: sbom.PnpmLockParser{}, command: pnpmCommand,
	},
}

// jsManagerFor returns the package manager owning a lock file.
func jsManagerFor(lockFile string) (jsPackageManager, bool) {
	for _, m := range jsManagers {
		if m.lockFile == lockFile {
			return m, true
		}
	}
	return jsPackageManager{}, false
}

const corepackEnv = "COREPACK_ENABLE_DOWNLOAD_PROMPT=0"

// pinnedTool returns "tool@version" from the packageManager field, without
// the "+sha..." integrity suffix, or "" when it pins a different tool.
func pinnedTool(packageManager, tool string) string {
	if !strings.HasPrefix(packageManager, tool+"@") {
		return ""
	}
	if i := strings.IndexByte(packageManager, '+'); i > 0 {
		return packageManager[:i]
	}
	return packageManager
}

// viaTool runs `tool args...`, preferring the exact version pinned in
// package.json (through corepack), then a tool on PATH, then corepack with
// fallback as the version.
func viaTool(e jsEnv, tool, fallback string, args ...string) toolCmd {
	if pin := pinnedTool(e.packageManager, tool); pin != "" && e.has("corepack") {
		return toolCmd{name: "corepack", args: append([]string{pin}, args...), env: []string{corepackEnv}}
	}
	if e.has(tool) {
		return toolCmd{name: tool, args: args}
	}
	return toolCmd{name: "corepack", args: append([]string{fallback}, args...), env: []string{corepackEnv}}
}

func isYarnBerry(lock []byte) bool { return bytes.Contains(lock, []byte("\n__metadata:")) }

func yarnCommand(e jsEnv) toolCmd {
	if !isYarnBerry(e.lock) {
		// Yarn classic has no lockfile-only mode.
		return viaTool(e, "yarn", "yarn@1", "install", "--ignore-scripts", "--non-interactive", "--no-progress")
	}
	cmd := toolCmd{args: []string{"install", "--mode=update-lockfile"}, env: []string{"YARN_ENABLE_IMMUTABLE_INSTALLS=false"}}
	// A global yarn is usually classic (1.x), which must not touch a berry
	// lock unless the project vendors yarn via yarnPath; use corepack instead.
	pin := pinnedTool(e.packageManager, "yarn")
	if pin == "" || strings.HasPrefix(pin, "yarn@1") {
		pin = "yarn@stable"
	}
	cmd.name = "corepack"
	cmd.args = append([]string{pin}, cmd.args...)
	cmd.env = append(cmd.env, corepackEnv)
	return cmd
}

var pnpmLockVersion = regexp.MustCompile(`(?m)^lockfileVersion:\s*'?(\d+)`)

func pnpmCommand(e jsEnv) toolCmd {
	// Without a pin, use the pnpm major that writes this lockfile format so
	// the lock is not silently migrated.
	fallback := "pnpm@9"
	if m := pnpmLockVersion.FindSubmatch(e.lock); m != nil {
		switch string(m[1]) {
		case "5":
			fallback = "pnpm@7"
		case "6":
			fallback = "pnpm@8"
		}
	}
	return viaTool(e, "pnpm", fallback, "install", "--lockfile-only", "--ignore-scripts")
}
