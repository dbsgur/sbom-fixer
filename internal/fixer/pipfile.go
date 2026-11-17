package fixer

import (
	"fmt"
	"regexp"
	"strings"

	"sbomapp/internal/sbom"
)

// Pure helpers that rewrite a version constraint in a Pipfile while keeping
// everything else (entry form, key spelling, quoting, comments) untouched.

// pipfileUpgrade raises every declaration of name to at least target and
// returns the new Pipfile text plus the sections and specs it wrote.
func pipfileUpgrade(text string, decls []sbom.PyRequirement, name, target string) (string, []string, error) {
	want := sbom.NormalizePyPIName(name)
	var changes []string
	for _, d := range decls {
		if d.Name != want {
			continue
		}
		if d.URL {
			return "", nil, fmt.Errorf("Pipfile [%s]에 git·경로로 지정된 의존성은 자동 수정하지 않습니다", d.Section)
		}
		spec, err := newPySpec(d.Spec, target)
		if err != nil {
			return "", nil, err
		}
		if text, err = setPipfileVersion(text, d.Section, want, spec); err != nil {
			return "", nil, err
		}
		changes = append(changes, fmt.Sprintf("[%s] %q", d.Section, spec))
	}
	if len(changes) == 0 {
		return "", nil, fmt.Errorf("Pipfile에서 %s 선언을 찾지 못했습니다", name)
	}
	return text, changes, nil
}

var (
	// "[packages]", "[packages.requests]", "[dev-packages.\"zope.interface\"]"
	tomlHeaderRe = regexp.MustCompile(`^\s*\[\s*([^\[\]]+?)\s*\]\s*(#.*)?$`)
	// key = value
	tomlKeyValRe = regexp.MustCompile(`^(\s*)("[^"]*"|'[^']*'|[A-Za-z0-9_.-]+)(\s*=\s*)(.*)$`)
	// version = "..." inside an inline table
	inlineVersionRe = regexp.MustCompile(`([{,]\s*)version(\s*=\s*)("(?:[^"\\]|\\.)*"|'[^']*')`)
)

// tomlKeyPath splits a (dotted, possibly quoted) TOML key: a."b.c" → [a b.c].
func tomlKeyPath(s string) []string {
	var parts []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote != 0 && ch == quote:
			quote = 0
		case quote != 0:
			cur.WriteByte(ch)
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '.':
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		case ch != ' ' && ch != '\t':
			cur.WriteByte(ch)
		}
	}
	return append(parts, strings.TrimSpace(cur.String()))
}

// tomlString returns spec as a TOML string using the quote style of old.
func tomlString(old, spec string) string {
	if strings.HasPrefix(old, "'") && !strings.Contains(spec, "'") {
		return "'" + spec + "'"
	}
	return `"` + spec + `"`
}

// stringLiteralEnd returns the index just past the TOML string starting at
// value[0] (" or '), or -1.
func stringLiteralEnd(value string) int {
	q := value[0]
	for i := 1; i < len(value); i++ {
		switch {
		case q == '"' && value[i] == '\\':
			i++
		case value[i] == q:
			return i + 1
		}
	}
	return -1
}

// setPipfileVersion sets the version constraint of package name (PEP 503
// normalised) in a Pipfile section. Supported forms:
//
//	name = "spec"
//	name = {version = "spec", extras = [...]}   (version added if missing)
//	[section.name] with a version = "spec" line (added if missing)
func setPipfileVersion(text, section, name, spec string) (string, error) {
	lines := strings.Split(text, "\n")
	var header []string
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "[[") {
			header = nil // array of tables ([[source]])
			continue
		}
		if m := tomlHeaderRe.FindStringSubmatch(line); m != nil {
			header = tomlKeyPath(m[1])
			// [section.name] sub-table
			if len(header) == 2 && header[0] == section && sbom.NormalizePyPIName(header[1]) == name {
				return setSubTableVersion(lines, i, spec), nil
			}
			continue
		}
		if len(header) != 1 || header[0] != section {
			continue
		}
		m := tomlKeyValRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := tomlKeyPath(m[2])
		if len(key) != 1 || sbom.NormalizePyPIName(key[0]) != name {
			continue
		}
		prefix, value := m[1]+m[2]+m[3], m[4]
		switch {
		case value == "":
		case value[0] == '"' || value[0] == '\'':
			end := stringLiteralEnd(value)
			if end < 0 {
				break
			}
			lines[i] = prefix + tomlString(value, spec) + value[end:]
			return strings.Join(lines, "\n"), nil
		case value[0] == '{':
			if loc := inlineVersionRe.FindStringSubmatchIndex(value); loc != nil {
				old := value[loc[6]:loc[7]]
				lines[i] = prefix + value[:loc[6]] + tomlString(old, spec) + value[loc[7]:]
			} else {
				rest := strings.TrimLeft(value[1:], " ")
				sep := ", "
				if strings.HasPrefix(rest, "}") {
					sep = ""
				}
				lines[i] = prefix + "{version = " + tomlString("", spec) + sep + rest
			}
			return strings.Join(lines, "\n"), nil
		}
		return "", fmt.Errorf("Pipfile [%s]의 %s 선언 형식을 해석할 수 없어 자동 수정하지 않습니다", section, name)
	}
	return "", fmt.Errorf("Pipfile [%s]에서 %s 선언을 찾지 못했습니다", section, name)
}

// setSubTableVersion rewrites (or adds) the version key of the
// [section.name] table whose header is at lines[at].
func setSubTableVersion(lines []string, at int, spec string) string {
	for i := at + 1; i < len(lines); i++ {
		if tomlHeaderRe.MatchString(lines[i]) || strings.HasPrefix(strings.TrimSpace(lines[i]), "[[") {
			break
		}
		m := tomlKeyValRe.FindStringSubmatch(lines[i])
		if m == nil || m[2] != "version" || m[4] == "" || (m[4][0] != '"' && m[4][0] != '\'') {
			continue
		}
		if end := stringLiteralEnd(m[4]); end > 0 {
			lines[i] = m[1] + m[2] + m[3] + tomlString(m[4], spec) + m[4][end:]
			return strings.Join(lines, "\n")
		}
	}
	out := append([]string{}, lines[:at+1]...)
	out = append(out, "version = "+tomlString("", spec))
	return strings.Join(append(out, lines[at+1:]...), "\n")
}
