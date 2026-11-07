package vuln

import (
	"strconv"
	"strings"
	"unicode"
)

// CompareVersions compares two version strings leniently enough to handle
// semver (npm, Go incl. "v" prefix and pseudo-versions) and most PEP 440
// versions. Returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	ta, tb := tokenize(a), tokenize(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		// A missing segment counts as 0 (1.0 == 1.0.0).
		x, y := token{"0", true}, token{"0", true}
		if i < len(ta) {
			x = ta[i]
		}
		if i < len(tb) {
			y = tb[i]
		}
		if x.isNum && y.isNum {
			if c := cmpNum(x.s, y.s); c != 0 {
				return c
			}
			continue
		}
		if x.isNum != y.isNum {
			// A number beats a pre-release tag (1.0.1 > 1.0.rc1), but a
			// post-release tag beats a number.
			if x.isNum {
				if isPost(y.s) {
					return -1
				}
				return 1
			}
			if isPost(x.s) {
				return 1
			}
			return -1
		}
		if c := cmpTag(x.s, y.s); c != 0 {
			return c
		}
	}
	return 0
}

type token struct {
	s     string
	isNum bool
}

func tokenize(v string) []token {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 { // build metadata / +incompatible
		v = v[:i]
	}
	if i := strings.IndexByte(v, '!'); i >= 0 { // PEP 440 epoch (ignored)
		v = v[i+1:]
	}
	var out []token
	var cur []rune
	curNum := false
	flush := func() {
		if len(cur) > 0 {
			out = append(out, token{string(cur), curNum})
			cur = cur[:0]
		}
	}
	for _, r := range v {
		switch {
		case unicode.IsDigit(r):
			if len(cur) > 0 && !curNum {
				flush()
			}
			curNum = true
			cur = append(cur, r)
		case unicode.IsLetter(r):
			if len(cur) > 0 && curNum {
				flush()
			}
			curNum = false
			cur = append(cur, r)
		default:
			flush()
		}
	}
	flush()
	return out
}

func isPost(s string) bool {
	return s == "post" || s == "rev" || s == "r" || s == "p"
}

var tagOrder = map[string]int{"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "pre": 3, "c": 3, "rc": 3}

func cmpTag(a, b string) int {
	oa, okA := tagOrder[a]
	ob, okB := tagOrder[b]
	if okA && okB {
		return sign(oa - ob)
	}
	return strings.Compare(a, b)
}

func cmpNum(a, b string) int {
	x, errA := strconv.ParseUint(a, 10, 64)
	y, errB := strconv.ParseUint(b, 10, 64)
	if errA != nil || errB != nil {
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if len(a) != len(b) {
			return sign(len(a) - len(b))
		}
		return strings.Compare(a, b)
	}
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// MajorOf returns the first numeric component of a version ("" if none).
func MajorOf(v string) string {
	for _, t := range tokenize(v) {
		if t.isNum {
			return strings.TrimLeft(t.s, "0")
		}
		return ""
	}
	return ""
}
