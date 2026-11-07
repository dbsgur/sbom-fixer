package shellenv

import "testing"

func TestMergePaths(t *testing.T) {
	got := MergePaths("/a:/b", "", "/b:/c", "/a", "/d")
	if got != "/a:/b:/c:/d" {
		t.Errorf("got %q", got)
	}
}

func TestExtractMarked(t *testing.T) {
	cases := map[string]string{
		"banner\n" + marker + "/usr/bin:/bin": "/usr/bin:/bin",
		marker + "x" + marker + "/final\n":    "/final",
		"no marker":                           "",
	}
	for in, want := range cases {
		if got := ExtractMarked([]byte(in)); got != want {
			t.Errorf("ExtractMarked(%q) = %q want %q", in, got, want)
		}
	}
}
