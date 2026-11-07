package vuln

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.17.15", "4.17.21", -1},
		{"1.0.0", "1.0", 0},
		{"v0.3.7", "0.3.8", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"2.0rc1", "2.0", -1},
		{"2.0.post1", "2.0", 1},
		{"1.10.0", "1.9.9", 1},
		{"v0.0.0-20210101000000-abcdef", "0.0.1", -1},
		{"v2.0.0+incompatible", "2.0.0", 0},
		{"2.31.0", "2.31.0", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCVSS(t *testing.T) {
	s, ok := cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if !ok || s != 9.8 {
		t.Fatalf("got %v", s)
	}
	s, _ = cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
	if s != 7.2 {
		t.Fatalf("got %v", s)
	}
}
