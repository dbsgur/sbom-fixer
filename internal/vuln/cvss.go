package vuln

import (
	"math"
	"strings"
)

// cvss3BaseScore computes the CVSS v3.x base score from a vector string such
// as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". ok=false if unparsable.
func cvss3BaseScore(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	scopeChanged := m["S"] == "C"
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}

	get := func(tbl map[string]float64, k string) (float64, bool) {
		v, ok := tbl[m[k]]
		return v, ok
	}
	vAV, ok1 := get(av, "AV")
	vAC, ok2 := get(ac, "AC")
	vPR, ok3 := get(pr, "PR")
	vUI, ok4 := get(ui, "UI")
	vC, ok5 := get(cia, "C")
	vI, ok6 := get(cia, "I")
	vA, ok7 := get(cia, "A")
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - (1-vC)*(1-vI)*(1-vA)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploit := 8.22 * vAV * vAC * vPR * vUI
	if impact <= 0 {
		return 0, true
	}
	var base float64
	if scopeChanged {
		base = math.Min(1.08*(impact+exploit), 10)
	} else {
		base = math.Min(impact+exploit, 10)
	}
	return roundUp(base), true
}

func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

func severityFromScore(s float64) string {
	switch {
	case s >= 9:
		return SeverityCritical
	case s >= 7:
		return SeverityHigh
	case s >= 4:
		return SeverityMedium
	case s > 0:
		return SeverityLow
	}
	return SeverityUnknown
}
