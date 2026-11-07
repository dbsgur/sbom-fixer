package sbom

// collector accumulates components for one manifest, dropping duplicates.
type collector struct {
	ecosystem string
	manifest  string
	seen      map[string]bool
	out       []Component
}

func newCollector(ecosystem, manifest string) *collector {
	return &collector{ecosystem: ecosystem, manifest: manifest, seen: map[string]bool{}}
}

func (c *collector) add(name, version string, direct, dev bool) {
	if name == "" || version == "" {
		return
	}
	k := name + "@" + version
	if c.seen[k] {
		return
	}
	c.seen[k] = true
	c.out = append(c.out, Component{
		Name:      name,
		Version:   version,
		Ecosystem: c.ecosystem,
		PURL:      makePURL(c.ecosystem, name, version),
		Manifest:  c.manifest,
		Direct:    direct,
		Dev:       dev,
	})
}
