package sbom

// ParseResult is what a Parser extracts from one file.
type ParseResult struct {
	Components []Component
	Warnings   []string
}

// Parser understands one kind of dependency file. Adding support for a new
// ecosystem means implementing this interface and registering it in
// DefaultParsers — the scanner itself does not change.
type Parser interface {
	// Match reports whether the parser handles a file with this base name.
	Match(fileName string) bool
	// Label is shown as progress text ("" = silent).
	Label() string
	// Parse reads absPath; relPath (relative to the scanned root) is
	// recorded as the component's manifest.
	Parse(absPath, relPath string) (ParseResult, error)
}

// DefaultParsers returns every built-in parser.
func DefaultParsers() []Parser {
	return []Parser{
		NpmLockParser{},
		YarnLockParser{},
		PnpmLockParser{},
		NpmManifestCheck{},
		GoModParser{},
		RequirementsParser{},
		PoetryLockParser{},
		UvLockParser{},
		PyprojectCheck{},
	}
}
