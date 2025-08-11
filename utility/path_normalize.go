package utility

import (
	"regexp"
	"strings"
)

// Precompiled regex to collapse accidental double slashes while avoiding schemes like http://
var doubleSlashRegex = regexp.MustCompile(`([^:/])//+`)

// NormalizePathInText rewrites host chroot paths to their canonical in-sandbox alias (/app)
func NormalizePathInText(s string) string {
	ch := GetChrootDir()
	if ch == "" {
		return s
	}
	// Replace any occurrence of the absolute chroot path with /app
	s2 := strings.ReplaceAll(s, ch, "/app")
	// Collapse any accidental double slashes but avoid collapsing after a scheme (e.g., http://)
	s2 = doubleSlashRegex.ReplaceAllString(s2, "$1/")
	return s2
}

// SanitizeContextFacts rewrites host-specific paths to canonical sandbox paths and dedupes.
func SanitizeContextFacts(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		norm := NormalizePathInText(trimmed)
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out
}
