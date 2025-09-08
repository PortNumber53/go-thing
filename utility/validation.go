package utility

import (
	"regexp"
	"sync"
)

var (
	emailRegexOnce     sync.Once
	emailRegexCompiled *regexp.Regexp
)

// EmailRegex returns a compiled, cached regular expression for basic email validation.
// Pattern: non-space/non-@ local part, then '@', then non-space/non-@ domain, dot, TLD.
func EmailRegex() *regexp.Regexp {
	emailRegexOnce.Do(func() {
		emailRegexCompiled = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	})
	return emailRegexCompiled
}

// IsValidEmail returns true if s matches the basic email pattern.
func IsValidEmail(s string) bool {
	return EmailRegex().MatchString(s)
}
