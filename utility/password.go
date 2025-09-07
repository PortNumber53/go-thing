package utility

import "unicode"

// IsStrongPassword requires at least 12 chars including upper, lower, digit, and special
func IsStrongPassword(s string) bool {
	// Count runes to handle Unicode safely
	if len([]rune(s)) < 12 {
		return false
	}
	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			// Any rune that is not letter, digit, or space counts as special
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
				hasSpecial = true
			}
		}
	}
	return hasLower && hasUpper && hasDigit && hasSpecial
}
