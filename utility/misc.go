package utility

import "fmt"

// SummarizeToolResponse returns a concise string summary from components.
func SummarizeToolResponse(success bool, data interface{}, errMsg string) string {
    if success {
        return fmt.Sprint(data)
    }
    return fmt.Sprintf("Failed: %s", errMsg)
}

// MaskToken masks sensitive values leaving a small prefix/suffix for identification.
func MaskToken(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}
