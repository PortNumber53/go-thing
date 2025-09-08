package utility

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// IsSecure determines if the request is effectively HTTPS (directly or via proxy header)
func IsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// IsSecureRequest determines if the request is effectively HTTPS (directly or via proxy header)
func IsSecureRequest(c *gin.Context) bool {
	return IsSecure(c.Request)
}

// NewCSRFToken generates a random token (hex) for CSRF protection
func NewCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SetCSRFCookie sets the CSRF cookie. We also return the token to the client via JSON from /csrf
func SetCSRFCookie(c *gin.Context, token string) {
	ck := &http.Cookie{
		Name:  "csrf_token",
		Value: token,
		Path:  "/",
		// HttpOnly true is acceptable because clients obtain the token from GET /csrf response body
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// Session cookie is fine; rotate by calling /csrf as needed
	}
	if IsSecureRequest(c) {
		ck.Secure = true
	}
	http.SetCookie(c.Writer, ck)
}

// Internal cache for CSRF allowed origins to avoid cross-package dependency on agent globals
var (
	csrfAllowedOrigins     map[string]struct{}
	csrfAllowedOriginsOnce sync.Once
)

// ValidateCSRF verifies the Origin/Referer (if present) and double-submit cookie/header token
func ValidateCSRF(c *gin.Context) bool {
	// --- Origin allowlist or same-origin check ---
	origin := strings.TrimSpace(c.Request.Header.Get("Origin"))
	if origin != "" {
		// Lazy-load ALLOWED_ORIGINS from config once
		csrfAllowedOriginsOnce.Do(func() {
			csrfAllowedOrigins = make(map[string]struct{})
			if cfg, err := LoadConfig(); err == nil && cfg != nil {
				if raw := strings.TrimSpace(cfg["ALLOWED_ORIGINS"]); raw != "" {
					for _, item := range strings.Split(raw, ",") {
						a := strings.TrimSpace(item)
						if a != "" {
							csrfAllowedOrigins[a] = struct{}{}
						}
					}
				}
			} else if err != nil {
				log.Printf("[CSRF] failed to load config for allowed origins: %v. Falling back to same-origin policy.", err)
			}
		})
		if len(csrfAllowedOrigins) > 0 {
			if _, ok := csrfAllowedOrigins[origin]; !ok {
				log.Printf("[CSRF] reject: origin not in allowlist: origin=%q", origin)
				return false
			}
			log.Printf("[CSRF] origin allowed via allowlist: %s", origin)
		} else {
			scheme := "http"
			if IsSecureRequest(c) {
				scheme = "https"
			}
			sameOrigin := strings.ToLower(strings.TrimSpace(scheme + "://" + c.Request.Host))
			if !strings.EqualFold(origin, sameOrigin) {
				log.Printf("[CSRF] reject: origin mismatch: origin=%q sameOrigin=%q", origin, sameOrigin)
				return false
			}
			log.Printf("[CSRF] origin allowed via same-origin: %s", origin)
		}
	}

	// --- Double submit: header must equal cookie ---
	headerTok := strings.TrimSpace(c.Request.Header.Get("X-CSRF-Token"))
	if headerTok == "" {
		log.Printf("[CSRF] reject: missing X-CSRF-Token header")
		return false
	}
	ck, err := c.Request.Cookie("csrf_token")
	if err != nil || ck == nil || strings.TrimSpace(ck.Value) == "" {
		log.Printf("[CSRF] reject: missing csrf_token cookie (err=%v)", err)
		return false
	}
	if !hmac.Equal([]byte(headerTok), []byte(strings.TrimSpace(ck.Value))) {
		log.Printf("[CSRF] reject: token mismatch (header vs cookie)")
		return false
	}
	log.Printf("[CSRF] passed: origin and token validated")
	return true
}

// HMACSHA256 computes the GitHub signature header value for the given secret and body.
// Returns the string in the format "sha256=<hex>" to compare against X-Hub-Signature-256.
func HMACSHA256(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sum := mac.Sum(nil)
	return "sha256=" + hex.EncodeToString(sum)
}

// HMACEqual performs a constant-time comparison between the received signature header
// and the expected value. Comparison is case-insensitive for hex digits.
func HMACEqual(gotHeader, expected string) bool {
	// Normalize to lowercase and trim spaces
	g := strings.ToLower(strings.TrimSpace(gotHeader))
	e := strings.ToLower(strings.TrimSpace(expected))
	return hmac.Equal([]byte(g), []byte(e))
}
