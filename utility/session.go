package utility

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// SetSessionCookie sets an HttpOnly cookie with a signed token for the user id.
// token format: userID.expUnix.hex(hmac_sha256(secret, userID.expUnix))
func SetSessionCookie(c *gin.Context, userID int64, secret []byte, duration time.Duration) {
	exp := time.Now().Add(duration)
	base := strconv.FormatInt(userID, 10) + "." + strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(base))
	sig := hex.EncodeToString(mac.Sum(nil))
	token := base + "." + sig
	cookie := &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	}
	if IsSecureRequest(c) {
		cookie.Secure = true
	}
	http.SetCookie(c.Writer, cookie)
}

// ClearSessionCookie expires the session cookie immediately.
func ClearSessionCookie(c *gin.Context) {
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if IsSecureRequest(c) {
		cookie.Secure = true
	}
	http.SetCookie(c.Writer, cookie)
}

// ParseSession verifies the cookie and returns userID if valid.
func ParseSession(r *http.Request, secret []byte) (int64, bool) {
	ck, err := r.Cookie("session")
	if err != nil || ck == nil || strings.TrimSpace(ck.Value) == "" {
		return 0, false
	}
	parts := strings.Split(ck.Value, ".")
	if len(parts) != 3 {
		return 0, false
	}
	userStr, expStr, sig := parts[0], parts[1], parts[2]
	base := userStr + "." + expStr
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(base))
	expectedMAC := mac.Sum(nil)
	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		return 0, false
	}
	if !hmac.Equal(sigBytes, expectedMAC) {
		return 0, false
	}
	// Check expiry
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().After(time.Unix(expUnix, 0)) {
		return 0, false
	}
	uid, err := strconv.ParseInt(userStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return uid, true
}
