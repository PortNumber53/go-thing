package routes

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"go-thing/db"
	"go-thing/utility"
)

// LoginDeps provides the minimal dependencies needed by the login route
// so the route can live outside of main while still using main's limiter/session helpers.
type LoginDeps struct {
	GetLimiter         func(ip string) bool
	IsLocked           func(user string) (bool, time.Duration)
	RecordFailure      func(user string)
	RecordSuccess      func(user string)
	DummyBcryptCompare func(password string)
	SetSessionCookie   func(c *gin.Context, userID int64)
}

// RegisterLoginRoutes registers the CSRF-protected /login endpoint using injected dependencies
func RegisterLoginRoutes(r *gin.Engine, deps LoginDeps) {
	r.POST("/login", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		type loginReq struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		var req loginReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		// IP-based throttling
		ip := c.ClientIP()
		if !deps.GetLimiter(ip) {
			// Avoid leaking whether the user exists; generic message
			c.Header("Retry-After", "30")
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many requests, slow down"})
			return
		}
		u := strings.ToLower(strings.TrimSpace(req.Username))
		p := req.Password
		// Per-user temporary lockout on repeated failures
		if locked, rem := deps.IsLocked(u); locked {
			c.Header("Retry-After", fmt.Sprintf("%d", int(rem.Seconds())))
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "account temporarily locked due to failed attempts"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var id int64
		var username, name, hash string
		const q = `SELECT id, username, name, password_hash FROM users WHERE username = $1`
		err := dbc.QueryRow(q, u).Scan(&id, &username, &name, &hash)
		if err != nil {
			if err == sql.ErrNoRows {
				// Mitigate timing attacks by doing a dummy bcrypt compare
				deps.DummyBcryptCompare(p)
				deps.RecordFailure(u)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
				return
			}
			log.Printf("[Login] query error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) != nil {
			deps.RecordFailure(u)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}
		// Success: clear failure state
		deps.RecordSuccess(u)
		deps.SetSessionCookie(c, id)
		c.JSON(http.StatusOK, gin.H{"ok": true, "user": gin.H{"id": id, "username": username, "name": name}})
	})
}
