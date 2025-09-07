package routes

import (
    "errors"
    "log"
    "net/http"
    "regexp"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v5/pgconn"
    "golang.org/x/crypto/bcrypt"
    "go-thing/db"
    "go-thing/utility"
)

var (
	emailRegexCompiled = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// RegisterSignupRoutes registers the CSRF-protected signup endpoint
func RegisterSignupRoutes(r *gin.Engine) {
	r.POST("/signup", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		type signupReq struct {
			Username string `json:"username" binding:"required"`
			Name     string `json:"name" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		var req signupReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		u := strings.ToLower(strings.TrimSpace(req.Username))
		n := strings.TrimSpace(req.Name)
		p := strings.TrimSpace(req.Password)
		if u == "" || n == "" || p == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "all fields are required"})
			return
		}
		if !emailRegexCompiled.MatchString(u) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username must be a valid email"})
			return
		}
		if len(p) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("[Signup] bcrypt error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process password"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		const q = `INSERT INTO users (username, name, password_hash) VALUES ($1, $2, $3)`
		if _, err := dbc.Exec(q, u, n, string(hash)); err != nil {
			if isUniqueViolation(err) {
				c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
				return
			}
			le := strings.ToLower(err.Error())
			if strings.Contains(le, "unique") || strings.Contains(le, "duplicate") || strings.Contains(le, "23505") {
				c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
				return
			}
			log.Printf("[Signup] insert error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
}
