package routes

import (
	"net/http"
	"strings"

	"go-thing/db"
	"go-thing/utility"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

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
		p := req.Password
		if u == "" || n == "" || p == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "all fields are required"})
			return
		}
		if !utility.IsValidEmail(u) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username must be a valid email"})
			return
		}
		if len(p) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
		if err != nil {
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
			if utility.IsUniqueViolation(err) {
				c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
}
