package routes

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"go-thing/db"
	"go-thing/utility"
)

// RegisterMeRoutes registers the current user endpoint: GET /me
func RegisterMeRoutes(r *gin.Engine, sessionSecret []byte) {
	r.GET("/me", func(c *gin.Context) {
		uid, ok := utility.ParseSession(c.Request, sessionSecret)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database not initialized"})
			return
		}
		var username, name string
		if err := dbc.QueryRow(`SELECT username, name FROM users WHERE id=$1`, uid).Scan(&username, &name); err != nil {
			if err == sql.ErrNoRows {
				log.Printf("[Me] WARN: valid session for non-existent user ID %d", uid)
				utility.ClearSessionCookie(c)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
				return
			}
			log.Printf("[Me] query error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": uid, "username": username, "name": name})
	})
}
