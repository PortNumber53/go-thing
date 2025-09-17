package routes

import (
	"net/http"

	"go-thing/utility"

	"github.com/gin-gonic/gin"
)

// RegisterLogoutRoutes registers the CSRF-protected /logout endpoint
func RegisterLogoutRoutes(r *gin.Engine) {
	r.POST("/logout", func(c *gin.Context) {
		if !utility.ValidateCSRF(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "csrf invalid"})
			return
		}
		utility.ClearSessionCookie(c)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
}
