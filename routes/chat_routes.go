package routes

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go-thing/utility"
)

// RegisterChatRoutes registers the /chat endpoint
func RegisterChatRoutes(r *gin.Engine, getOrCreateAnyThread func() (int64, error)) {
	r.POST("/chat", func(c *gin.Context) {
		var req struct {
			Message string `json:"message" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		threadID, err := getOrCreateAnyThread()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to ensure thread"})
			return
		}
		if err := utility.StoreMessage(threadID, "user", req.Message, map[string]interface{}{"source": "http"}); err != nil {
			log.Printf("[DB] Failed to store user message: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to persist user message"})
			return
		}
		// Load last persisted context for this thread
		initialCtx, err := utility.GetLastContextForThread(threadID)
		if err != nil {
			log.Printf("[Context] load error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load conversation context"})
			return
		}
		log.Printf("[Context] Using initial current_context for HTTP: %v", initialCtx)
		resp, updatedCtx, err := utility.GeminiAPIHandler(c.Request.Context(), req.Message, initialCtx)
		if err != nil {
			log.Printf("[Chat] gemini error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process message. Please try again later."})
			return
		}
		if strings.TrimSpace(resp) == "" {
			resp = "**No response available. Please try again.**"
		}
		log.Printf("[Context] Persisting updated current_context (HTTP): %v", updatedCtx)
		if err := utility.StoreMessage(threadID, "assistant", resp, map[string]interface{}{"source": "http", "current_context": updatedCtx}); err != nil {
			log.Printf("[DB] Failed to store assistant message: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to persist assistant message"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"response": resp, "thread_id": threadID})
	})
}
