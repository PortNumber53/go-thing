package routes

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	toolsrv "go-thing/tools"
)

// RegisterShellRoutes registers shell session management routes and the WebSocket endpoint.
// The caller must provide a configured websocket.Upgrader (e.g., with a proper CheckOrigin).
func RegisterShellRoutes(r *gin.Engine, upgrader *websocket.Upgrader) {
	// List sessions
	r.GET("/shell/sessions", func(c *gin.Context) {
		ids := toolsrv.GetShellBroker().List()
		c.JSON(http.StatusOK, gin.H{"sessions": ids})
	})

	// Create or get a session
	r.POST("/shell/sessions", func(c *gin.Context) {
		var req struct {
			ID     string `json:"id" binding:"required"`
			Subdir string `json:"subdir"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if strings.TrimSpace(req.ID) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "session id cannot be empty"})
			return
		}
		if _, err := toolsrv.GetShellBroker().CreateOrGet(req.ID, req.Subdir); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "id": req.ID})
	})

	// Delete a session
	r.DELETE("/shell/sessions/:id", func(c *gin.Context) {
		id := c.Param("id")
		if err := toolsrv.GetShellBroker().Close(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// WebSocket attach to a shell session (creates if missing)
	r.GET("/shell/ws/:id", func(c *gin.Context) {
		id := c.Param("id")
		// Create if missing with default workdir
		sess, err := toolsrv.GetShellBroker().CreateOrGet(id, "")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Printf("[ShellWS] upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Subscribe to output
		outCh := sess.Subscribe()
		defer sess.Unsubscribe(outCh)

		// Writer goroutine
		done := make(chan struct{})
		var once sync.Once
		closeDone := func() { once.Do(func() { close(done) }) }
		var writeMu sync.Mutex
		go func() {
			for {
				select {
				case data, ok := <-outCh:
					if !ok {
						// Serialize WebSocket writes with a shared mutex to avoid concurrent writer issues.
						writeMu.Lock()
						_ = conn.WriteMessage(websocket.TextMessage, []byte("[session closed]\n"))
						writeMu.Unlock()
						_ = conn.Close()
						closeDone()
						return
					}
					writeMu.Lock()
					err := conn.WriteMessage(websocket.BinaryMessage, data)
					writeMu.Unlock()
					if err != nil {
						log.Printf("[ShellWS %s] write error: %v", id, err)
						_ = conn.Close()
						closeDone()
						return
					}
				case <-done:
					return
				}
			}
		}()

		// Read loop -> enqueue to shell with heartbeat and backpressure handling
		const pongWait = 60 * time.Second
		conn.SetReadDeadline(time.Now().Add(pongWait))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(pongWait))
			return nil
		})

	ReadLoop:
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("[ShellWS %s] read error: %v", id, err)
				}
				break
			}
			if mt == websocket.TextMessage || mt == websocket.BinaryMessage {
				if !sess.Enqueue(msg) {
					log.Printf("[ShellWS %s] input queue is full, closing connection.", id)
					writeMu.Lock()
					_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "Input queue full"))
					writeMu.Unlock()
					break ReadLoop
				}
			}
		}
		closeDone()
	})
}
