package routes

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-thing/db"
	toolsrv "go-thing/tools"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// parseInt returns int or 0
func parseInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// RegisterShellRoutes registers shell session management routes and the WebSocket endpoint.
// The caller must provide a configured websocket.Upgrader (e.g., with a proper CheckOrigin).
func RegisterShellRoutes(r *gin.Engine, requireAuth gin.HandlerFunc, upgrader *websocket.Upgrader) {
	auth := r.Group("/", requireAuth)
	// List sessions
	auth.GET("/shell/sessions", func(c *gin.Context) {
		ids := toolsrv.GetShellBroker().List()
		c.JSON(http.StatusOK, gin.H{"sessions": ids})
	})

	// Create or get a session
	auth.POST("/shell/sessions", func(c *gin.Context) {
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
	auth.DELETE("/shell/sessions/:id", func(c *gin.Context) {
		id := c.Param("id")
		if err := toolsrv.GetShellBroker().Close(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// WebSocket attach to a shell session (creates if missing)
	auth.GET("/shell/ws/:id", func(c *gin.Context) {
		id := c.Param("id")
		// Read user's docker settings to ensure/start the right container
		v, ok := c.Get("userID")
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not logged in"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id"})
			return
		}
		dbc := db.Get()
		if dbc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "db not initialized"})
			return
		}
		var settingsRaw sql.NullString
		if err := dbc.QueryRow(`SELECT settings::text FROM users WHERE id=$1`, uid).Scan(&settingsRaw); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load settings"})
			return
		}
		var settings map[string]interface{}
		if settingsRaw.Valid && strings.TrimSpace(settingsRaw.String) != "" {
			if err := json.Unmarshal([]byte(settingsRaw.String), &settings); err != nil {
				log.Printf("[ShellWS] unmarshal settings err: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse settings"})
				return
			}
		}
		dockerVal, _ := settings["docker"].(map[string]interface{})
		container, _ := dockerVal["container"].(string)
		image, _ := dockerVal["image"].(string)
		args, _ := dockerVal["args"].(string)
		if strings.TrimSpace(container) == "" || strings.TrimSpace(image) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "docker container/image not configured"})
			return
		}
		if _, err := toolsrv.StartContainerWithSettings(container, image, args); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		sess, err := toolsrv.GetShellBroker().CreateOrGetInContainer(container, id, "")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Apply initial size from query if provided (avoid 0x0 default)
		if colsQ := strings.TrimSpace(c.Query("cols")); colsQ != "" {
			if rowsQ := strings.TrimSpace(c.Query("rows")); rowsQ != "" {
				if cc, rr := parseInt(colsQ), parseInt(rowsQ); cc > 0 && rr > 0 {
					_ = sess.Resize(cc, rr)
				}
			}
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

		// Keepalive ping goroutine to ensure the connection stays open when idle
		go func() {
			pingTicker := time.NewTicker(30 * time.Second)
			defer pingTicker.Stop()
			for {
				select {
				case <-done:
					return
				case <-pingTicker.C:
					writeMu.Lock()
					_ = conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
					writeMu.Unlock()
				}
			}
		}()

		// Read loop -> enqueue to shell with heartbeat and backpressure handling
		const pongWait = 90 * time.Second
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
			if mt == websocket.TextMessage {
				// Try to detect resize control messages: {"type":"resize","cols":80,"rows":24}
				var ctrl struct {
					Type string `json:"type"`
					Cols int    `json:"cols"`
					Rows int    `json:"rows"`
				}
				if err := json.Unmarshal(msg, &ctrl); err == nil && ctrl.Type == "resize" {
					_ = sess.Resize(ctrl.Cols, ctrl.Rows)
					continue
				}
				// Treat other text frames as input (supports non-binary clients)
				if !sess.Enqueue(msg) {
					log.Printf("[ShellWS %s] input queue is full, closing connection.", id)
					writeMu.Lock()
					_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "Input queue full"))
					writeMu.Unlock()
					break ReadLoop
				}
			} else if mt == websocket.BinaryMessage {
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
