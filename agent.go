package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gin-gonic/gin"
	genai "google.golang.org/genai"
)

var (
	configOnce sync.Once
	configData map[string]string
	configErr  error
)

func loadConfig() (map[string]string, error) {
	configOnce.Do(func() {
		path := os.ExpandEnv("$HOME/.config/go-thing/config")
		b, err := ioutil.ReadFile(path)
		if err != nil {
			configErr = err
			return
		}
		err = json.Unmarshal(b, &configData)
		if err != nil {
			configErr = err
		}
	})
	return configData, configErr
}

// Gemini API call logic
func geminiAPIHandler(ctx context.Context, query string) (string, error) {
	cfg, err := loadConfig()
	if err != nil {
		return "", err
	}
	apiKey := cfg["GEMINI_API_KEY"]
	if apiKey == "" {
		return "", fmt.Errorf("GEMINI_API_KEY missing in config")
	}
	client, err := genai.NewClient(ctx, &genai.ClientConfig{APIKey: apiKey})
	if err != nil {
		return "", err
	}
	// Add system prompt for Markdown formatting
	systemPrompt := "You are an AI assistant. Always respond using properly formatted Markdown."
	fullPrompt := systemPrompt + "\n\n" + query
	resp, err := client.Models.GenerateContent(ctx, "gemini-2.5-flash", genai.Text(fullPrompt), nil)
	if err != nil {
		return "", err
	}
	return resp.Text(), nil
}

func main() {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI Agent Chat</title>
<style>
body { font-family: sans-serif; margin: 2em; }
#chat { border: 1px solid #ccc; padding: 1em; height: 300px; overflow-y: auto; margin-bottom: 1em; }
#input { width: 80%; }
.agent-msg { background: #f6f8fa; padding: 0.5em; border-radius: 4px; margin: 0.5em 0; }
.user-msg { background: #e6f7ff; padding: 0.5em; border-radius: 4px; margin: 0.5em 0; text-align: right; }
</style>
<!-- Marked.js for Markdown rendering -->
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
</head>
<body>
<h2>AI Agent Chat</h2>
<div id="chat"></div>
<input id="input" type="text" placeholder="Type a message..." autofocus />
<button onclick="sendMsg()">Send</button>
<script>
document.addEventListener('DOMContentLoaded', function() {
const chat = document.getElementById('chat');
const input = document.getElementById('input');
function append(msg, who) {
if (!chat) return;
const div = document.createElement('div');
if (who === 'Agent') {
  div.className = 'agent-msg';
  // Render Markdown to HTML
  div.innerHTML = marked.parse(msg);
} else if (who === 'You') {
  div.className = 'user-msg';
  div.textContent = who + ': ' + msg;
} else {
  div.textContent = (who ? who+': ' : '') + msg;
}
chat.appendChild(div);
chat.scrollTop = chat.scrollHeight;
}
function sendMsg() {
if (!input) return;
const msg = input.value.trim();
if (!msg) return;
append(msg, 'You');
input.value = '';
fetch('/chat', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ message: msg })
})
.then(r => r.json())
.then(data => append(data.reply, 'Agent'));
}
if (input) {
input.addEventListener('keydown', e => { if (e.key === 'Enter') sendMsg(); });
window.sendMsg = sendMsg;
}
});
</script>
</body>
</html>
`)
	})

	r.POST("/chat", func(c *gin.Context) {
		var req struct {
			Message string `json:"message"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}
		log.Printf("[POST /chat] Received: %q", req.Message)
		// Call Gemini API
		reply, err := geminiAPIHandler(context.Background(), req.Message)
		if err != nil {
			log.Printf("[POST /chat] Gemini error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"reply": "[Gemini error] " + err.Error()})
			return
		}
		log.Printf("[POST /chat] Gemini reply: %q", reply)
		c.JSON(http.StatusOK, gin.H{"reply": reply})
	})

	r.POST("/webhook", func(c *gin.Context) {
		// Placeholder for Slack webhook integration
		c.JSON(http.StatusOK, gin.H{"status": "webhook received"})
	})

	r.Run("0.0.0.0:7865")
}
