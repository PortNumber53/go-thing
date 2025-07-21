package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	genai "google.golang.org/genai"
)

func toolHandler(w http.ResponseWriter, r *http.Request) {
	taskQuery := r.URL.Query().Get("task")
	if taskQuery == "" {
		fmt.Fprintln(w, "No task provided")
		return
	}

	parts := strings.SplitN(taskQuery, " ", 2) // Split into tool name and arguments
	if len(parts) < 2 {
		fmt.Fprintln(w, "Invalid task format")
		return
	}

	toolName := parts[0]
	args := parts[1]

	if toolName == "write_file" {
		// Parse arguments: expect "path content"
		argParts := strings.SplitN(args, " ", 2)
		if len(argParts) < 2 {
			fmt.Fprintln(w, "write_file requires path and content")
			return
		}
		filePath := argParts[0]
		content := argParts[1]

		// Read config
		configData, err := os.ReadFile(os.ExpandEnv("$HOME/.config/go-thing/config"))
		if err != nil {
			http.Error(w, "Config file error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		var config map[string]string
		err = json.Unmarshal(configData, &config)
		if err != nil {
			http.Error(w, "Config parse error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeDir, ok := config["write_dir"]
		if !ok {
			http.Error(w, "write_dir not configured", http.StatusInternalServerError)
			return
		}

		// Check if filePath is within writeDir
		absWriteDir, _ := filepath.Abs(writeDir)
		absFilePath, _ := filepath.Abs(filePath)
		if !strings.HasPrefix(absFilePath, absWriteDir) {
			http.Error(w, "Write denied: path outside allowed directory", http.StatusForbidden)
			return
		}

		// Write the file
		err = os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "File written successfully")
		return
	}

	// Handle other tools or default response
	response := fmt.Sprintf("Tool executed successfully for task: %s", taskQuery)
	fmt.Fprintln(w, response)
}

// Add new function for Gemini API call
func geminiAPIHandler(ctx context.Context, query string) (string, error) {
	client, err := genai.NewClient(ctx, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Models.GenerateContent(ctx, "gemini-2.5-flash", genai.Text(query), nil)
	if err != nil {
		return "", err
	}
	return resp.Text(), nil
}

func main() {
	http.HandleFunc("/api/tool", toolHandler)
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
