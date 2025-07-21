package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"path/filepath"
	"google.golang.org/genai"
)

type Config struct {
    GEMINI_API_KEY string `json:"GEMINI_API_KEY"`
    WriteDir string `json:"write_dir"`
}

func main() {
	// Read config file
	configPath := os.ExpandEnv("$HOME/.config/go-thing/config")
	configData, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("Error reading config: %v\n", err)
		return
	}
	var config Config
	err = json.Unmarshal(configData, &config)
	if err != nil {
		fmt.Printf("Error parsing config JSON: %v\n", err)
		return
	}
	geminiAPIKey := config.GEMINI_API_KEY
	writeDir := config.WriteDir
	if geminiAPIKey == "" {
		geminiAPIKey = os.Getenv("GEMINI_API_KEY")
	}
	if writeDir == "" {
		fmt.Println("write_dir not found in config, using default or error handling")
		// Add default or handle as needed
	}

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("AI Agent started. Enter tasks (type 'exit' to quit):")

	const systemPrompt = `You are an AI agent with access to the following tools:
- write_file: Writes content to a file within a specified directory. Usage: Only respond with 'use write_file <path> <content>' if a write is needed and it is the ONLY action required for the query. After executing a tool, provide the final response without further tool calls. Always check if a tool is necessary. If asked about tools, list and describe them without any 'use' commands.
`

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				fmt.Printf("Error reading input: %v\n", err)
			}
			break // Handle end of input or error
		}
		task := scanner.Text()
		if task == "exit" {
			fmt.Println("Exiting agent.")
			return
		}

		// Call Gemini API with the task
		ctx := context.Background()
		client, err := genai.NewClient(ctx, &genai.ClientConfig{APIKey: geminiAPIKey, Backend: genai.BackendGeminiAPI})
		if err != nil {
			fmt.Printf("Error creating Gemini client: %v\n", err)
			continue
		}
		resp, err := client.Models.GenerateContent(ctx, "gemini-1.5-flash", genai.Text(systemPrompt + "User query: " + task), nil)
		if err != nil {
			fmt.Printf("Error calling Gemini API: %v\n", err)
			continue
		}
		geminiResponse := resp.Text()
		if strings.HasPrefix(geminiResponse, "use write_file ") {
			toolArgs := strings.TrimPrefix(geminiResponse, "use write_file ")
			argParts := strings.SplitN(toolArgs, " ", 2)
			if len(argParts) == 2 {
				filePath := argParts[0]
				content := argParts[1]
				fullPath := filepath.Join(writeDir, filePath)
				absFullPath, err := filepath.Abs(fullPath)
				if err != nil {
					fmt.Printf("Error getting absolute path: %v\n", err)
					geminiResponse = "Path error occurred. No write performed. Final response: Operation failed due to path issue."
				} else {
					absWriteDir, err := filepath.Abs(writeDir)
					if err != nil {
						fmt.Printf("Error getting absolute write directory: %v\n", err)
						geminiResponse = "Directory path error. No write performed. Final response: Operation failed due to directory issue."
					} else {
						fmt.Printf("Debug: write_dir = %s, full_path = %s, abs_write_dir = %s, abs_full_path = %s\n", writeDir, fullPath, absWriteDir, absFullPath)
						if !strings.HasPrefix(absFullPath, absWriteDir) {
							fmt.Println("Write denied: path outside allowed directory")
							geminiResponse = "Write denied due to path restriction. Final response: Cannot write file outside allowed directory."
						} else {
							err = os.WriteFile(fullPath, []byte(content), 0644)
							if err != nil {
								fmt.Printf("Error writing file: %v\n", err)
								geminiResponse = "Error writing file: " + err.Error() + " Final response: Write operation failed."
							} else {
								fmt.Println("File written successfully")
								geminiResponse = "File written successfully. Final response: Write operation completed."
							}
						}
					}
				}
			} else {
				fmt.Println("Invalid tool arguments")
				geminiResponse = "Invalid tool arguments provided. Final response: Tool call failed."
			}
		} // No else needed; if no tool use, keep original response
		fmt.Printf("Final Gemini response: %s\n", geminiResponse)
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading input: %v\n", err)
	}
}
