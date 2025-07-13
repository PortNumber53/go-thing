package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("AI Agent started. Enter tasks (type 'exit' to quit):")

	for scanner.Scan() {
		task := scanner.Text()
		if task == "exit" {
			fmt.Println("Exiting agent.")
			return
		}
		fmt.Printf("Handling task: %s\n", task)
		// Simulate calling a custom API tool
		resp, err := http.Get("http://localhost:8080/api/tool?task=" + url.QueryEscape(task)) // Replace with your actual API endpoint
		if err != nil {
			fmt.Printf("Error calling tool: %v\n", err)
		} else {
			fmt.Printf("Tool response status: %s\n", resp.Status)
			resp.Body.Close() // Ensure body is closed to avoid leaks
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading input: %v\n", err)
	}
}
