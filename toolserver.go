package toolserver

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/api/tool", toolHandler)
	fmt.Println("Tool server started on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}

func toolHandler(w http.ResponseWriter, r *http.Request) {
	taskQuery := r.URL.Query().Get("task")
	if taskQuery == "" {
		fmt.Fprintln(w, "No task provided")
		return
	}
	response := fmt.Sprintf("Tool executed successfully for task: %s", taskQuery)
	fmt.Fprintln(w, response)
}
