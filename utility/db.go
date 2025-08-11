package utility

import (
	"encoding/json"
	"fmt"
	"log"

	"go-thing/db"
)

// CreateNewThread creates a new thread row and returns its ID.
func CreateNewThread(title string) (int64, error) {
	dbc := db.Get()
	if dbc == nil {
		return 0, fmt.Errorf("db not initialized")
	}
	var id int64
	err := dbc.QueryRow(`INSERT INTO threads (title) VALUES ($1) RETURNING id`, title).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// StoreMessage inserts a message into the specified thread.
func StoreMessage(threadID int64, role, content string, metadata map[string]interface{}) error {
	dbc := db.Get()
	if dbc == nil {
		return fmt.Errorf("storeMessage failed: database not initialized")
	}
	// Marshal metadata to JSONB via string parameter
	var metaJSON string = "{}"
	if metadata != nil {
		b, err := json.Marshal(metadata)
		if err != nil {
			log.Printf("[DB] Failed to marshal metadata: %v", err)
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		metaJSON = string(b)
	}
	if _, err := dbc.Exec(`INSERT INTO messages (thread_id, role, content, metadata) VALUES ($1,$2,$3,$4::jsonb)`, threadID, role, content, metaJSON); err != nil {
		log.Printf("[DB] insert message failed: %v", err)
		return err
	}
	return nil
}
