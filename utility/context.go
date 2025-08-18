package utility

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"go-thing/db"
)

// GetLastContextForThread loads the most recent message metadata for a thread and extracts current_context
func GetLastContextForThread(threadID int64) ([]string, error) {
	dbc := db.Get()
	if dbc == nil {
		return nil, fmt.Errorf("db not initialized")
	}
	// Fetch the most recent message that actually has a non-empty current_context
	// Using JSONB operators to ensure we don't pick up the latest user message w/o context
	var metaBytes []byte
	err := dbc.QueryRow(
		`SELECT metadata FROM messages
         WHERE thread_id=$1
           AND role = 'assistant'
           AND metadata ? 'current_context'
           AND (
             CASE WHEN jsonb_typeof(metadata->'current_context') = 'array'
                  THEN jsonb_array_length(metadata->'current_context')
                  ELSE 0
             END
           ) > 0
         ORDER BY id DESC LIMIT 1`, threadID,
	).Scan(&metaBytes)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var meta struct {
		CurrentContext []string `json:"current_context"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}
	if meta.CurrentContext != nil {
		// The caller will sanitize the context (trim/remove empties) via sanitizeContextFacts().
		return meta.CurrentContext, nil
	}
	return nil, nil
}

// MergeStringSets merges two string slices, de-duplicating while preserving order (favoring later slice order at the end)
func MergeStringSets(base []string, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	res := make([]string, 0, len(base)+len(extra))
	for _, v := range base {
		if !seen[v] {
			seen[v] = true
			res = append(res, v)
		}
	}
	for _, v := range extra {
		if !seen[v] {
			seen[v] = true
			res = append(res, v)
		}
	}
	return res
}
