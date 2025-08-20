package tools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ----------------- Helper: extract Jira error details -----------------
// jiraErrorDetailFromBody tries to parse Jira error response JSON and returns a concise string.
// Falls back to the raw response body when structure is unknown.
func jiraErrorDetailFromBody(respBody []byte) string {
	type jiraErr struct {
		ErrorMessages []string          `json:"errorMessages"`
		Errors        map[string]string `json:"errors"`
	}
	var e jiraErr
	if json.Unmarshal(respBody, &e) == nil {
		var parts []string
		if len(e.ErrorMessages) > 0 {
			parts = append(parts, strings.Join(e.ErrorMessages, "; "))
		}
		if len(e.Errors) > 0 {
			kv := make([]string, 0, len(e.Errors))
			for k, v := range e.Errors { kv = append(kv, fmt.Sprintf("%s: %s", k, v)) }
			parts = append(parts, strings.Join(kv, "; "))
		}
		if len(parts) > 0 {
			return strings.Join(parts, " | ")
		}
	}
	return string(respBody)
}

// ----------------- Helper: coerce bool -----------------
func coerceBool(v interface{}) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		if t == "true" || t == "1" || t == "yes" { return true, true }
		if t == "false" || t == "0" || t == "no" { return false, true }
	}
	return false, false
}

// ----------------- POST /rest/api/3/comment/list -----------------
func executeJiraGetCommentsByIdsTool(args map[string]interface{}) (*ToolResponse, error) {
	idsRaw, ok := args["ids"]
	if !ok {
		return &ToolResponse{Success: false, Error: "ids is required (comma-separated string or array)"}, nil
	}
	parseInt := func(s string) (int, error) {
		if s == "" { return 0, fmt.Errorf("empty id") }
		// try fast path
		if n, err := strconv.Atoi(s); err == nil { return n, nil }
		// fallback via json.Number to accept large ints safely
		var num json.Number = json.Number(s)
		if i64, err := num.Int64(); err == nil { return int(i64), nil }
		return 0, fmt.Errorf("invalid id: %s", s)
	}
	ids := make([]int, 0, 8)
	switch v := idsRaw.(type) {
	case []interface{}:
		for _, it := range v {
			switch t := it.(type) {
			case float64:
				ids = append(ids, int(t))
			case int:
				ids = append(ids, t)
			case json.Number:
				if i, err := t.Int64(); err == nil { ids = append(ids, int(i)) } else { return &ToolResponse{Success: false, Error: fmt.Sprintf("invalid id: %v", t)}, nil }
			case string:
				if n, err := parseInt(strings.TrimSpace(t)); err == nil { ids = append(ids, n) } else { return &ToolResponse{Success: false, Error: err.Error()}, nil }
			default:
				return &ToolResponse{Success: false, Error: fmt.Sprintf("unsupported id type: %T", t)}, nil
			}
		}
	case []string:
		for _, s := range v {
			if n, err := parseInt(strings.TrimSpace(s)); err == nil { ids = append(ids, n) } else { return &ToolResponse{Success: false, Error: err.Error()}, nil }
		}
	case string:
		s := strings.TrimSpace(v)
		// Allow users to paste with brackets like "[1,2,3]"
		s = strings.TrimPrefix(s, "[")
		s = strings.TrimSuffix(s, "]")
		if s == "" {
			return &ToolResponse{Success: false, Error: "ids is empty"}, nil
		}
		parts := strings.Split(s, ",")
		for _, p := range parts {
			token := strings.TrimSpace(p)
			if token == "" { continue }
			if n, err := parseInt(token); err == nil { ids = append(ids, n) } else { return &ToolResponse{Success: false, Error: err.Error()}, nil }
		}
	default:
		return &ToolResponse{Success: false, Error: fmt.Sprintf("unsupported ids type: %T (expected array or comma-separated string)", v)}, nil
	}
	if len(ids) == 0 {
		return &ToolResponse{Success: false, Error: "no valid ids provided"}, nil
	}
	body := map[string]interface{}{"ids": ids}
	status, respBody, _, err := jiraDo("POST", "/rest/api/3/comment/list", nil, body)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status < 200 || status >= 300 { return &ToolResponse{Success: false, Error: fmt.Sprintf("jira get comments by ids failed: %d", status)}, nil }
	var obj interface{}
	if err := json.Unmarshal(respBody, &obj); err != nil { return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil }
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- GET list comments for issue -----------------
func executeJiraListCommentsTool(args map[string]interface{}) (*ToolResponse, error) {
	issueIdOrKey, _ := args["issueIdOrKey"].(string)
	if issueIdOrKey == "" {
		// allow alias "issue"
		issueIdOrKey, _ = args["issue"].(string)
	}
	if issueIdOrKey == "" { return &ToolResponse{Success: false, Error: "issueIdOrKey is required"}, nil }
	q := url.Values{}
	if v, ok := args["startAt"].(float64); ok { q.Set("startAt", fmt.Sprintf("%d", int(v))) }
	if v, ok := args["maxResults"].(float64); ok { q.Set("maxResults", fmt.Sprintf("%d", int(v))) }
	if v, ok := args["orderBy"].(string); ok && v != "" { q.Set("orderBy", v) }
	if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }
	status, body, _, err := jiraDo("GET", "/rest/api/3/issue/"+url.PathEscape(issueIdOrKey)+"/comment", q, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status < 200 || status >= 300 { return &ToolResponse{Success: false, Error: fmt.Sprintf("jira list comments failed: %d", status)}, nil }
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil { return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil }
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- POST add comment -----------------
func executeJiraAddCommentTool(args map[string]interface{}) (*ToolResponse, error) {
	issueIdOrKey, _ := args["issueIdOrKey"].(string)
	if issueIdOrKey == "" { issueIdOrKey, _ = args["issue"].(string) }
	if issueIdOrKey == "" { return &ToolResponse{Success: false, Error: "issueIdOrKey is required"}, nil }

	body := map[string]interface{}{}
	if rawBody, ok := args["body"]; ok {
		if processedBody, shouldSet := processADFValue(rawBody); shouldSet {
			body["body"] = processedBody
		}
	}
	if v, ok := args["visibility"].(map[string]interface{}); ok { body["visibility"] = v }
	if v, ok := args["properties"].([]interface{}); ok { body["properties"] = v }
	if v, ok := args["expand"].(string); ok && v != "" { body["expand"] = v }
	if _, exists := body["body"]; !exists {
		return &ToolResponse{Success: false, Error: "body is required (string or Atlassian doc)"}, nil
	}
	status, respBody, _, err := jiraDo("POST", "/rest/api/3/issue/"+url.PathEscape(issueIdOrKey)+"/comment", nil, body)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status != http.StatusCreated && !(status >= 200 && status < 300) {
		detail := jiraErrorDetailFromBody(respBody)
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira add comment failed: %d - %s", status, detail)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(respBody, &obj); err != nil { return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil }
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- GET a comment -----------------
func executeJiraGetCommentTool(args map[string]interface{}) (*ToolResponse, error) {
	issueIdOrKey, _ := args["issueIdOrKey"].(string)
	if issueIdOrKey == "" { issueIdOrKey, _ = args["issue"].(string) }
	id, _ := args["id"].(string)
	if id == "" { id, _ = args["commentId"].(string) }
	if issueIdOrKey == "" || id == "" { return &ToolResponse{Success: false, Error: "issueIdOrKey and id are required"}, nil }
	q := url.Values{}
	if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }
	status, body, _, err := jiraDo("GET", "/rest/api/3/issue/"+url.PathEscape(issueIdOrKey)+"/comment/"+url.PathEscape(id), q, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status == http.StatusNotFound { return &ToolResponse{Success: false, Error: "comment not found"}, nil }
	if status < 200 || status >= 300 { return &ToolResponse{Success: false, Error: fmt.Sprintf("jira get comment failed: %d", status)}, nil }
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil { return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil }
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- PUT update comment -----------------
func executeJiraUpdateCommentTool(args map[string]interface{}) (*ToolResponse, error) {
	issueIdOrKey, _ := args["issueIdOrKey"].(string)
	if issueIdOrKey == "" { issueIdOrKey, _ = args["issue"].(string) }
	id, _ := args["id"].(string)
	if id == "" { id, _ = args["commentId"].(string) }
	if issueIdOrKey == "" || id == "" { return &ToolResponse{Success: false, Error: "issueIdOrKey and id are required"}, nil }
	q := url.Values{}
	if b, ok := coerceBool(args["notifyUsers"]); ok { q.Set("notifyUsers", fmt.Sprintf("%t", b)) }
	if b, ok := coerceBool(args["overrideEditableFlag"]); ok { q.Set("overrideEditableFlag", fmt.Sprintf("%t", b)) }
	if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }
	body := map[string]interface{}{}
	if rawBody, ok := args["body"]; ok {
		if processedBody, shouldSet := processADFValue(rawBody); shouldSet {
			body["body"] = processedBody
		}
	}
	if v, ok := args["visibility"].(map[string]interface{}); ok { body["visibility"] = v }
	if v, ok := args["properties"].([]interface{}); ok { body["properties"] = v }
	if _, exists := body["body"]; !exists {
		return &ToolResponse{Success: false, Error: "body is required (string or Atlassian doc)"}, nil
	}
	status, respBody, _, err := jiraDo("PUT", "/rest/api/3/issue/"+url.PathEscape(issueIdOrKey)+"/comment/"+url.PathEscape(id), q, body)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status < 200 || status >= 300 {
		detail := jiraErrorDetailFromBody(respBody)
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira update comment failed: %d - %s", status, detail)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(respBody, &obj); err != nil { return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil }
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- DELETE comment -----------------
func executeJiraDeleteCommentTool(args map[string]interface{}) (*ToolResponse, error) {
	issueIdOrKey, _ := args["issueIdOrKey"].(string)
	if issueIdOrKey == "" { issueIdOrKey, _ = args["issue"].(string) }
	id, _ := args["id"].(string)
	if id == "" { id, _ = args["commentId"].(string) }
	if issueIdOrKey == "" || id == "" { return &ToolResponse{Success: false, Error: "issueIdOrKey and id are required"}, nil }
	status, respBody, _, err := jiraDo("DELETE", "/rest/api/3/issue/"+url.PathEscape(issueIdOrKey)+"/comment/"+url.PathEscape(id), nil, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status == http.StatusNoContent { return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "comment deleted"}}, nil }
	if status < 200 || status >= 300 {
		detail := jiraErrorDetailFromBody(respBody)
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira delete comment failed: %d - %s", status, detail)}, nil
	}
	return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "comment deleted"}}, nil
}

func init() {
	tools["jira_get_comments_by_ids"] = Tool{
		Name:        "jira_get_comments_by_ids",
		Description: "Get a paginated list of comments by comment IDs",
		Help: `Usage: /tool jira_get_comments_by_ids --ids <id1,id2,...>
		Examples:
		  /tool jira_get_comments_by_ids --ids 10000,10001
		Note: Comma-separated string is recommended for /tool commands; API clients may send a native array.`,
		Parameters: map[string]string{"ids": "Comma-separated comment IDs or array (required)"},
	}
	toolExecutors["jira_get_comments_by_ids"] = executeJiraGetCommentsByIdsTool

	tools["jira_list_comments"] = Tool{
		Name:        "jira_list_comments",
		Description: "List all comments for an issue",
		Help: `Usage: /tool jira_list_comments --issueIdOrKey <ISSUE> [--startAt <n>] [--maxResults <n>] [--orderBy <field>] [--expand <fields>]
		Aliases: --issue`,
		Parameters: map[string]string{
			"issueIdOrKey": "Issue key or ID (required)",
			"startAt":      "Start index",
			"maxResults":   "Max results",
			"orderBy":      "Order by field",
			"expand":       "Expand fields",
		},
	}
	toolExecutors["jira_list_comments"] = executeJiraListCommentsTool

	tools["jira_add_comment"] = Tool{
		Name:        "jira_add_comment",
		Description: "Add a comment to an issue",
		Help: `Usage: /tool jira_add_comment --issueIdOrKey <ISSUE> --body <string|object> [--visibility <obj>] [--properties <array>] [--expand <fields>]\nAliases: --issue` ,
		Parameters: map[string]string{
			"issueIdOrKey": "Issue key or ID (required)",
			"body":         "Comment body (string or Atlassian doc object, required)",
			"visibility":   "Visibility object",
			"properties":   "Array of EntityProperty objects",
			"expand":       "Expand fields",
		},
	}
	toolExecutors["jira_add_comment"] = executeJiraAddCommentTool

	tools["jira_get_comment"] = Tool{
		Name:        "jira_get_comment",
		Description: "Get a single comment by ID",
		Help: `Usage: /tool jira_get_comment --issueIdOrKey <ISSUE> --id <commentId> [--expand <fields>]\nAliases: --issue, --commentId` ,
		Parameters: map[string]string{
			"issueIdOrKey": "Issue key or ID (required)",
			"id":           "Comment ID (required)",
			"expand":       "Expand fields",
		},
	}
	toolExecutors["jira_get_comment"] = executeJiraGetCommentTool

	tools["jira_update_comment"] = Tool{
		Name:        "jira_update_comment",
		Description: "Update a comment",
		Help: `Usage: /tool jira_update_comment --issueIdOrKey <ISSUE> --id <commentId> --body <string|object> [--notifyUsers <bool>] [--overrideEditableFlag <bool>] [--expand <fields>]\nAliases: --issue, --commentId` ,
		Parameters: map[string]string{
			"issueIdOrKey":        "Issue key or ID (required)",
			"id":                  "Comment ID (required)",
			"body":                "Updated body (required)",
			"notifyUsers":         "Notify users (bool)",
			"overrideEditableFlag": "Override editable flag (bool)",
			"expand":              "Expand fields",
		},
	}
	toolExecutors["jira_update_comment"] = executeJiraUpdateCommentTool

	tools["jira_delete_comment"] = Tool{
		Name:        "jira_delete_comment",
		Description: "Delete a comment",
		Help: `Usage: /tool jira_delete_comment --issueIdOrKey <ISSUE> --id <commentId>\nAliases: --issue, --commentId` ,
		Parameters: map[string]string{
			"issueIdOrKey": "Issue key or ID (required)",
			"id":           "Comment ID (required)",
		},
	}
	toolExecutors["jira_delete_comment"] = executeJiraDeleteCommentTool
}
