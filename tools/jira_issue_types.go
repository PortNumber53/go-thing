package tools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// ----------------- Issue Types: List all -----------------
func executeJiraListIssueTypesTool(args map[string]interface{}) (*ToolResponse, error) {
	status, body, _, err := jiraDo("GET", "/rest/api/3/issuetype", nil, nil)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira list issue types failed: %d", status)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil
	}
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- Issue Types: Create -----------------
func executeJiraCreateIssueTypeTool(args map[string]interface{}) (*ToolResponse, error) {
	name, _ := args["name"].(string)
	if name == "" {
		return &ToolResponse{Success: false, Error: "name is required"}, nil
	}
	body := map[string]interface{}{"name": name}
	if v, ok := args["description"].(string); ok && v != "" { body["description"] = v }
	if v, ok := args["type"].(string); ok && v != "" { body["type"] = v }
	// hierarchyLevel is an int
	if f, ok := args["hierarchyLevel"].(float64); ok { body["hierarchyLevel"] = int(f) }
	if i, ok := args["hierarchyLevel"].(int); ok { body["hierarchyLevel"] = i }

	status, respBody, _, err := jiraDo("POST", "/rest/api/3/issuetype", nil, body)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira create issue type failed: %d", status)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(respBody, &obj); err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil
	}
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- Issue Types: For Project -----------------
func executeJiraGetIssueTypesForProjectTool(args map[string]interface{}) (*ToolResponse, error) {
	// projectId required (as integer per docs)
	q := url.Values{}
	// Accept as string or number
	if s, ok := args["projectId"].(string); ok && s != "" {
		q.Set("projectId", s)
	} else if f, ok := args["projectId"].(float64); ok {
		q.Set("projectId", strconv.Itoa(int(f)))
	} else if i, ok := args["projectId"].(int); ok {
		q.Set("projectId", strconv.Itoa(i))
	} else {
		return &ToolResponse{Success: false, Error: "projectId is required"}, nil
	}
	// optional level
	if f, ok := args["level"].(float64); ok { q.Set("level", strconv.Itoa(int(f))) }
	if i, ok := args["level"].(int); ok { q.Set("level", strconv.Itoa(i)) }

	status, body, _, err := jiraDo("GET", "/rest/api/3/issuetype/project", q, nil)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira get issue types for project failed: %d", status)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil
	}
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- Issue Types: Get by ID -----------------
func executeJiraGetIssueTypeTool(args map[string]interface{}) (*ToolResponse, error) {
	id, _ := args["id"].(string)
	if id == "" {
		return &ToolResponse{Success: false, Error: "id is required"}, nil
	}
	status, body, _, err := jiraDo("GET", "/rest/api/3/issuetype/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status == http.StatusNotFound {
		return &ToolResponse{Success: false, Error: "issue type not found"}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira get issue type failed: %d", status)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil
	}
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- Issue Types: Update -----------------
func executeJiraUpdateIssueTypeTool(args map[string]interface{}) (*ToolResponse, error) {
	id, _ := args["id"].(string)
	if id == "" { return &ToolResponse{Success: false, Error: "id is required"}, nil }
	body := map[string]interface{}{}
	if v, ok := args["name"].(string); ok && v != "" { body["name"] = v }
	if v, ok := args["description"].(string); ok && v != "" { body["description"] = v }
	if f, ok := args["avatarId"].(float64); ok { body["avatarId"] = int(f) }
	if i, ok := args["avatarId"].(int); ok { body["avatarId"] = i }

	status, respBody, _, err := jiraDo("PUT", "/rest/api/3/issuetype/"+url.PathEscape(id), nil, body)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira update issue type failed: %d", status)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(respBody, &obj); err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil
	}
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- Issue Types: Delete -----------------
func executeJiraDeleteIssueTypeTool(args map[string]interface{}) (*ToolResponse, error) {
	id, _ := args["id"].(string)
	if id == "" { return &ToolResponse{Success: false, Error: "id is required"}, nil }
	q := url.Values{}
	if s, ok := args["alternativeIssueTypeId"].(string); ok && s != "" { q.Set("alternativeIssueTypeId", s) }
	status, _, _, err := jiraDo("DELETE", "/rest/api/3/issuetype/"+url.PathEscape(id), q, nil)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status == http.StatusNoContent {
		return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "issue type deleted"}}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira delete issue type failed: %d", status)}, nil
	}
	return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "issue type deleted"}}, nil
}

// ----------------- Issue Types: Alternatives for ID -----------------
func executeJiraGetIssueTypeAlternativesTool(args map[string]interface{}) (*ToolResponse, error) {
	id, _ := args["id"].(string)
	if id == "" { return &ToolResponse{Success: false, Error: "id is required"}, nil }
	status, body, _, err := jiraDo("GET", "/rest/api/3/issuetype/"+url.PathEscape(id)+"/alternatives", nil, nil)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira get issue type alternatives failed: %d", status)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil
	}
	return &ToolResponse{Success: true, Data: obj}, nil
}

func init() {
	tools["jira_list_issue_types"] = Tool{
		Name:        "jira_list_issue_types",
		Description: "List all Jira issue types visible to the user",
		Help: `Usage: /tool jira_list_issue_types\n\nExamples:\n  /tool jira_list_issue_types`,
	}
	toolExecutors["jira_list_issue_types"] = executeJiraListIssueTypesTool

	tools["jira_create_issue_type"] = Tool{
		Name:        "jira_create_issue_type",
		Description: "Create a Jira issue type",
		Help: `Usage: /tool jira_create_issue_type --name <name> [--description <text>] [--type <standard|subtask>] [--hierarchyLevel <int>]\n\nExamples:\n  /tool jira_create_issue_type --name Bug --type standard`,
		Parameters: map[string]string{
			"name":            "Name of the issue type (required)",
			"description":     "Description",
			"type":            "Type: standard or subtask",
			"hierarchyLevel":  "Hierarchy level (int)",
		},
	}
	toolExecutors["jira_create_issue_type"] = executeJiraCreateIssueTypeTool

	tools["jira_get_issue_types_for_project"] = Tool{
		Name:        "jira_get_issue_types_for_project",
		Description: "Get issue types for a project",
		Help: `Usage: /tool jira_get_issue_types_for_project --projectId <id> [--level <int>]\n\nExamples:\n  /tool jira_get_issue_types_for_project --projectId 10000`,
		Parameters: map[string]string{
			"projectId": "Project ID (required)",
			"level":     "Optional hierarchy level filter",
		},
	}
	toolExecutors["jira_get_issue_types_for_project"] = executeJiraGetIssueTypesForProjectTool

	tools["jira_get_issue_type"] = Tool{
		Name:        "jira_get_issue_type",
		Description: "Get a specific issue type by ID",
		Help: `Usage: /tool jira_get_issue_type --id <id>\n\nExamples:\n  /tool jira_get_issue_type --id 3`,
		Parameters: map[string]string{"id": "Issue type ID (required)"},
	}
	toolExecutors["jira_get_issue_type"] = executeJiraGetIssueTypeTool

	tools["jira_update_issue_type"] = Tool{
		Name:        "jira_update_issue_type",
		Description: "Update a Jira issue type",
		Help: `Usage: /tool jira_update_issue_type --id <id> [--name <name>] [--description <text>] [--avatarId <int>]\n\nExamples:\n  /tool jira_update_issue_type --id 3 --name Task`,
		Parameters: map[string]string{
			"id":          "Issue type ID (required)",
			"name":        "New name",
			"description": "New description",
			"avatarId":    "Avatar ID (int)",
		},
	}
	toolExecutors["jira_update_issue_type"] = executeJiraUpdateIssueTypeTool

	tools["jira_delete_issue_type"] = Tool{
		Name:        "jira_delete_issue_type",
		Description: "Delete a Jira issue type",
		Help: `Usage: /tool jira_delete_issue_type --id <id> [--alternativeIssueTypeId <id>]\n\nExamples:\n  /tool jira_delete_issue_type --id 3`,
		Parameters: map[string]string{
			"id":                     "Issue type ID (required)",
			"alternativeIssueTypeId": "Alternative issue type ID (used when in use)",
		},
	}
	toolExecutors["jira_delete_issue_type"] = executeJiraDeleteIssueTypeTool

	tools["jira_get_issue_type_alternatives"] = Tool{
		Name:        "jira_get_issue_type_alternatives",
		Description: "Get alternative issue types for a given type ID",
		Help: `Usage: /tool jira_get_issue_type_alternatives --id <id>\n\nExamples:\n  /tool jira_get_issue_type_alternatives --id 3`,
		Parameters: map[string]string{"id": "Issue type ID (required)"},
	}
	toolExecutors["jira_get_issue_type_alternatives"] = executeJiraGetIssueTypeAlternativesTool
}
