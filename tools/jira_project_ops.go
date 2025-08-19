package tools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// setQueryFromInt sets q[key] from args[key] when it's provided as either int or float64.
// Jira tools sometimes receive numeric args unmarshaled as float64; this helper normalizes them.
func setQueryFromInt(q url.Values, args map[string]interface{}, key string) {
	if v, ok := args[key].(int); ok {
		q.Set(key, strconv.Itoa(v))
		return
	}
	if v, ok := args[key].(float64); ok {
		q.Set(key, strconv.Itoa(int(v)))
	}
}

// getProjectIDOrKey extracts the project identifier from args, checking common keys.
// It returns the resolved idOrKey or a ToolResponse on error.
func getProjectIDOrKey(args map[string]interface{}) (string, *ToolResponse) {
	for _, key := range []string{"projectIdOrKey", "project", "id"} {
		if idOrKey, ok := args[key].(string); ok && idOrKey != "" {
			return idOrKey, nil
		}
	}
	return "", &ToolResponse{Success: false, Error: "projectIdOrKey is required"}

}

// ----------------- Projects: GET /rest/api/3/project (deprecated all) -----------------
func executeJiraProjectsAllTool(args map[string]interface{}) (*ToolResponse, error) {
	q := url.Values{}
	if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }
	setQueryFromInt(q, args, "recent")
	if v, ok := args["properties"].(string); ok && v != "" { q.Set("properties", v) }

	status, body, _, err := jiraDo("GET", "/rest/api/3/project", q, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status < 200 || status >= 300 {
		if status == http.StatusUnauthorized { return &ToolResponse{Success: false, Error: "unauthorized"}, nil }
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira list projects failed: %d", status)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil
	}
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- Projects: POST /rest/api/3/project (create) -----------------
func executeJiraCreateProjectTool(args map[string]interface{}) (*ToolResponse, error) {
	// passthrough body; accept args as the body map directly
	body := map[string]interface{}{}
	for k, v := range args { body[k] = v }

	status, respBody, _, err := jiraDo("POST", "/rest/api/3/project", nil, body)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status == http.StatusCreated || (status >= 200 && status < 300) {
		var obj interface{}
		if len(respBody) > 0 && json.Unmarshal(respBody, &obj) == nil {
			return &ToolResponse{Success: true, Data: obj}, nil
		}
		return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "project created"}}, nil
	}
	return &ToolResponse{Success: false, Error: fmt.Sprintf("jira create project failed: %d", status)}, nil
}

// ----------------- Projects: GET /rest/api/3/project/recent -----------------
func executeJiraProjectsRecentTool(args map[string]interface{}) (*ToolResponse, error) {
	q := url.Values{}
	if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }
	if v, ok := args["properties"].(string); ok && v != "" { q.Set("properties", v) }

	status, body, _, err := jiraDo("GET", "/rest/api/3/project/recent", q, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
    if status < 200 || status >= 300 {
        if status == http.StatusUnauthorized { return &ToolResponse{Success: false, Error: "unauthorized"}, nil }
        return &ToolResponse{Success: false, Error: fmt.Sprintf("jira recent projects failed: %d", status)}, nil
    }
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil { return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil }
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- Projects: GET /rest/api/3/project/search -----------------
func executeJiraProjectsSearchTool(args map[string]interface{}) (*ToolResponse, error) {
	q := url.Values{}
	// Standard pagination and filters
	setQueryFromInt(q, args, "startAt")
	setQueryFromInt(q, args, "maxResults")
	if v, ok := args["orderBy"].(string); ok && v != "" { q.Set("orderBy", v) }
	if v, ok := args["id"].(string); ok && v != "" { q.Set("id", v) } // CSV or multi supported by passing CSV
	if v, ok := args["keys"].(string); ok && v != "" { q.Set("keys", v) }
	if v, ok := args["query"].(string); ok && v != "" { q.Set("query", v) }
	if v, ok := args["typeKey"].(string); ok && v != "" { q.Set("typeKey", v) }
	setQueryFromInt(q, args, "categoryId")
	if v, ok := args["action"].(string); ok && v != "" { q.Set("action", v) }
	if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }
	// Allow additional possible filters if provided
	for _, k := range []string{"status", "statusCategory"} {
		if v, ok := args[k].(string); ok && v != "" { q.Set(k, v) }
	}

	status, body, _, err := jiraDo("GET", "/rest/api/3/project/search", q, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status < 200 || status >= 300 {
		if status == http.StatusUnauthorized {
			return &ToolResponse{Success: false, Error: "unauthorized"}, nil
		}
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira search projects failed: %d", status)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil { return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil }
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- Projects: GET /rest/api/3/project/{projectIdOrKey} -----------------
func executeJiraGetProjectTool(args map[string]interface{}) (*ToolResponse, error) {
	idOrKey, tr := getProjectIDOrKey(args)
	if tr != nil { return tr, nil }
	q := url.Values{}
	if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }
	if v, ok := args["properties"].(string); ok && v != "" { q.Set("properties", v) }

	status, body, _, err := jiraDo("GET", "/rest/api/3/project/"+url.PathEscape(idOrKey), q, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status == http.StatusNotFound { return &ToolResponse{Success: false, Error: "project not found"}, nil }
	if status < 200 || status >= 300 {
		if status == http.StatusUnauthorized {
			return &ToolResponse{Success: false, Error: "unauthorized"}, nil
		}
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira get project failed: %d", status)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil { return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil }
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- Projects: PUT /rest/api/3/project/{projectIdOrKey} -----------------
func executeJiraUpdateProjectTool(args map[string]interface{}) (*ToolResponse, error) {
	idOrKey, tr := getProjectIDOrKey(args)
	if tr != nil { return tr, nil }

	q := url.Values{}
	if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }

	body := map[string]interface{}{}
    for k, v := range args {
        body[k] = v
    }
    // Remove non-body parameters
    delete(body, "projectIdOrKey")
    delete(body, "project")
    delete(body, "id")
    delete(body, "expand")

	status, respBody, _, err := jiraDo("PUT", "/rest/api/3/project/"+url.PathEscape(idOrKey), q, body)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status < 200 || status >= 300 { return &ToolResponse{Success: false, Error: fmt.Sprintf("jira update project failed: %d", status)}, nil }
	var obj interface{}
	if len(respBody) > 0 && json.Unmarshal(respBody, &obj) == nil { return &ToolResponse{Success: true, Data: obj}, nil }
	return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "project updated"}}, nil
}

// ----------------- Projects: DELETE /rest/api/3/project/{projectIdOrKey} -----------------
func executeJiraDeleteProjectTool(args map[string]interface{}) (*ToolResponse, error) {
	idOrKey, tr := getProjectIDOrKey(args)
	if tr != nil { return tr, nil }
	q := url.Values{}
	if v, ok := args["enableUndo"].(bool); ok { q.Set("enableUndo", strconv.FormatBool(v)) }

	status, _, _, err := jiraDo("DELETE", "/rest/api/3/project/"+url.PathEscape(idOrKey), q, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
    if status < 200 || status >= 300 { return &ToolResponse{Success: false, Error: fmt.Sprintf("jira delete project failed: %d", status)}, nil }
    return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "project deleted"}}, nil
}

// ----------------- Projects: POST /rest/api/3/project/{projectIdOrKey}/archive -----------------
func executeJiraArchiveProjectTool(args map[string]interface{}) (*ToolResponse, error) {
	idOrKey, tr := getProjectIDOrKey(args)
	if tr != nil { return tr, nil }

	status, body, _, err := jiraDo("POST", "/rest/api/3/project/"+url.PathEscape(idOrKey)+"/archive", nil, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status == http.StatusNoContent { return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "project archived"}}, nil }
	if status < 200 || status >= 300 { return &ToolResponse{Success: false, Error: fmt.Sprintf("jira archive project failed: %d", status)}, nil }
	var obj interface{}
	if len(body) > 0 && json.Unmarshal(body, &obj) == nil { return &ToolResponse{Success: true, Data: obj}, nil }
	return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "project archived"}}, nil
}

// ----------------- Projects: POST /rest/api/3/project/{projectIdOrKey}/delete (async) -----------------
func executeJiraDeleteProjectAsyncTool(args map[string]interface{}) (*ToolResponse, error) {
	idOrKey, tr := getProjectIDOrKey(args)
	if tr != nil { return tr, nil }

	status, body, headers, err := jiraDo("POST", "/rest/api/3/project/"+url.PathEscape(idOrKey)+"/delete", nil, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status == http.StatusSeeOther || (status >= 200 && status < 300) {
		// Return task progress object if present and the Location header for polling
		var obj map[string]interface{}
		var data interface{}
		if len(body) > 0 && json.Unmarshal(body, &obj) == nil { data = obj } else { data = map[string]interface{}{"message": "delete enqueued"} }
		loc := headers.Get("Location")
		if loc != "" {
			return &ToolResponse{Success: true, Data: map[string]interface{}{"location": loc, "task": data}}, nil
		}
		return &ToolResponse{Success: true, Data: data}, nil
	}
	return &ToolResponse{Success: false, Error: fmt.Sprintf("jira async delete project failed: %d", status)}, nil
}

// ----------------- Projects: POST /rest/api/3/project/{projectIdOrKey}/restore -----------------
func executeJiraRestoreProjectTool(args map[string]interface{}) (*ToolResponse, error) {
	idOrKey, tr := getProjectIDOrKey(args)
	if tr != nil { return tr, nil }

	status, body, _, err := jiraDo("POST", "/rest/api/3/project/"+url.PathEscape(idOrKey)+"/restore", nil, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status < 200 || status >= 300 { return &ToolResponse{Success: false, Error: fmt.Sprintf("jira restore project failed: %d", status)}, nil }
	var obj interface{}
	if len(body) > 0 && json.Unmarshal(body, &obj) == nil { return &ToolResponse{Success: true, Data: obj}, nil }
	return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "project restored"}}, nil
}

// ----------------- Projects: GET /rest/api/3/project/{projectIdOrKey}/statuses -----------------
func executeJiraGetProjectStatusesTool(args map[string]interface{}) (*ToolResponse, error) {
	idOrKey, tr := getProjectIDOrKey(args)
	if tr != nil { return tr, nil }

	status, body, _, err := jiraDo("GET", "/rest/api/3/project/"+url.PathEscape(idOrKey)+"/statuses", nil, nil)
	if err != nil { return &ToolResponse{Success: false, Error: err.Error()}, nil }
	if status < 200 || status >= 300 {
		if status == http.StatusNotFound { return &ToolResponse{Success: false, Error: "project not found"}, nil }
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira get project statuses failed: %d", status)}, nil
	}
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil { return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil }
	return &ToolResponse{Success: true, Data: obj}, nil
}

func init() {
	// Tool definitions + registration
	tools["jira_projects_all"] = Tool{
		Name:        "jira_projects_all",
		Description: "Get all projects (deprecated by Jira; prefer jira_projects_search)",
		Help: `Usage: /tool jira_projects_all [--expand <s>] [--recent <n>] [--properties <csv>]`,
		Parameters: map[string]string{
			"expand":     "Expand parameter",
			"recent":     "Number of recent projects",
			"properties": "CSV property keys",
		},
	}
	toolExecutors["jira_projects_all"] = executeJiraProjectsAllTool

	tools["jira_create_project"] = Tool{
		Name:        "jira_create_project",
		Description: "Create a Jira project (pass body fields per Jira API)",
		Help:        `Usage: /tool jira_create_project --key <KEY> --name <Name> --projectTypeKey <business|software|service_desk> --projectTemplateKey <template> [other fields...]`,
		Parameters: map[string]string{
			"key":               "Project key (required)",
			"name":              "Project name (required)",
			"projectTypeKey":    "Project type key",
			"projectTemplateKey": "Template key",
			"leadAccountId":     "Lead accountId",
			"assigneeType":      "Assignee type",
			"avatarId":          "Avatar ID",
			"categoryId":        "Category ID",
			"description":       "Description",
			"issueSecurityScheme":"Issue security scheme ID",
			"notificationScheme": "Notification scheme ID",
			"permissionScheme":  "Permission scheme ID",
			"url":               "Project URL",
		},
	}
	toolExecutors["jira_create_project"] = executeJiraCreateProjectTool

	tools["jira_projects_recent"] = Tool{
		Name:        "jira_projects_recent",
		Description: "Get up to 20 recently viewed projects",
		Help:        `Usage: /tool jira_projects_recent [--expand <s>] [--properties <csv>]`,
		Parameters: map[string]string{
			"expand":     "Expand parameter",
			"properties": "CSV property keys",
		},
	}
	toolExecutors["jira_projects_recent"] = executeJiraProjectsRecentTool

	tools["jira_projects_search"] = Tool{
		Name:        "jira_projects_search",
		Description: "Search projects with pagination and filters",
		Help:        `Usage: /tool jira_projects_search [--startAt <n>] [--maxResults <n>] [--orderBy <field>] [--id <csv>] [--keys <csv>] [--query <s>] [--typeKey <s>] [--categoryId <n>] [--action <s>] [--expand <s>]`,
		Parameters: map[string]string{
			"startAt":    "Offset",
			"maxResults": "Page size",
			"orderBy":    "Order by field",
			"id":         "CSV of project IDs",
			"keys":       "CSV of project keys",
			"query":      "Search query",
			"typeKey":    "Project type key",
			"categoryId": "Category ID",
			"action":     "Action filter",
			"expand":     "Expand parameter",
		},
	}
	toolExecutors["jira_projects_search"] = executeJiraProjectsSearchTool

	tools["jira_get_project"] = Tool{
		Name:        "jira_get_project",
		Description: "Get project details by ID or key",
		Help:        `Usage: /tool jira_get_project --projectIdOrKey <idOrKey> [--expand <s>] [--properties <csv>]`,
		Parameters: map[string]string{
			"projectIdOrKey": "Project ID or key",
			"expand":        "Expand parameter",
			"properties":    "CSV property keys",
		},
	}
	toolExecutors["jira_get_project"] = executeJiraGetProjectTool

	tools["jira_update_project"] = Tool{
		Name:        "jira_update_project",
		Description: "Update project details",
		Help:        `Usage: /tool jira_update_project --projectIdOrKey <idOrKey> [--expand <s>] [fields...]`,
		Parameters: map[string]string{
			"projectIdOrKey": "Project ID or key",
			"expand":        "Expand parameter",
			"name":          "Name",
			"key":           "Key",
			"lead":          "Lead username",
			"leadAccountId": "Lead accountId",
			"assigneeType":  "Assignee type",
			"avatarId":      "Avatar ID",
			"categoryId":    "Category ID",
			"description":   "Description",
			"issueSecurityScheme": "Issue security scheme ID",
			"notificationScheme":  "Notification scheme ID",
			"permissionScheme":    "Permission scheme ID",
			"url":           "Project URL",
		},
	}
	toolExecutors["jira_update_project"] = executeJiraUpdateProjectTool

	tools["jira_delete_project"] = Tool{
		Name:        "jira_delete_project",
		Description: "Delete a project (cannot delete if archived)",
		Help:        `Usage: /tool jira_delete_project --projectIdOrKey <idOrKey> [--enableUndo <bool>]`,
		Parameters: map[string]string{
			"projectIdOrKey": "Project ID or key",
			"enableUndo":     "Enable undo (boolean)",
		},
	}
	toolExecutors["jira_delete_project"] = executeJiraDeleteProjectTool

	tools["jira_archive_project"] = Tool{
		Name:        "jira_archive_project",
		Description: "Archive a project",
		Help:        `Usage: /tool jira_archive_project --projectIdOrKey <idOrKey>`,
		Parameters: map[string]string{
			"projectIdOrKey": "Project ID or key",
		},
	}
	toolExecutors["jira_archive_project"] = executeJiraArchiveProjectTool

	tools["jira_delete_project_async"] = Tool{
		Name:        "jira_delete_project_async",
		Description: "Delete a project asynchronously (returns task + Location)",
		Help:        `Usage: /tool jira_delete_project_async --projectIdOrKey <idOrKey>`,
		Parameters: map[string]string{
			"projectIdOrKey": "Project ID or key",
		},
	}
	toolExecutors["jira_delete_project_async"] = executeJiraDeleteProjectAsyncTool

	tools["jira_restore_project"] = Tool{
		Name:        "jira_restore_project",
		Description: "Restore a deleted or archived project",
		Help:        `Usage: /tool jira_restore_project --projectIdOrKey <idOrKey>`,
		Parameters: map[string]string{
			"projectIdOrKey": "Project ID or key",
		},
	}
	toolExecutors["jira_restore_project"] = executeJiraRestoreProjectTool

	tools["jira_get_project_statuses"] = Tool{
		Name:        "jira_get_project_statuses",
		Description: "Get valid statuses for a project grouped by issue type",
		Help:        `Usage: /tool jira_get_project_statuses --projectIdOrKey <idOrKey>`,
		Parameters: map[string]string{
			"projectIdOrKey": "Project ID or key",
		},
	}
	toolExecutors["jira_get_project_statuses"] = executeJiraGetProjectStatusesTool
}
