package tools

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/ini.v1"

	"go-thing/internal/config"
)

// helper to build auth header and base URL
func jiraBuildRequest(method, fullURL, email, token string, body []byte) (*http.Request, error) {
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Body = io.NopCloser(strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
	}
	if email != "" {
		basic := base64.StdEncoding.EncodeToString([]byte(email + ":" + token))
		req.Header.Set("Authorization", "Basic "+basic)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// handleADFField reads args[fieldName] and sets fields[fieldName] appropriately.
// It accepts either:
// - string: if JSON object, parse; otherwise wrap as minimal ADF doc
// - map[string]interface{}: use as-is
func handleADFField(fields map[string]interface{}, args map[string]interface{}, fieldName string) {
    if raw, ok := args[fieldName]; ok {
        switch v := raw.(type) {
        case string:
            s := strings.TrimSpace(v)
            if s == "" {
                return
            }
            if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
                var obj map[string]interface{}
                if err := json.Unmarshal([]byte(s), &obj); err == nil {
                    fields[fieldName] = obj
                    return
                }
            }
            fields[fieldName] = map[string]interface{}{
                "type":    "doc",
                "version": 1,
                "content": []interface{}{
                    map[string]interface{}{
                        "type":    "paragraph",
                        "content": []interface{}{map[string]interface{}{"type": "text", "text": s}},
                    },
                },
            }
        case map[string]interface{}:
            fields[fieldName] = v
        }
    }
}

// ----------------- jira_create_issue -----------------
// POST /rest/api/3/issue
func executeJiraCreateIssueTool(args map[string]interface{}) (*ToolResponse, error) {
    // Build body
    body := map[string]interface{}{}
    fields := map[string]interface{}{}

    // Allow full passthrough of fields if provided
    if raw, ok := args["fields"]; ok {
        switch v := raw.(type) {
        case string:
            if strings.TrimSpace(v) != "" {
                var obj map[string]interface{}
                if err := json.Unmarshal([]byte(v), &obj); err == nil {
                    fields = obj
                } else {
                    return &ToolResponse{Success: false, Error: fmt.Sprintf("invalid fields JSON: %v", err)}, nil
                }
            }
        case map[string]interface{}:
            fields = v
        }
    }

    // Convenience parameters (merged over existing fields without clobbering nested maps unexpectedly)
    ensureMap := func(m map[string]interface{}, key string) map[string]interface{} {
        if child, ok := m[key].(map[string]interface{}); ok {
            return child
        }
        child := map[string]interface{}{}
        m[key] = child
        return child
    }

    // environment and description (ADF-capable fields)
    handleADFField(fields, args, "environment")

    // project: by key or id
    if v, ok := args["projectKey"].(string); ok && v != "" {
        p := ensureMap(fields, "project")
        p["key"] = v
    }
    if v, ok := args["projectId"].(string); ok && v != "" {
        p := ensureMap(fields, "project")
        p["id"] = v
    }

    // issuetype: by id or name
    if v, ok := args["issuetypeId"].(string); ok && v != "" {
        it := ensureMap(fields, "issuetype")
        it["id"] = v
    }
    if v, ok := args["issuetypeName"].(string); ok && v != "" {
        it := ensureMap(fields, "issuetype")
        it["name"] = v
    }

    // summary
    if v, ok := args["summary"].(string); ok && v != "" {
        fields["summary"] = v
    }

    handleADFField(fields, args, "description")

    // labels: accept []interface{}, []string, or comma-separated string
    if raw, ok := args["labels"]; ok {
        var arr []string
        switch v := raw.(type) {
        case []interface{}:
            for _, it := range v {
                if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
                    arr = append(arr, strings.TrimSpace(s))
                }
            }
        case []string:
            for _, s := range v {
                if strings.TrimSpace(s) != "" {
                    arr = append(arr, strings.TrimSpace(s))
                }
            }
        case string:
            for _, s := range strings.Split(v, ",") {
                if strings.TrimSpace(s) != "" {
                    arr = append(arr, strings.TrimSpace(s))
                }
            }
        }
        if len(arr) > 0 { fields["labels"] = arr }
    }

    // priority by name or id
    if v, ok := args["priorityName"].(string); ok && v != "" {
        fields["priority"] = map[string]interface{}{"name": v}
    }
    if v, ok := args["priorityId"].(string); ok && v != "" {
        fields["priority"] = map[string]interface{}{"id": v}
    }

    // assignee / reporter by accountId
    if v, ok := args["assigneeAccountId"].(string); ok && v != "" {
        fields["assignee"] = map[string]interface{}{"accountId": v}
    }
    if v, ok := args["reporterAccountId"].(string); ok && v != "" {
        fields["reporter"] = map[string]interface{}{"accountId": v}
    }

    // parent (for subtasks): support id or key
    if v, ok := args["parentId"].(string); ok && v != "" {
        fields["parent"] = map[string]interface{}{"id": v}
    } else if v, ok := args["parentKey"].(string); ok && v != "" {
        fields["parent"] = map[string]interface{}{"key": v}
    }

    if len(fields) == 0 {
        return &ToolResponse{Success: false, Error: "fields are required (provide 'fields' or convenience params like projectKey/issuetypeId/summary)"}, nil
    }
    body["fields"] = fields

    // Optional: update/properties/historyMetadata/transition passthrough
    for _, k := range []string{"update", "properties", "historyMetadata", "transition"} {
        if v, ok := args[k]; ok {
            // If provided as JSON string, try to parse
            if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
                var obj interface{}
                if err := json.Unmarshal([]byte(s), &obj); err == nil {
                    body[k] = obj
                    continue
                }
            }
            body[k] = v
        }
    }

    status, respBody, _, err := jiraDo("POST", "/rest/api/3/issue", nil, body)
    if err != nil {
        return &ToolResponse{Success: false, Error: err.Error()}, nil
    }
    // Handle non-2xx first
    if status < 200 || status >= 300 {
        // Try to parse Jira error details
        var eobj map[string]interface{}
        if len(respBody) > 0 && json.Unmarshal(respBody, &eobj) == nil {
            var details []string
            if msgs, ok := eobj["errorMessages"].([]interface{}); ok {
                for _, m := range msgs { if s, ok := m.(string); ok { details = append(details, s) } }
            }
            if errs, ok := eobj["errors"].(map[string]interface{}); ok {
                for k, v := range errs { details = append(details, fmt.Sprintf("%s: %v", k, v)) }
            }
            if len(details) > 0 {
                return &ToolResponse{Success: false, Error: fmt.Sprintf("jira create issue failed: %d: %s", status, strings.Join(details, "; "))}, nil
            }
        }
        return &ToolResponse{Success: false, Error: fmt.Sprintf("jira create issue failed: %d", status)}, nil
    }
    // All 2xx success statuses
    var obj interface{}
    if len(respBody) > 0 && json.Unmarshal(respBody, &obj) == nil {
        return &ToolResponse{Success: true, Data: obj}, nil
    }
    return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "issue created"}}, nil
}

func jiraDo(method, pathWithParams string, query url.Values, bodyObj interface{}) (int, []byte, http.Header, error) {
	// Read config
	cfg, err := ini.Load(os.ExpandEnv(config.ConfigFilePath))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("config error: %w", err)
	}
	def := cfg.Section("default")
	jiraURL := def.Key("JIRA_URL").String()
	jiraToken := def.Key("JIRA_TOKEN").String()
	jiraEmail := def.Key("JIRA_EMAIL").String()
	if jiraURL == "" || jiraToken == "" {
		return 0, nil, nil, errors.New("JIRA_URL or JIRA_TOKEN not configured")
	}

	base, err := url.Parse(jiraURL)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("invalid JIRA_URL: %w", err)
	}
	base.Path = strings.TrimRight(base.Path, "/") + pathWithParams
	if query != nil {
		base.RawQuery = query.Encode()
	}

	var bodyBytes []byte
	if bodyObj != nil {
		bodyBytes, _ = json.Marshal(bodyObj)
	}

	req, err := jiraBuildRequest(method, base.String(), jiraEmail, jiraToken, bodyBytes)
	if err != nil {
		return 0, nil, nil, err
	}

	// Log request (mask auth)
	maskAuth := func(h string) string {
		if h == "" { return "" }
		if strings.HasPrefix(h, "Basic ") { return "Basic ***masked***" }
		if strings.HasPrefix(h, "Bearer ") { return "Bearer ***masked***" }
		return "***masked***"
	}
	var headerLines []string
	for k, v := range req.Header {
		val := strings.Join(v, ", ")
		if strings.EqualFold(k, "Authorization") {
			val = maskAuth(val)
		}
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", k, val))
	}
	if bodyBytes != nil {
		log.Printf("[Jira] Request: %s %s\nHeaders:\n%s\nBody:\n%s", req.Method, req.URL.String(), strings.Join(headerLines, "\n"), string(bodyBytes))
	} else {
		log.Printf("[Jira] Request: %s %s\nHeaders:\n%s", req.Method, req.URL.String(), strings.Join(headerLines, "\n"))
	}

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	var respHeaderLines []string
	for k, v := range resp.Header {
		respHeaderLines = append(respHeaderLines, fmt.Sprintf("%s: %s", k, strings.Join(v, ", ")))
	}
	const maxLogBody = 1 << 14
	bodyForLog := respBody
	if len(bodyForLog) > maxLogBody {
		bodyForLog = bodyForLog[:maxLogBody]
	}
	log.Printf("[Jira] Response: %s\nHeaders:\n%s\nBody (%d bytes, showing %d):\n%s", resp.Status, strings.Join(respHeaderLines, "\n"), len(respBody), len(bodyForLog), string(bodyForLog))

	return resp.StatusCode, respBody, resp.Header, nil
}

// ----------------- jira_get_issue -----------------
func executeJiraGetIssueTool(args map[string]interface{}) (*ToolResponse, error) {
	issue, _ := args["issue"].(string)
	if issue == "" {
		// allow alias issueIdOrKey
		issue, _ = args["issueIdOrKey"].(string)
	}
	if issue == "" {
		return &ToolResponse{Success: false, Error: "issue (issueIdOrKey) is required"}, nil
	}

	q := url.Values{}
	if v, ok := args["fields"].(string); ok && v != "" { q.Set("fields", v) }
	if v, ok := args["fieldsByKeys"].(bool); ok { q.Set("fieldsByKeys", strconv.FormatBool(v)) }
	if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }
	if v, ok := args["properties"].(string); ok && v != "" { q.Set("properties", v) }
	if v, ok := args["updateHistory"].(bool); ok { q.Set("updateHistory", strconv.FormatBool(v)) }
	if v, ok := args["failFast"].(bool); ok { q.Set("failFast", strconv.FormatBool(v)) }

	status, body, _, err := jiraDo("GET", "/rest/api/3/issue/"+url.PathEscape(issue), q, nil)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status == http.StatusNotFound {
		return &ToolResponse{Success: false, Error: "issue not found"}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira get issue failed: %d", status)}, nil
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil
	}
	return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- jira_edit_issue -----------------
func executeJiraEditIssueTool(args map[string]interface{}) (*ToolResponse, error) {
	issue, _ := args["issue"].(string)
	if issue == "" { issue, _ = args["issueIdOrKey"].(string) }
	if issue == "" {
		return &ToolResponse{Success: false, Error: "issue (issueIdOrKey) is required"}, nil
	}
	// Optional query params
	q := url.Values{}
	if v, ok := args["notifyUsers"].(bool); ok { q.Set("notifyUsers", strconv.FormatBool(v)) }
	if v, ok := args["overrideScreenSecurity"].(bool); ok { q.Set("overrideScreenSecurity", strconv.FormatBool(v)) }
	if v, ok := args["overrideEditableFlag"].(bool); ok { q.Set("overrideEditableFlag", strconv.FormatBool(v)) }
	if v, ok := args["returnIssue"].(bool); ok { q.Set("returnIssue", strconv.FormatBool(v)) }
	if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }

	// Body: accept passthrough JSON via fields/update/properties/historyMetadata/transition
	body := map[string]interface{}{}
	for _, k := range []string{"fields", "update", "properties", "historyMetadata", "transition"} {
		if v, ok := args[k]; ok {
			body[k] = v
		}
	}
	status, respBody, _, err := jiraDo("PUT", "/rest/api/3/issue/"+url.PathEscape(issue), q, body)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status == http.StatusNoContent { // 204
		return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "issue updated"}}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira edit issue failed: %d", status)}, nil
	}
	// Some cases return 200 with JSON when returnIssue=true
	var obj interface{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &obj); err == nil {
			return &ToolResponse{Success: true, Data: obj}, nil
		}
	}
	return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "issue updated"}}, nil
}

// ----------------- jira_delete_issue -----------------
func executeJiraDeleteIssueTool(args map[string]interface{}) (*ToolResponse, error) {
	issue, _ := args["issue"].(string)
	if issue == "" { issue, _ = args["issueIdOrKey"].(string) }
	if issue == "" {
		return &ToolResponse{Success: false, Error: "issue (issueIdOrKey) is required"}, nil
	}
	q := url.Values{}
	// deleteSubtasks can be string per docs; accept bool or string
	if v, ok := args["deleteSubtasks"].(bool); ok {
		q.Set("deleteSubtasks", strconv.FormatBool(v))
	} else if s, ok := args["deleteSubtasks"].(string); ok && s != "" {
		q.Set("deleteSubtasks", s)
	}
	status, _, _, err := jiraDo("DELETE", "/rest/api/3/issue/"+url.PathEscape(issue), q, nil)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status == http.StatusNoContent {
		return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "issue deleted"}}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira delete issue failed: %d", status)}, nil
	}
	return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "issue deleted"}}, nil
}

// Optional: Assign issue helper since user provided docs
func executeJiraAssignIssueTool(args map[string]interface{}) (*ToolResponse, error) {
	issue, _ := args["issue"].(string)
	if issue == "" { issue, _ = args["issueIdOrKey"].(string) }
	if issue == "" {
		return &ToolResponse{Success: false, Error: "issue (issueIdOrKey) is required"}, nil
	}
	body := map[string]interface{}{}
	for _, k := range []string{"accountId", "name", "key"} {
		if v, ok := args[k]; ok { body[k] = v }
	}
	status, respBody, _, err := jiraDo("PUT", "/rest/api/3/issue/"+url.PathEscape(issue)+"/assignee", nil, body)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	if status == http.StatusNoContent {
		return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "assignee set"}}, nil
	}
	if status < 200 || status >= 300 {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("jira assign issue failed: %d", status)}, nil
	}
	var obj interface{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &obj); err == nil {
			return &ToolResponse{Success: true, Data: obj}, nil
		}
	}
	return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "assignee set"}}, nil
}

// ----------------- jira_get_transitions -----------------
// GET /rest/api/3/issue/{issueIdOrKey}/transitions
func executeJiraGetTransitionsTool(args map[string]interface{}) (*ToolResponse, error) {
    issue, _ := args["issue"].(string)
    if issue == "" { issue, _ = args["issueIdOrKey"].(string) }
    if issue == "" {
        return &ToolResponse{Success: false, Error: "issue (issueIdOrKey) is required"}, nil
    }

    q := url.Values{}
    if v, ok := args["expand"].(string); ok && v != "" { q.Set("expand", v) }
    if v, ok := args["transitionId"].(string); ok && v != "" { q.Set("transitionId", v) }
    if v, ok := args["skipRemoteOnlyCondition"].(bool); ok { q.Set("skipRemoteOnlyCondition", strconv.FormatBool(v)) }
    if v, ok := args["includeUnavailableTransitions"].(bool); ok { q.Set("includeUnavailableTransitions", strconv.FormatBool(v)) }
    if v, ok := args["sortByOpsBarAndStatus"].(bool); ok { q.Set("sortByOpsBarAndStatus", strconv.FormatBool(v)) }

    status, body, _, err := jiraDo("GET", "/rest/api/3/issue/"+url.PathEscape(issue)+"/transitions", q, nil)
    if err != nil {
        return &ToolResponse{Success: false, Error: err.Error()}, nil
    }
    if status < 200 || status >= 300 {
        if status == http.StatusNotFound {
            return &ToolResponse{Success: false, Error: "issue not found"}, nil
        }
        return &ToolResponse{Success: false, Error: fmt.Sprintf("jira get transitions failed: %d", status)}, nil
    }
    var obj map[string]interface{}
    if err := json.Unmarshal(body, &obj); err != nil {
        return &ToolResponse{Success: false, Error: fmt.Sprintf("parse error: %v", err)}, nil
    }
    return &ToolResponse{Success: true, Data: obj}, nil
}

// ----------------- jira_transition_issue -----------------
// POST /rest/api/3/issue/{issueIdOrKey}/transitions
func executeJiraTransitionIssueTool(args map[string]interface{}) (*ToolResponse, error) {
    issue, _ := args["issue"].(string)
    if issue == "" { issue, _ = args["issueIdOrKey"].(string) }
    if issue == "" {
        return &ToolResponse{Success: false, Error: "issue (issueIdOrKey) is required"}, nil
    }

    // Build body supporting fields per docs
    body := map[string]interface{}{}
    for _, k := range []string{"fields", "update", "properties", "historyMetadata", "transition"} {
        if v, ok := args[k]; ok {
            body[k] = v
        }
    }
    // Allow simple --transitionId convenience, wrap into transition object if provided and transition missing
    if tid, ok := args["transitionId"].(string); ok && tid != "" {
        if _, exists := body["transition"]; !exists {
            body["transition"] = map[string]interface{}{"id": tid}
        }
    }

    status, respBody, _, err := jiraDo("POST", "/rest/api/3/issue/"+url.PathEscape(issue)+"/transitions", nil, body)
    if err != nil {
        return &ToolResponse{Success: false, Error: err.Error()}, nil
    }
    if status == http.StatusNoContent { // 204
        return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "transition applied"}}, nil
    }
    if status < 200 || status >= 300 {
        switch status {
        case http.StatusBadRequest:
            return &ToolResponse{Success: false, Error: "bad request: verify transition id and required fields"}, nil
        case http.StatusNotFound:
            return &ToolResponse{Success: false, Error: "issue or transition not found"}, nil
        case http.StatusConflict:
            return &ToolResponse{Success: false, Error: "conflict: transition cannot be performed"}, nil
        case http.StatusUnauthorized:
            return &ToolResponse{Success: false, Error: "unauthorized"}, nil
        default:
            return &ToolResponse{Success: false, Error: fmt.Sprintf("jira transition failed: %d", status)}, nil
        }
    }
    // Some responses may include JSON (rare). Try to parse if present.
    if len(respBody) > 0 {
        var obj interface{}
        if err := json.Unmarshal(respBody, &obj); err == nil {
            return &ToolResponse{Success: true, Data: obj}, nil
        }
    }
    return &ToolResponse{Success: true, Data: map[string]interface{}{"message": "transition applied"}}, nil
}

func init() {
    tools["jira_get_issue"] = Tool{
        Name:        "jira_get_issue",
        Description: "Get Jira issue details by ID or key",
        Help: `Usage: /tool jira_get_issue --issue <ID-or-KEY> [--fields <csv>] [--fieldsByKeys <bool>] [--expand <s>] [--properties <csv>] [--updateHistory <bool>] [--failFast <bool>]

Parameters:
  --issue <ID-or-KEY>   Issue ID or key (alias: --issueIdOrKey)
  --fields <csv>        Comma-separated fields to return
  --fieldsByKeys <bool> Interpret fields by keys
  --expand <s>          Expand parameter
  --properties <csv>    Properties to return
  --updateHistory <bool> Include change history updates
  --failFast <bool>     Fail fast on parsing

Examples:
  /tool jira_get_issue --issue PROJ-123`,
        Parameters: map[string]string{
            "issue":         "Issue ID or key (alias: issueIdOrKey)",
            "fields":        "Comma-separated fields",
            "fieldsByKeys":  "Boolean",
            "expand":        "Expand parameter",
            "properties":    "Comma-separated properties",
            "updateHistory": "Boolean",
            "failFast":      "Boolean",
        },
    }
    toolExecutors["jira_get_issue"] = executeJiraGetIssueTool

    // Create issue
    tools["jira_create_issue"] = Tool{
        Name:        "jira_create_issue",
        Description: "Create a Jira issue (supports full fields JSON or convenience params)",
        Help: `Usage: /tool jira_create_issue [--fields <json>] [--projectKey <key> | --projectId <id>] [--issuetypeId <id> | --issuetypeName <name>] [--summary <text>] [--description <text|json>] [--environment <text|json>] [--labels <csv|json>] [--priorityName <name>] [--priorityId <id>] [--assigneeAccountId <id>] [--reporterAccountId <id>] [--parentId <id> | --parentKey <key>] [--update <json>] [--properties <json>] [--historyMetadata <json>] [--transition <json>]

Notes:
  - If --fields is provided, it is used as the request fields object.
  - If --description or --environment is a plain string, it will be wrapped into Atlassian Document Format (ADF) automatically (as required by Jira for textarea fields).
  - You may pass --transition as a JSON object to move the issue to a different workflow step on creation.

Examples:
  /tool jira_create_issue --projectKey PROJ --issuetypeName Task --summary "Set up CI" --description "Create CI pipeline"
  /tool jira_create_issue --fields '{"project":{"key":"PROJ"},"issuetype":{"id":"10001"},"summary":"Do X"}'`,
        Parameters: map[string]string{
            "fields":             "JSON object for fields (overrides convenience params)",
            "projectKey":         "Project key",
            "projectId":          "Project ID",
            "issuetypeId":        "Issue type ID",
            "issuetypeName":      "Issue type name",
            "summary":            "Summary text",
            "description":        "ADF JSON object or plain string (auto-wrapped)",
            "environment":        "ADF JSON object or plain string (auto-wrapped)",
            "labels":             "CSV string, JSON array, or array",
            "priorityName":       "Priority name",
            "priorityId":         "Priority ID",
            "assigneeAccountId":  "Assignee accountId",
            "reporterAccountId":  "Reporter accountId",
            "parentId":           "Parent issue ID (for subtasks)",
            "parentKey":          "Parent issue key (for subtasks)",
            "update":             "JSON object",
            "properties":         "JSON array/object",
            "historyMetadata":    "JSON object",
            "transition":         "JSON object for initial transition",
        },
    }
    toolExecutors["jira_create_issue"] = executeJiraCreateIssueTool

    tools["jira_edit_issue"] = Tool{
        Name:        "jira_edit_issue",
        Description: "Edit Jira issue fields/properties",
        Help: `Usage: /tool jira_edit_issue --issue <ID-or-KEY> [--notifyUsers <bool>] [--overrideScreenSecurity <bool>] [--overrideEditableFlag <bool>] [--returnIssue <bool>] [--expand <s>] --fields <json> --update <json>

Body keys (JSON strings are accepted): fields, update, properties, historyMetadata, transition

Examples:
  /tool jira_edit_issue --issue PROJ-123 --fields '{"summary":"New summary"}'`,
        Parameters: map[string]string{
            "issue":                 "Issue ID or key (alias: issueIdOrKey)",
            "notifyUsers":          "Boolean",
            "overrideScreenSecurity":"Boolean",
            "overrideEditableFlag": "Boolean",
            "returnIssue":          "Boolean",
            "expand":               "Expand parameter",
            "fields":               "JSON object of fields",
            "update":               "JSON object of updates",
            "properties":           "JSON array of properties",
            "historyMetadata":      "JSON object",
            "transition":           "JSON object",
        },
    }
    toolExecutors["jira_edit_issue"] = executeJiraEditIssueTool

    tools["jira_delete_issue"] = Tool{
        Name:        "jira_delete_issue",
        Description: "Delete a Jira issue",
        Help: `Usage: /tool jira_delete_issue --issue <ID-or-KEY> [--deleteSubtasks <bool|" + "string>]

Examples:
  /tool jira_delete_issue --issue PROJ-123 --deleteSubtasks true`,
		Parameters: map[string]string{
			"issue":          "Issue ID or key (alias: issueIdOrKey)",
			"deleteSubtasks": "Boolean or string",
		},
	}
	toolExecutors["jira_delete_issue"] = executeJiraDeleteIssueTool

	// Bonus tool since docs provided
	tools["jira_assign_issue"] = Tool{
		Name:        "jira_assign_issue",
		Description: "Assign a Jira issue to a user",
		Help: `Usage: /tool jira_assign_issue --issue <ID-or-KEY> [--accountId <id>] [--name <username>] [--key <userKey>]

Examples:
  /tool jira_assign_issue --issue PROJ-123 --accountId 5b10ac8d82e05b22cc7d4ef5`,
		Parameters: map[string]string{
			"issue":     "Issue ID or key (alias: issueIdOrKey)",
			"accountId": "Account ID",
			"name":      "Username",
			"key":       "User key",
		},
	}
	toolExecutors["jira_assign_issue"] = executeJiraAssignIssueTool

	// Transitions: list available transitions for an issue
	tools["jira_get_transitions"] = Tool{
		Name:        "jira_get_transitions",
		Description: "Get available transitions for a Jira issue",
		Help: `Usage: /tool jira_get_transitions --issue <ID-or-KEY> [--expand <s>] [--transitionId <id>] [--skipRemoteOnlyCondition <bool>] [--includeUnavailableTransitions <bool>] [--sortByOpsBarAndStatus <bool>]

Parameters:
  --issue <ID-or-KEY>                 Issue ID or key (alias: --issueIdOrKey)
  --expand <s>                        Expand parameter (e.g., transitions.fields)
  --transitionId <id>                 If provided, request details for a specific transition ID
  --skipRemoteOnlyCondition <bool>    Skip remote only condition
  --includeUnavailableTransitions <bool> Include unavailable transitions
  --sortByOpsBarAndStatus <bool>      Sort by ops bar and status

Examples:
  /tool jira_get_transitions --issue PROJ-123 --expand transitions.fields`,
		Parameters: map[string]string{
			"issue":                        "Issue ID or key (alias: issueIdOrKey)",
			"expand":                       "Expand parameter",
			"transitionId":                 "Transition ID",
			"skipRemoteOnlyCondition":      "Boolean",
			"includeUnavailableTransitions": "Boolean",
			"sortByOpsBarAndStatus":        "Boolean",
		},
	}
	toolExecutors["jira_get_transitions"] = executeJiraGetTransitionsTool

	// Alias with requested name: jira_get_transitions_for_issue
	tools["jira_get_transitions_for_issue"] = Tool{
		Name:        "jira_get_transitions_for_issue",
		Description: "Get available transitions for a Jira issue (alias)",
		Help: `Usage: /tool jira_get_transitions_for_issue --issue <ID-or-KEY> [--expand <s>] [--transitionId <id>] [--skipRemoteOnlyCondition <bool>] [--includeUnavailableTransitions <bool>] [--sortByOpsBarAndStatus <bool>]

Parameters:
  --issue <ID-or-KEY>                 Issue ID or key (alias: --issueIdOrKey)
  --expand <s>                        Expand parameter (e.g., transitions.fields)
  --transitionId <id>                 If provided, request details for a specific transition ID
  --skipRemoteOnlyCondition <bool>    Skip remote only condition
  --includeUnavailableTransitions <bool> Include unavailable transitions
  --sortByOpsBarAndStatus <bool>      Sort by ops bar and status

Examples:
  /tool jira_get_transitions_for_issue --issue PROJ-123 --expand transitions.fields`,
		Parameters: map[string]string{
			"issue":                        "Issue ID or key (alias: issueIdOrKey)",
			"expand":                       "Expand parameter",
			"transitionId":                 "Transition ID",
			"skipRemoteOnlyCondition":      "Boolean",
			"includeUnavailableTransitions": "Boolean",
			"sortByOpsBarAndStatus":        "Boolean",
		},
	}
	toolExecutors["jira_get_transitions_for_issue"] = executeJiraGetTransitionsTool

	// Transition: perform an issue transition
	tools["jira_transition_issue"] = Tool{
		Name:        "jira_transition_issue",
		Description: "Perform a transition on a Jira issue (and optionally update fields/comments)",
		Help: `Usage: /tool jira_transition_issue --issue <ID-or-KEY> [--transitionId <id>] [--transition <json>] [--fields <json>] [--update <json>] [--properties <json>] [--historyMetadata <json>]

Notes:
  Provide either --transitionId to set {"transition":{"id":"<id>"}} or a full --transition JSON object.

Examples:
  /tool jira_transition_issue --issue PROJ-123 --transitionId 5
  /tool jira_transition_issue --issue PROJ-123 --transition '{"id":"711"}' --update '{"comment":[{"add":{"body":{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"QA passed"}]}]}}}]}'`,
		Parameters: map[string]string{
			"issue":          "Issue ID or key (alias: issueIdOrKey)",
			"transitionId":   "Transition ID (convenience)",
			"transition":     "JSON object e.g. {\"id\":\"5\"}",
			"fields":         "JSON object of fields",
			"update":         "JSON object of updates (e.g., comments)",
			"properties":     "JSON array of properties",
			"historyMetadata": "JSON object",
		},
	}
	toolExecutors["jira_transition_issue"] = executeJiraTransitionIssueTool
}
