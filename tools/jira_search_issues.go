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

// Minimal shapes for parsing Jira search response
type jiraSearchResponse struct {
	Issues []struct {
		Key    string `json:"key"`
		Fields struct {
			Summary string `json:"summary"`
			Status  struct {
				Name string `json:"name"`
			} `json:"status"`
			Assignee *struct {
				DisplayName string `json:"displayName"`
			} `json:"assignee"`
		} `json:"fields"`
	} `json:"issues"`
	Total int `json:"total"`
}

type JiraIssue struct {
	Key      string `json:"key"`
	Summary  string `json:"summary"`
	Status   string `json:"status"`
	Assignee string `json:"assignee,omitempty"`
	URL      string `json:"url"`
}

func jiraDoRequest(jiraURL, token, email, jql string, max int, opts map[string]interface{}) ([]JiraIssue, error) {
	if jiraURL == "" || token == "" {
		return nil, errors.New("JIRA_URL or JIRA_TOKEN not configured")
	}

	base, err := url.Parse(jiraURL)
	if err != nil {
		return nil, fmt.Errorf("invalid JIRA_URL: %w", err)
	}
	// Build enhanced search endpoint
	base.Path = strings.TrimRight(base.Path, "/") + "/rest/api/3/search/jql"

	// Decide GET vs POST
	usePOST := false
	if len(jql) > 1800 {
		usePOST = true
	}
	if _, has := opts["reconcileIssues"]; has {
		usePOST = true
	}

	var req *http.Request
	var postBodyBytes []byte
	if !usePOST {
		q := base.Query()
		q.Set("jql", jql)
		if max <= 0 {
			max = 10
		}
		q.Set("maxResults", strconv.Itoa(max))
		// optional params
		if v, ok := opts["fields"].([]string); ok && len(v) > 0 {
			q.Set("fields", strings.Join(v, ","))
		} else {
			q.Set("fields", "key,summary,status,assignee")
		}
		if v, ok := opts["expand"].(string); ok && v != "" {
			q.Set("expand", v)
		}
		if v, ok := opts["nextPageToken"].(string); ok && v != "" {
			q.Set("nextPageToken", v)
		}
		if v, ok := opts["fieldsByKeys"].(bool); ok {
			q.Set("fieldsByKeys", strconv.FormatBool(v))
		}
		if v, ok := opts["failFast"].(bool); ok {
			q.Set("failFast", strconv.FormatBool(v))
		}
		base.RawQuery = q.Encode()
		req, err = http.NewRequest("GET", base.String(), nil)
	} else {
		// POST body
		body := map[string]interface{}{
			"jql":        jql,
			"maxResults": max,
		}
		if v, ok := opts["fields"].([]string); ok && len(v) > 0 {
			body["fields"] = v
		} else {
			body["fields"] = []string{"key", "summary", "status", "assignee"}
		}
		if v, ok := opts["expand"].(string); ok && v != "" {
			body["expand"] = v
		}
		if v, ok := opts["nextPageToken"].(string); ok && v != "" {
			body["nextPageToken"] = v
		}
		if v, ok := opts["fieldsByKeys"].(bool); ok {
			body["fieldsByKeys"] = v
		}
		if v, ok := opts["failFast"].(bool); ok {
			body["failFast"] = v
		}
		if v, ok := opts["reconcileIssues"].([]int); ok && len(v) > 0 {
			body["reconcileIssues"] = v
		}
		b, _ := json.Marshal(body)
		postBodyBytes = b
		req, err = http.NewRequest("POST", base.String(), io.NopCloser(strings.NewReader(string(b))))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		return nil, err
	}

	// Prefer Bearer; if email provided, also set Basic to support API token
	if email != "" {
		basic := base64.StdEncoding.EncodeToString([]byte(email + ":" + token))
		req.Header.Set("Authorization", "Basic "+basic)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")

	// Log raw request (masking secrets)
	maskAuth := func(h string) string {
		if h == "" {
			return ""
		}
		// Preserve scheme, mask credentials/token
		if strings.HasPrefix(h, "Basic ") {
			return "Basic ***masked***"
		}
		if strings.HasPrefix(h, "Bearer ") {
			return "Bearer ***masked***"
		}
		return "***masked***"
	}

	// Collect headers for logging with masking
	var headerLines []string
	for k, v := range req.Header {
		val := strings.Join(v, ", ")
		if strings.EqualFold(k, "Authorization") {
			val = maskAuth(val)
		}
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", k, val))
	}

	if usePOST {
		log.Printf("[Jira] Request: %s %s\nHeaders:\n%s\nBody:\n%s", req.Method, req.URL.String(), strings.Join(headerLines, "\n"), string(postBodyBytes))
	} else {
		log.Printf("[Jira] Request: %s %s\nHeaders:\n%s", req.Method, req.URL.String(), strings.Join(headerLines, "\n"))
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read full response body for logging and parsing
	respBodyBytes, _ := io.ReadAll(resp.Body)

	// Log response headers
	var respHeaderLines []string
	for k, v := range resp.Header {
		respHeaderLines = append(respHeaderLines, fmt.Sprintf("%s: %s", k, strings.Join(v, ", ")))
	}

	// Limit the logged body size to avoid excessive logs
	const maxLogBody = 1 << 14 // 16 KiB
	bodyForLog := respBodyBytes
	if len(bodyForLog) > maxLogBody {
		bodyForLog = bodyForLog[:maxLogBody]
	}
	log.Printf("[Jira] Response: %s\nHeaders:\n%s\nBody (%d bytes, showing %d):\n%s", resp.Status, strings.Join(respHeaderLines, "\n"), len(respBodyBytes), len(bodyForLog), string(bodyForLog))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			hint := "Ensure JIRA_URL, JIRA_TOKEN are correct"
			if email == "" {
				hint += "; add JIRA_EMAIL to use Basic auth with API token for Jira Cloud"
			}
			return nil, fmt.Errorf("jira search failed: %s (%s)", resp.Status, hint)
		}
		return nil, fmt.Errorf("jira search failed: %s", resp.Status)
	}

	var jsr jiraSearchResponse
	if err := json.Unmarshal(respBodyBytes, &jsr); err != nil {
		return nil, fmt.Errorf("failed to parse jira response: %w", err)
	}

	// Build simplified issues
	issues := make([]JiraIssue, 0, len(jsr.Issues))
	for _, it := range jsr.Issues {
		assignee := ""
		if it.Fields.Assignee != nil {
			assignee = it.Fields.Assignee.DisplayName
		}

		// Compose issue URL: {JIRA_URL}/browse/{KEY}
		browseBase := strings.TrimRight(jiraURL, "/") + "/browse/" + it.Key
		issues = append(issues, JiraIssue{
			Key:      it.Key,
			Summary:  it.Fields.Summary,
			Status:   it.Fields.Status.Name,
			Assignee: assignee,
			URL:      browseBase,
		})
	}

	return issues, nil
}

func executeJiraSearchIssuesTool(args map[string]interface{}) (*ToolResponse, error) {
	// Extract params
	query, _ := args["query"].(string)
	if query == "" {
		// Accept alias "jql" too
		query, _ = args["jql"].(string)
	}
	if query == "" {
		return &ToolResponse{Success: false, Error: "query (JQL) parameter is required"}, nil
	}
	max := 10
	if mv, ok := args["max"].(float64); ok { // JSON numbers decode to float64
		max = int(mv)
	} else if mi, ok := args["max"].(int); ok {
		max = mi
	}

	// Optional parameters per Jira docs
	opts := map[string]interface{}{}
	if v, ok := args["fields"].([]string); ok {
		opts["fields"] = v
	} else if v, ok := args["fields"].(string); ok && v != "" {
		parts := strings.Split(v, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		opts["fields"] = parts
	}
	if v, ok := args["expand"].(string); ok {
		opts["expand"] = v
	}
	if v, ok := args["nextPageToken"].(string); ok {
		opts["nextPageToken"] = v
	}
	if v, ok := args["fieldsByKeys"].(bool); ok {
		opts["fieldsByKeys"] = v
	}
	if v, ok := args["failFast"].(bool); ok {
		opts["failFast"] = v
	}
	// reconcileIssues may arrive as []any or []float64
	if vf, ok := args["reconcileIssues"].([]interface{}); ok {
		arr := make([]int, 0, len(vf))
		for _, itm := range vf {
			switch t := itm.(type) {
			case float64:
				arr = append(arr, int(t))
			case int:
				arr = append(arr, t)
			}
		}
		if len(arr) > 0 {
			opts["reconcileIssues"] = arr
		}
	} else if vi, ok := args["reconcileIssues"].([]int); ok {
		if len(vi) > 0 {
			opts["reconcileIssues"] = vi
		}
	}

	// Read config
	cfg, err := ini.Load(os.ExpandEnv(config.ConfigFilePath))
	if err != nil {
		return &ToolResponse{Success: false, Error: fmt.Sprintf("Config file error: %v", err)}, nil
	}
	def := cfg.Section("default")
	jiraURL := def.Key("JIRA_URL").String()
	jiraToken := def.Key("JIRA_TOKEN").String()
	jiraEmail := def.Key("JIRA_EMAIL").String() // optional; if present use Basic auth

	issues, err := jiraDoRequest(jiraURL, jiraToken, jiraEmail, query, max, opts)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}

	return &ToolResponse{Success: true, Data: map[string]interface{}{
		"count":  len(issues),
		"issues": issues,
	}}, nil
}

func init() {
	// Register tool metadata
	tools["jira_search_issues"] = Tool{
		Name:        "jira_search_issues",
		Description: "Search Jira issues using Jira Enhanced JQL API (GET/POST)",
		Help: `Usage: /tool jira_search_issues --query <JQL> [--max <N>] [--fields <csv>] [--expand <s>] [--nextPageToken <s>] [--fieldsByKeys <bool>] [--failFast <bool>] [--reconcileIssues <json-array>]

Parameters:
  --query <JQL>    The JQL query string (alias: --jql)
  --max <N>        Maximum results to return (default: 10)
  --fields <csv>   Comma-separated fields to return (default: key,summary,status,assignee)
  --expand <s>     Expand parameter per Jira API
  --nextPageToken <s>  Pagination token from previous response
  --fieldsByKeys <bool> If true, interpret fields by keys
  --failFast <bool> If true, fail fast on parsing
  --reconcileIssues <json-array> Enable read-after-write consistency (forces POST)

Examples:
  /tool jira_search_issues --query "project = TEST ORDER BY created DESC" --max 5
  /tool jira_search_issues --help`,
		Parameters: map[string]string{
			"query": "JQL query string (alias: jql)",
			"max":   "Maximum results to return (default: 10)",
			"fields": "Comma-separated list of fields (optional)",
			"expand": "Expand parameter (optional)",
			"nextPageToken": "Pagination token (optional)",
			"fieldsByKeys": "Boolean (optional)",
			"failFast": "Boolean (optional)",
			"reconcileIssues": "JSON array of issue IDs to reconcile (optional; forces POST)",
		},
	}

	// Register executor
	toolExecutors["jira_search_issues"] = executeJiraSearchIssuesTool
}
