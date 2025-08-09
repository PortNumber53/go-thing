package tools

import (
	"encoding/base64"
	"encoding/json"
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

// minimal user shape for common fields
type jiraUser struct {
	AccountID   string            `json:"accountId,omitempty"`
	AccountType string            `json:"accountType,omitempty"`
	Active      bool              `json:"active,omitempty"`
	DisplayName string            `json:"displayName,omitempty"`
	Email       string            `json:"emailAddress,omitempty"`
	AvatarUrls  map[string]string `json:"avatarUrls,omitempty"`
	Self        string            `json:"self,omitempty"`
}

type foundUsersResponse struct {
	Header string     `json:"header"`
	Total  int        `json:"total"`
	Users  []jiraUser `json:"users"`
}

type pageBeanUser struct {
	Self       string     `json:"self"`
	NextPage   string     `json:"nextPage"`
	MaxResults int        `json:"maxResults"`
	StartAt    int        `json:"startAt"`
	Total      int        `json:"total"`
	IsLast     bool       `json:"isLast"`
	Values     []jiraUser `json:"values"`
}

// helper to auth and execute GET with query params
func jiraUserGet(baseURL, token, email, endpoint string, q map[string]string) ([]byte, *http.Response, error) {
	if baseURL == "" || token == "" {
		return nil, nil, fmt.Errorf("JIRA_URL or JIRA_TOKEN not configured")
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid JIRA_URL: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + endpoint
	qs := u.Query()
	for k, v := range q {
		if v != "" {
			qs.Set(k, v)
		}
	}
	u.RawQuery = qs.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	if email != "" {
		b := base64.StdEncoding.EncodeToString([]byte(email + ":" + token))
		req.Header.Set("Authorization", "Basic "+b)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")

	// Log (mask auth)
	mask := func(v string) string {
		if v == "" {
			return ""
		}
		if strings.HasPrefix(v, "Basic ") {
			return "Basic ***masked***"
		}
		if strings.HasPrefix(v, "Bearer ") {
			return "Bearer ***masked***"
		}
		return "***masked***"
	}
	var headerLines []string
	for k, v := range req.Header {
		val := strings.Join(v, ", ")
		if strings.EqualFold(k, "Authorization") {
			val = mask(val)
		}
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", k, val))
	}
	log.Printf("[Jira Users] Request: %s %s\nHeaders:\n%s", req.Method, req.URL.String(), strings.Join(headerLines, "\n"))

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		// body read by caller
	}()
	body, _ := io.ReadAll(resp.Body)
	// copy body for caller since we consumed it
	resp.Body.Close()
	resp.Body = io.NopCloser(strings.NewReader(string(body)))

	// Log response
	var respHeaders []string
	for k, v := range resp.Header {
		respHeaders = append(respHeaders, fmt.Sprintf("%s: %s", k, strings.Join(v, ", ")))
	}
	const maxLog = 1 << 14
	bf := body
	if len(bf) > maxLog {
		bf = bf[:maxLog]
	}
	log.Printf("[Jira Users] Response: %s\nHeaders:\n%s\nBody (%d bytes, showing %d):\n%s", resp.Status, strings.Join(respHeaders, "\n"), len(body), len(bf), string(bf))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, resp, fmt.Errorf("jira API failed: %s", resp.Status)
	}
	return body, resp, nil
}

// executor helpers
func getJiraConfig() (jiraURL, jiraToken, jiraEmail string, err error) {
	cfg, e := ini.Load(os.ExpandEnv(config.ConfigFilePath))
	if e != nil {
		return "", "", "", fmt.Errorf("Config file error: %v", e)
	}
	def := cfg.Section("default")
	return def.Key("JIRA_URL").String(), def.Key("JIRA_TOKEN").String(), def.Key("JIRA_EMAIL").String(), nil
}

// Tool: jira_users_all -> GET /rest/api/3/users/search
func executeJiraUsersAll(args map[string]interface{}) (*ToolResponse, error) {
	jiraURL, jiraToken, jiraEmail, err := getJiraConfig()
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	q := map[string]string{}
	if v, ok := args["startAt"].(float64); ok {
		q["startAt"] = strconv.Itoa(int(v))
	}
	if v, ok := args["maxResults"].(float64); ok {
		q["maxResults"] = strconv.Itoa(int(v))
	}
	body, _, err := jiraUserGet(jiraURL, jiraToken, jiraEmail, "/rest/api/3/users/search", q)
	if err != nil {
		return &ToolResponse{Success: false, Error: err.Error()}, nil
	}
	var users []jiraUser
	_ = json.Unmarshal(body, &users) // best-effort simplify
	if len(users) > 0 {
		return &ToolResponse{Success: true, Data: users}, nil
	}
	// fallback to raw
	var raw any
	_ = json.Unmarshal(body, &raw)
	return &ToolResponse{Success: true, Data: raw}, nil
}

// Tool: jira_users_assignable_multi -> GET /rest/api/3/user/assignable/multiProjectSearch
func executeJiraUsersAssignableMulti(args map[string]interface{}) (*ToolResponse, error) {
	jiraURL, jiraToken, jiraEmail, err := getJiraConfig()
	if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	q := map[string]string{}
	if v, ok := args["query"].(string); ok { q["query"] = v }
	// projectKeys can be csv or array
	if v, ok := args["projectKeys"].(string); ok && v != "" { q["projectKeys"] = v } else if arr, ok := args["projectKeys"].([]interface{}); ok {
		parts := make([]string,0,len(arr))
		for _, it := range arr { parts = append(parts, fmt.Sprint(it)) }
		q["projectKeys"] = strings.Join(parts, ",")
	}
	if v, ok := args["startAt"].(float64); ok { q["startAt"] = strconv.Itoa(int(v)) }
	if v, ok := args["maxResults"].(float64); ok { q["maxResults"] = strconv.Itoa(int(v)) }
	body, _, err := jiraUserGet(jiraURL, jiraToken, jiraEmail, "/rest/api/3/user/assignable/multiProjectSearch", q)
	if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	var users []jiraUser
	if err := json.Unmarshal(body, &users); err == nil {
		return &ToolResponse{Success:true, Data: users}, nil
	}
	var raw any; _ = json.Unmarshal(body, &raw)
	return &ToolResponse{Success:true, Data: raw}, nil
}

// Tool: jira_users_assignable -> GET /rest/api/3/user/assignable/search
func executeJiraUsersAssignable(args map[string]interface{}) (*ToolResponse, error) {
	jiraURL, jiraToken, jiraEmail, err := getJiraConfig(); if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	q := map[string]string{}
	if v, ok := args["query"].(string); ok { q["query"] = v }
	if v, ok := args["sessionId"].(string); ok { q["sessionId"] = v }
	if v, ok := args["username"].(string); ok { q["username"] = v }
	if v, ok := args["accountId"].(string); ok { q["accountId"] = v }
	if v, ok := args["project"].(string); ok { q["project"] = v }
	if v, ok := args["issueKey"].(string); ok { q["issueKey"] = v }
	if v, ok := args["issueId"].(string); ok { q["issueId"] = v }
	if v, ok := args["actionDescriptorId"].(float64); ok { q["actionDescriptorId"] = strconv.Itoa(int(v)) }
	if v, ok := args["startAt"].(float64); ok { q["startAt"] = strconv.Itoa(int(v)) }
	if v, ok := args["maxResults"].(float64); ok { q["maxResults"] = strconv.Itoa(int(v)) }
	body, _, err := jiraUserGet(jiraURL, jiraToken, jiraEmail, "/rest/api/3/user/assignable/search", q)
	if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	var users []jiraUser; if err := json.Unmarshal(body, &users); err == nil { return &ToolResponse{Success:true, Data: users}, nil }
	var raw any; _ = json.Unmarshal(body, &raw); return &ToolResponse{Success:true, Data: raw}, nil
}

// Tool: jira_users_permission_search -> GET /rest/api/3/user/permission/search
func executeJiraUsersPermissionSearch(args map[string]interface{}) (*ToolResponse, error) {
	jiraURL, jiraToken, jiraEmail, err := getJiraConfig(); if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	q := map[string]string{}
	if v, ok := args["query"].(string); ok { q["query"] = v }
	if v, ok := args["username"].(string); ok { q["username"] = v }
	if v, ok := args["accountId"].(string); ok { q["accountId"] = v }
	if v, ok := args["permissions"].(string); ok { q["permissions"] = v }
	if v, ok := args["issueKey"].(string); ok { q["issueKey"] = v }
	if v, ok := args["projectKey"].(string); ok { q["projectKey"] = v }
	if v, ok := args["startAt"].(float64); ok { q["startAt"] = strconv.Itoa(int(v)) }
	if v, ok := args["maxResults"].(float64); ok { q["maxResults"] = strconv.Itoa(int(v)) }
	body, _, err := jiraUserGet(jiraURL, jiraToken, jiraEmail, "/rest/api/3/user/permission/search", q)
	if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	var users []jiraUser; if err := json.Unmarshal(body, &users); err == nil { return &ToolResponse{Success:true, Data: users}, nil }
	var raw any; _ = json.Unmarshal(body, &raw); return &ToolResponse{Success:true, Data: raw}, nil
}

// Tool: jira_user_picker -> GET /rest/api/3/user/picker
func executeJiraUserPicker(args map[string]interface{}) (*ToolResponse, error) {
	jiraURL, jiraToken, jiraEmail, err := getJiraConfig(); if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	q := map[string]string{}
	// required query
	q["query"], _ = args["query"].(string)
	if q["query"] == "" { return &ToolResponse{Success:false, Error:"query is required"}, nil }
	if v, ok := args["maxResults"].(float64); ok { q["maxResults"] = strconv.Itoa(int(v)) }
	if v, ok := args["showAvatar"].(bool); ok { q["showAvatar"] = strconv.FormatBool(v) }
	// excludeAccountIds array or csv
	if v, ok := args["excludeAccountIds"].(string); ok && v != "" { q["excludeAccountIds"] = v } else if arr, ok := args["excludeAccountIds"].([]interface{}); ok {
		parts := make([]string,0,len(arr)); for _, it := range arr { parts = append(parts, fmt.Sprint(it)) }; q["excludeAccountIds"] = strings.Join(parts, ",")
	}
	if v, ok := args["avatarSize"].(string); ok { q["avatarSize"] = v }
	if v, ok := args["excludeConnectUsers"].(bool); ok { q["excludeConnectUsers"] = strconv.FormatBool(v) }
	body, _, err := jiraUserGet(jiraURL, jiraToken, jiraEmail, "/rest/api/3/user/picker", q)
	if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	var fu foundUsersResponse; if err := json.Unmarshal(body, &fu); err == nil { return &ToolResponse{Success:true, Data: fu}, nil }
	var raw any; _ = json.Unmarshal(body, &raw); return &ToolResponse{Success:true, Data: raw}, nil
}

// Tool: jira_users_search -> GET /rest/api/3/user/search
func executeJiraUsersSearch(args map[string]interface{}) (*ToolResponse, error) {
	jiraURL, jiraToken, jiraEmail, err := getJiraConfig(); if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	q := map[string]string{}
	if v, ok := args["query"].(string); ok { q["query"] = v }
	if v, ok := args["username"].(string); ok { q["username"] = v }
	if v, ok := args["accountId"].(string); ok { q["accountId"] = v }
	if v, ok := args["property"].(string); ok { q["property"] = v }
	if v, ok := args["startAt"].(float64); ok { q["startAt"] = strconv.Itoa(int(v)) }
	if v, ok := args["maxResults"].(float64); ok { q["maxResults"] = strconv.Itoa(int(v)) }
	body, _, err := jiraUserGet(jiraURL, jiraToken, jiraEmail, "/rest/api/3/user/search", q)
	if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	var users []jiraUser; if err := json.Unmarshal(body, &users); err == nil { return &ToolResponse{Success:true, Data: users}, nil }
	var raw any; _ = json.Unmarshal(body, &raw); return &ToolResponse{Success:true, Data: raw}, nil
}

// Tool: jira_users_search_query -> GET /rest/api/3/user/search/query
func executeJiraUsersSearchQuery(args map[string]interface{}) (*ToolResponse, error) {
	jiraURL, jiraToken, jiraEmail, err := getJiraConfig(); if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	q := map[string]string{}
	q["query"], _ = args["query"].(string)
	if q["query"] == "" { return &ToolResponse{Success:false, Error: "query is required"}, nil }
	if v, ok := args["startAt"].(float64); ok { q["startAt"] = strconv.Itoa(int(v)) }
	if v, ok := args["maxResults"].(float64); ok { q["maxResults"] = strconv.Itoa(int(v)) }
	body, _, err := jiraUserGet(jiraURL, jiraToken, jiraEmail, "/rest/api/3/user/search/query", q)
	if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	var page pageBeanUser; if err := json.Unmarshal(body, &page); err == nil { return &ToolResponse{Success:true, Data: page}, nil }
	var raw any; _ = json.Unmarshal(body, &raw); return &ToolResponse{Success:true, Data: raw}, nil
}

// Tool: jira_users_search_query_key -> GET /rest/api/3/user/search/query/key
func executeJiraUsersSearchQueryKey(args map[string]interface{}) (*ToolResponse, error) {
	jiraURL, jiraToken, jiraEmail, err := getJiraConfig(); if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	q := map[string]string{}
	q["query"], _ = args["query"].(string)
	if q["query"] == "" { return &ToolResponse{Success:false, Error: "query is required"}, nil }
	if v, ok := args["startAt"].(float64); ok { q["startAt"] = strconv.Itoa(int(v)) }
	if v, ok := args["maxResult"].(float64); ok { q["maxResult"] = strconv.Itoa(int(v)) }
	body, _, err := jiraUserGet(jiraURL, jiraToken, jiraEmail, "/rest/api/3/user/search/query/key", q)
	if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	var raw any; _ = json.Unmarshal(body, &raw); return &ToolResponse{Success:true, Data: raw}, nil
}

// Tool: jira_users_viewissue_search -> GET /rest/api/3/user/viewissue/search
func executeJiraUsersViewIssueSearch(args map[string]interface{}) (*ToolResponse, error) {
	jiraURL, jiraToken, jiraEmail, err := getJiraConfig(); if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	q := map[string]string{}
	if v, ok := args["query"].(string); ok { q["query"] = v }
	if v, ok := args["username"].(string); ok { q["username"] = v }
	if v, ok := args["accountId"].(string); ok { q["accountId"] = v }
	if v, ok := args["issueKey"].(string); ok { q["issueKey"] = v }
	if v, ok := args["projectKey"].(string); ok { q["projectKey"] = v }
	if v, ok := args["startAt"].(float64); ok { q["startAt"] = strconv.Itoa(int(v)) }
	if v, ok := args["maxResults"].(float64); ok { q["maxResults"] = strconv.Itoa(int(v)) }
	body, _, err := jiraUserGet(jiraURL, jiraToken, jiraEmail, "/rest/api/3/user/viewissue/search", q)
	if err != nil { return &ToolResponse{Success:false, Error: err.Error()}, nil }
	var users []jiraUser; if err := json.Unmarshal(body, &users); err == nil { return &ToolResponse{Success:true, Data: users}, nil }
	var raw any; _ = json.Unmarshal(body, &raw); return &ToolResponse{Success:true, Data: raw}, nil
}

func init() {
	// Register tool metadata and executors
	tools["jira_users_all"] = Tool{
		Name:        "jira_users_all",
		Description: "Get all users (active/inactive/deleted)",
		Help:       "Usage: /tool jira_users_all [--startAt <n>] [--maxResults <n>]",
		Parameters: map[string]string{
			"startAt":    "Integer start index (optional)",
			"maxResults": "Integer max results (optional)",
		},
	}
	toolExecutors["jira_users_all"] = executeJiraUsersAll

	tools["jira_users_assignable_multi"] = Tool{
		Name:        "jira_users_assignable_multi",
		Description: "Find users assignable to issues across multiple projects",
		Help:       "Usage: /tool jira_users_assignable_multi --projectKeys <CSV> [--query <s>] [--startAt <n>] [--maxResults <n>]",
		Parameters: map[string]string{
			"projectKeys": "Comma-separated project keys (required by Jira)",
			"query":       "Search string (optional)",
			"startAt":     "Start index (optional)",
			"maxResults":  "Max results (optional)",
		},
	}
	toolExecutors["jira_users_assignable_multi"] = executeJiraUsersAssignableMulti

	tools["jira_users_assignable"] = Tool{
		Name:        "jira_users_assignable",
		Description: "Find users assignable to a specific issue or project",
		Help:       "Usage: /tool jira_users_assignable [--project <key>|--issueKey <KEY>|--issueId <id>] [--query <s>] [--startAt <n>] [--maxResults <n>]",
		Parameters: map[string]string{
			"project":    "Project key or id",
			"issueKey":   "Issue key",
			"issueId":    "Issue id",
			"query":      "Filter string",
			"accountId":  "Account ID to check assignability",
			"startAt":    "Start index",
			"maxResults": "Max results",
		},
	}
	toolExecutors["jira_users_assignable"] = executeJiraUsersAssignable

	tools["jira_users_permission_search"] = Tool{
		Name:        "jira_users_permission_search",
		Description: "Find users with specific permissions for a project or issue",
		Help:       "Usage: /tool jira_users_permission_search --permissions <permKey> [--projectKey <key>|--issueKey <KEY>] [--query <s>] [--startAt <n>] [--maxResults <n>]",
		Parameters: map[string]string{
			"permissions": "Permissions to check (required by Jira)",
			"projectKey":  "Project key",
			"issueKey":    "Issue key",
			"query":       "Filter string",
			"startAt":     "Start index",
			"maxResults":  "Max results",
		},
	}
	toolExecutors["jira_users_permission_search"] = executeJiraUsersPermissionSearch

	tools["jira_user_picker"] = Tool{
		Name:        "jira_user_picker",
		Description: "Find users for picker (highlights matches)",
		Help:       "Usage: /tool jira_user_picker --query <s> [--maxResults <n>] [--excludeAccountIds <CSV>] [--showAvatar <bool>] [--avatarSize <s>] [--excludeConnectUsers <bool>]",
		Parameters: map[string]string{
			"query":               "Search string (required)",
			"maxResults":          "Max results (optional)",
			"excludeAccountIds":   "Comma-separated account IDs to exclude",
			"showAvatar":          "Boolean",
			"avatarSize":          "Avatar size hint",
			"excludeConnectUsers": "Boolean",
		},
	}
	toolExecutors["jira_user_picker"] = executeJiraUserPicker

	tools["jira_users_search"] = Tool{
		Name:        "jira_users_search",
		Description: "Find active users matching a search string/property",
		Help:       "Usage: /tool jira_users_search [--query <s>] [--username <s>] [--accountId <s>] [--property <s>] [--startAt <n>] [--maxResults <n>]",
		Parameters: map[string]string{
			"query":      "Search string",
			"username":   "Deprecated username",
			"accountId":  "Account ID",
			"property":   "Property key to match",
			"startAt":    "Start index",
			"maxResults": "Max results",
		},
	}
	toolExecutors["jira_users_search"] = executeJiraUsersSearch

	tools["jira_users_search_query"] = Tool{
		Name:        "jira_users_search_query",
		Description: "Structured query to find users (paginated)",
		Help:       "Usage: /tool jira_users_search_query --query <structured> [--startAt <n>] [--maxResults <n>]",
		Parameters: map[string]string{
			"query":      "Structured user query (required)",
			"startAt":    "Start index",
			"maxResults": "Max results",
		},
	}
	toolExecutors["jira_users_search_query"] = executeJiraUsersSearchQuery

	tools["jira_users_search_query_key"] = Tool{
		Name:        "jira_users_search_query_key",
		Description: "Structured query returning only user keys (paginated)",
		Help:       "Usage: /tool jira_users_search_query_key --query <structured> [--startAt <n>] [--maxResult <n>]",
		Parameters: map[string]string{
			"query":     "Structured user query (required)",
			"startAt":   "Start index",
			"maxResult": "Max results",
		},
	}
	toolExecutors["jira_users_search_query_key"] = executeJiraUsersSearchQueryKey

	tools["jira_users_viewissue_search"] = Tool{
		Name:        "jira_users_viewissue_search",
		Description: "Find users with Browse permission for an issue/project",
		Help:       "Usage: /tool jira_users_viewissue_search [--issueKey <KEY>|--projectKey <key>] [--query <s>] [--startAt <n>] [--maxResults <n>]",
		Parameters: map[string]string{
			"issueKey":   "Issue key",
			"projectKey": "Project key",
			"query":      "Filter string",
			"startAt":    "Start index",
			"maxResults": "Max results",
		},
	}
	toolExecutors["jira_users_viewissue_search"] = executeJiraUsersViewIssueSearch
}
