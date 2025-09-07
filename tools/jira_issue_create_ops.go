package tools

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ---- create_issue refactor helpers ----
type jiraCreateIssueParams struct {
	// Raw passthrough fields object (if provided)
	Fields map[string]interface{}

	// Convenience params
	ProjectID      string
	ProjectKey     string
	IssueTypeID    string
	IssueTypeName  string
	Summary        string
	Description    interface{} // string or map[string]interface{} (handled by processADFValue at build time)
	Environment    interface{} // string or map[string]interface{} (handled by processADFValue at build time)
	Labels         interface{} // []string | []interface{} | string
	PriorityName   string
	PriorityID     string
	AssigneeAcctID string
	ReporterAcctID string
	ParentID       string
	ParentKey      string

	// Optional top-level keys
	Update          interface{}
	Properties      interface{}
	HistoryMetadata interface{}
	Transition      interface{}
}

// parseJiraCreateIssueArgs normalizes and validates args into jiraCreateIssueParams.
// It preserves existing behavior including JSON validation for certain string inputs.
func parseJiraCreateIssueArgs(args map[string]interface{}) (*jiraCreateIssueParams, *ToolResponse) {
	p := &jiraCreateIssueParams{Fields: map[string]interface{}{}}

	// fields passthrough may be JSON string or object
	if raw, ok := args["fields"]; ok {
		switch v := raw.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				var obj map[string]interface{}
				if err := json.Unmarshal([]byte(v), &obj); err == nil {
					// Only assign if the decoded object is non-nil (avoid nil map)
					if obj != nil {
						p.Fields = obj
					}
				} else {
					return nil, &ToolResponse{Success: false, Error: fmt.Sprintf("invalid fields JSON: %v", err)}
				}
			}
		case map[string]interface{}:
			// Guard against assigning a nil map (e.g., from JSON null)
			if v != nil {
				p.Fields = v
			}
		}
	}

	// Convenience params
	// Centralize string-based convenience params for maintainability
	stringParams := map[string]*string{
		"projectId":         &p.ProjectID,
		"projectKey":        &p.ProjectKey,
		"issuetypeId":       &p.IssueTypeID,
		"issuetypeName":     &p.IssueTypeName,
		"summary":           &p.Summary,
		"priorityName":      &p.PriorityName,
		"priorityId":        &p.PriorityID,
		"assigneeAccountId": &p.AssigneeAcctID,
		"reporterAccountId": &p.ReporterAcctID,
		"parentId":          &p.ParentID,
		"parentKey":         &p.ParentKey,
	}
	for name, ptr := range stringParams {
		if v, ok := args[name].(string); ok && v != "" {
			*ptr = v
		}
	}

	// Non-string or mixed-type convenience params
	if v, ok := args["description"]; ok {
		p.Description = v
	}
	if v, ok := args["environment"]; ok {
		p.Environment = v
	}
	if v, ok := args["labels"]; ok {
		p.Labels = v
	}

	// Optional top-level keys: if provided as JSON string, validate and unmarshal
	validateJSONOrPass := func(name string) (interface{}, *ToolResponse) {
		if v, ok := args[name]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				var obj interface{}
				if err := json.Unmarshal([]byte(s), &obj); err != nil {
					return nil, &ToolResponse{Success: false, Error: fmt.Sprintf("invalid JSON for parameter '%s': %v", name, err)}
				}
				return obj, nil
			}
			return v, nil
		}
		return nil, nil
	}
	// DRY handling of optional top-level keys
	optionalKeys := []struct {
		name string
		ptr  *interface{}
	}{
		{"update", &p.Update},
		{"properties", &p.Properties},
		{"historyMetadata", &p.HistoryMetadata},
		{"transition", &p.Transition},
	}
	for _, key := range optionalKeys {
		v, tr := validateJSONOrPass(key.name)
		if tr != nil {
			return nil, tr
		}
		*key.ptr = v
	}

	return p, nil
}

// buildJiraCreateIssueBody produces the final request body with fields and optional sections.
func buildJiraCreateIssueBody(p *jiraCreateIssueParams) (map[string]interface{}, *ToolResponse) {
	body := map[string]interface{}{}
	fields := p.Fields

	// helper to ensure nested map
	ensureMap := func(m map[string]interface{}, key string) map[string]interface{} {
		if child, ok := m[key].(map[string]interface{}); ok {
			return child
		}
		child := map[string]interface{}{}
		m[key] = child
		return child
	}

	// environment
	if _, exists := fields["environment"]; !exists {
		if processedEnv, ok := processADFValue(p.Environment); ok {
			fields["environment"] = processedEnv
		}
	}

	// project: prefer id over key (only if not provided in fields)
	if _, exists := fields["project"]; !exists {
		if p.ProjectID != "" {
			ensureMap(fields, "project")["id"] = p.ProjectID
		} else if p.ProjectKey != "" {
			ensureMap(fields, "project")["key"] = p.ProjectKey
		}
	}

	// issuetype: prefer id over name (only if not provided in fields)
	if _, exists := fields["issuetype"]; !exists {
		if p.IssueTypeID != "" {
			ensureMap(fields, "issuetype")["id"] = p.IssueTypeID
		} else if p.IssueTypeName != "" {
			ensureMap(fields, "issuetype")["name"] = p.IssueTypeName
		}
	}

	// summary (only if not provided in fields)
	if _, exists := fields["summary"]; !exists {
		if p.Summary != "" {
			fields["summary"] = p.Summary
		}
	}

	// description (ADF-capable) (only if not provided in fields)
	if _, exists := fields["description"]; !exists {
		if processedDesc, ok := processADFValue(p.Description); ok {
			fields["description"] = processedDesc
		}
	}

	// labels parsing (only if not provided in fields)
	if _, exists := fields["labels"]; !exists {
		if p.Labels != nil {
			var arr []string
			addLabel := func(s string) {
				trimmed := strings.TrimSpace(s)
				if trimmed != "" {
					arr = append(arr, trimmed)
				}
			}
			switch v := p.Labels.(type) {
			case []interface{}:
				for _, it := range v {
					if s, ok := it.(string); ok {
						addLabel(s)
					}
				}
			case []string:
				for _, s := range v {
					addLabel(s)
				}
			case string:
				for _, s := range strings.Split(v, ",") {
					addLabel(s)
				}
			}
			if len(arr) > 0 {
				fields["labels"] = arr
			}
		}
	}

	// priority: prefer id over name (avoid setting both); only if not provided in fields
	if _, exists := fields["priority"]; !exists {
		if p.PriorityID != "" {
			fields["priority"] = map[string]interface{}{"id": p.PriorityID}
		} else if p.PriorityName != "" {
			fields["priority"] = map[string]interface{}{"name": p.PriorityName}
		}
	}

	// assignee / reporter (only if not provided in fields)
	if _, exists := fields["assignee"]; !exists {
		if p.AssigneeAcctID != "" {
			fields["assignee"] = map[string]interface{}{"accountId": p.AssigneeAcctID}
		}
	}
	if _, exists := fields["reporter"]; !exists {
		if p.ReporterAcctID != "" {
			fields["reporter"] = map[string]interface{}{"accountId": p.ReporterAcctID}
		}
	}

	// parent (only if not provided in fields)
	if _, exists := fields["parent"]; !exists {
		if p.ParentID != "" {
			fields["parent"] = map[string]interface{}{"id": p.ParentID}
		} else if p.ParentKey != "" {
			fields["parent"] = map[string]interface{}{"key": p.ParentKey}
		}
	}

	if len(fields) == 0 {
		return nil, &ToolResponse{Success: false, Error: "fields are required (provide 'fields' or convenience params like projectKey/issuetypeId/summary)"}
	}

	body["fields"] = fields

	// Optional passthrough sections
	if p.Update != nil {
		body["update"] = p.Update
	}
	if p.Properties != nil {
		body["properties"] = p.Properties
	}
	if p.HistoryMetadata != nil {
		body["historyMetadata"] = p.HistoryMetadata
	}
	if p.Transition != nil {
		body["transition"] = p.Transition
	}

	return body, nil
}

// ----------------- jira_create_issue -----------------
// POST /rest/api/3/issue
func executeJiraCreateIssueTool(args map[string]interface{}) (*ToolResponse, error) {
	// Parse args
	params, tr := parseJiraCreateIssueArgs(args)
	if tr != nil {
		return tr, nil
	}

	// Build body
	body, tr2 := buildJiraCreateIssueBody(params)
	if tr2 != nil {
		return tr2, nil
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
				for _, m := range msgs {
					if s, ok := m.(string); ok {
						details = append(details, s)
					}
				}
			}
			if errs, ok := eobj["errors"].(map[string]interface{}); ok {
				for k, v := range errs {
					details = append(details, fmt.Sprintf("%s: %v", k, v))
				}
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
