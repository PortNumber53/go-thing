package utility

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
)

// GitHubDo performs an authenticated request to the GitHub REST API.
// It reads configuration via LoadConfig():
//   - GITHUB_API_BASE (default: https://api.github.com)
//   - GITHUB_TOKEN (required for authenticated requests; PAT or GitHub App token)
//
// Example:
//  status, body, hdrs, err := GitHubDo("GET", "/repos/owner/repo", nil, nil)
func GitHubDo(method, path string, q url.Values, body interface{}) (int, []byte, http.Header, error) {
    cfg, _ := LoadConfig()
    base := "https://api.github.com"
    if cfg != nil {
        if v := strings.TrimSpace(cfg["GITHUB_API_BASE"]); v != "" {
            base = strings.TrimRight(v, "/")
        }
    }
    // Ensure single slash join
    if !strings.HasPrefix(path, "/") {
        path = "/" + path
    }
    u := base + path
    if len(q) > 0 {
        if strings.Contains(u, "?") {
            u += "&" + q.Encode()
        } else {
            u += "?" + q.Encode()
        }
    }

    var bodyReader io.Reader
    if body != nil {
        b, err := json.Marshal(body)
        if err != nil {
            return 0, nil, nil, fmt.Errorf("github: marshal body: %w", err)
        }
        bodyReader = bytes.NewReader(b)
    }

    req, err := http.NewRequest(method, u, bodyReader)
    if err != nil {
        return 0, nil, nil, fmt.Errorf("github: new request: %w", err)
    }

    // Headers
    req.Header.Set("Accept", "application/vnd.github+json")
    // Pin an API version; callers can override via custom header if needed
    req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
    if bodyReader != nil {
        req.Header.Set("Content-Type", "application/json")
    }
    req.Header.Set("User-Agent", "go-thing-agent/1.0")

    // Auth
    if cfg != nil {
        if tok := strings.TrimSpace(cfg["GITHUB_TOKEN"]); tok != "" {
            // Personal access token or App installation token
            req.Header.Set("Authorization", "Bearer "+tok)
        }
    }

    // Client
    httpClient := &http.Client{Timeout: 30 * time.Second}
    resp, err := httpClient.Do(req)
    if err != nil {
        return 0, nil, nil, fmt.Errorf("github: do: %w", err)
    }
    defer resp.Body.Close()

    rb, err := io.ReadAll(resp.Body)
    if err != nil {
        return resp.StatusCode, nil, resp.Header, fmt.Errorf("github: read body: %w", err)
    }
    return resp.StatusCode, rb, resp.Header, nil
}
