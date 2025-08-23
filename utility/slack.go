package utility

import (
    "context"
    "errors"
    "fmt"
    "log"
    "strings"
    "time"

	"github.com/slack-go/slack"
	"go-thing/db"
)

// constants for Slack Home tab behavior and Slack API error matching.
const (
	// defaultRecentThreadsLimit defines how many recent threads to show by default
	// in the Slack Home tab and when no explicit limit is provided.
	defaultRecentThreadsLimit = 10

	// slackErrorHashConflict is returned by Slack when the provided view hash
	// is stale (someone else updated the view). In that case, we retry publish
	// without a hash.
	slackErrorHashConflict = "hash_conflict"

	// slackDateFallbackFormat is the Go time layout used to format timestamps
	// in the Slack Home recent threads list as a fallback human-readable string.
	// It pairs with Slack's date token for clients that can't render it.
	slackDateFallbackFormat = "2006-01-02 15:04:05 UTC"

	// maxTitleLenRecentThreads is the maximum number of runes to include from a
	// thread title in the Slack Home recent list to avoid hitting Slack's 3000
	// character limit on a single mrkdwn text object.
	maxTitleLenRecentThreads = 150
)

// Prebuilt replacer for escaping Slack mrkdwn-sensitive characters in titles.
// Defined at package scope to avoid per-call allocations.
var slackMrkdwnEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// truncateRunes truncates a string to a maximum of `max` runes. If the string
// is truncated, an ellipsis "…" is appended, and the total length of the
// returned string will not exceed `max`.
func truncateRunes(s string, max int) string {
    r := []rune(s)
    if max < 0 || len(r) <= max {
        return s
    }
    if max == 0 {
        return ""
    }
    // Reserve 1 rune for the ellipsis when truncation is needed.
    if max == 1 {
        return "…"
    }
    return string(r[:max-1]) + "…"
}

// getBotToken loads the config and returns the Slack bot token.
// Centralized to avoid duplication and ensure consistent error wrapping.
func getBotToken() (string, error) {
    cfg, err := LoadConfig()
    if err != nil {
        return "", fmt.Errorf("failed to load config: %w", err)
    }
    botToken := cfg["SLACK_BOT_TOKEN"]
    if strings.TrimSpace(botToken) == "" {
        return "", fmt.Errorf("SLACK_BOT_TOKEN missing in config")
    }
    return botToken, nil
}

// SendSlackResponse posts a message to a Slack channel using the bot token
// configured in the INI config (SLACK_BOT_TOKEN in [default]).
func SendSlackResponse(channel, message string) error {
    botToken, err := getBotToken()
    if err != nil {
        return err
    }
    api := slack.New(botToken)
	_, _, err = api.PostMessage(
		channel,
		slack.MsgOptionText(message, false),
		slack.MsgOptionAsUser(true),
	)
	if err != nil {
		return fmt.Errorf("failed to post message: %v", err)
	}
	log.Printf("[Slack API] Message sent to channel %s", channel)
	return nil
}

// threadSummary is a minimal projection of a thread for display purposes.
type threadSummary struct {
	ID        int64
	Title     string
	UpdatedAt time.Time
}

// fetchRecentThreads returns the most recently updated threads (up to limit).
func fetchRecentThreads(ctx context.Context, limit int) ([]threadSummary, error) {
	if limit <= 0 {
		limit = defaultRecentThreadsLimit
	}
	dbc := db.Get()
	if dbc == nil {
		return nil, fmt.Errorf("db not initialized")
	}
	rows, err := dbc.QueryContext(ctx, `SELECT id, COALESCE(title, ''), updated_at FROM threads ORDER BY updated_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying recent threads: %w", err)
	}
	defer rows.Close()
	out := make([]threadSummary, 0, limit)
	for rows.Next() {
		var t threadSummary
		if err := rows.Scan(&t.ID, &t.Title, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning thread row: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating over thread rows: %w", err)
	}
	return out, nil
}

// BuildSlackHomeView constructs a simple Home tab view with blocks.
// It returns the view and a non-fatal error if parts of the view could
// not be generated (e.g., DB fetch issues). Callers may still publish
// the returned view and log the partial failure.
func BuildSlackHomeView(ctx context.Context) (slack.HomeTabViewRequest, error) {
	header := slack.NewHeaderBlock(
		slack.NewTextBlockObject("plain_text", "Go-Thing • Home", false, false),
	)
	intro := slack.NewSectionBlock(
		slack.NewTextBlockObject("mrkdwn", "Welcome to the Go-Thing AI agent. Use any channel to ask questions, or DM the bot. This Home tab will show quick tips and links.", false, false),
		nil,
		nil,
	)
	tips := slack.NewSectionBlock(
		slack.NewTextBlockObject("mrkdwn", "• Type `/go-thing help` for commands (if configured)\n• Mention me in a channel to start a thread\n• Visit the web UI to manage conversations", false, false),
		nil,
		nil,
	)
	divider := slack.NewDividerBlock()
	// Recent threads
	var recentList string
	var buildErr error
	if threads, err := fetchRecentThreads(ctx, defaultRecentThreadsLimit); err != nil {
		buildErr = fmt.Errorf("recent threads unavailable: %w", err)
		recentList = "_No recent threads available._"
	} else if len(threads) == 0 {
		recentList = "_No threads yet. Start a conversation by messaging the bot!_"
	} else {
		var b strings.Builder
		for _, t := range threads {
			title := strings.TrimSpace(t.Title)
			if title == "" {
				title = "Untitled thread"
			}
            // Truncate overly long titles to keep the mrkdwn block under limits.
            title = truncateRunes(title, maxTitleLenRecentThreads)
            // Escape characters for Slack mrkdwn to prevent formatting issues.
            title = slackMrkdwnEscaper.Replace(title)
			// Example line: • #12 — Project kickoff (2025-08-22 18:30 UTC)
			fmt.Fprintf(&b, "• #%d — %s (updated <!date^%d^{date_short} {time}|%s>)\n", t.ID, title, t.UpdatedAt.Unix(), t.UpdatedAt.UTC().Format(slackDateFallbackFormat))
		}
		recentList = strings.TrimSuffix(b.String(), "\n")
	}
	recentHeader := slack.NewSectionBlock(
		slack.NewTextBlockObject("mrkdwn", "*Recent Threads*", false, false),
		nil,
		nil,
	)
	recent := slack.NewSectionBlock(
		slack.NewTextBlockObject("mrkdwn", recentList, false, false),
		nil,
		nil,
	)

	blocks := slack.Blocks{BlockSet: []slack.Block{header, intro, divider, tips, divider, recentHeader, recent}}
	return slack.HomeTabViewRequest{Type: slack.VTHomeTab, Blocks: blocks}, buildErr
}

// PublishSlackHomeTab publishes the Home tab for the given user using the bot token.
// Optionally pass the current view hash to avoid overwriting a newer view; on
// hash_conflict, we retry once without the hash. Requires `views:write` scope.
func PublishSlackHomeTab(ctx context.Context, userID string, hash string) error {
    botToken, err := getBotToken()
    if err != nil {
        return err
    }
    if strings.TrimSpace(userID) == "" {
        return fmt.Errorf("userID required")
    }
    api := slack.New(botToken)
    view, buildErr := BuildSlackHomeView(ctx)
    if buildErr != nil {
        // Log view generation errors immediately to ensure they are not lost if publishing fails.
        log.Printf("[Slack API] Home tab view generation was incomplete for user %s: %v", userID, buildErr)
    }

    req := slack.PublishViewContextRequest{UserID: userID, View: view}
    if h := strings.TrimSpace(hash); h != "" {
        req.Hash = &h
    }

    if _, err := api.PublishViewContext(ctx, req); err != nil {
        var slackErr *slack.SlackErrorResponse
        // Only retry if a hash was provided in the first place.
        if req.Hash != nil && errors.As(err, &slackErr) && slackErr.Err == slackErrorHashConflict {
            log.Printf("[Slack Home] hash_conflict with supplied hash, retrying without hash for user %s", userID)
            req.Hash = nil // Retry without the hash.
            if _, err2 := api.PublishViewContext(ctx, req); err2 != nil {
                return fmt.Errorf("views.publish failed after retry: %w", err2)
            }
        } else {
            return fmt.Errorf("views.publish failed: %w", err)
        }
    }
    log.Printf("[Slack API] Home tab published for user %s", userID)
    return nil
}
