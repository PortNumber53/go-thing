package utility

import (
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
	slackDateFallbackFormat = "2006-01-02 15:04:05"
)

// SendSlackResponse posts a message to a Slack channel using the bot token
// configured in the INI config (SLACK_BOT_TOKEN in [default]).
func SendSlackResponse(channel, message string) error {
	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}
	botToken := cfg["SLACK_BOT_TOKEN"]
	if strings.TrimSpace(botToken) == "" {
		return fmt.Errorf("SLACK_BOT_TOKEN missing in config")
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
func fetchRecentThreads(limit int) ([]threadSummary, error) {
	if limit <= 0 {
		limit = defaultRecentThreadsLimit
	}
	dbc := db.Get()
	if dbc == nil {
		return nil, fmt.Errorf("db not initialized")
	}
	rows, err := dbc.Query(`SELECT id, COALESCE(title, ''), updated_at FROM threads ORDER BY updated_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying recent threads: %w", err)
	}
	defer rows.Close()
	var out []threadSummary
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
func BuildSlackHomeView() slack.HomeTabViewRequest {
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
	if threads, err := fetchRecentThreads(defaultRecentThreadsLimit); err != nil {
		log.Printf("[Slack Home] fetchRecentThreads failed: %v", err)
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
			// Escape characters for Slack mrkdwn to prevent formatting issues.
title = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(title)
			// Example line: • #12 — Project kickoff (2025-08-22 18:30 UTC)
			fmt.Fprintf(&b, "• #%d — %s (updated <!date^%d^{date_short} {time}|%s>)\n", t.ID, title, t.UpdatedAt.Unix(), t.UpdatedAt.UTC().Format(slackDateFallbackFormat)+" UTC")
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
	return slack.HomeTabViewRequest{Type: slack.VTHomeTab, Blocks: blocks}
}

// PublishSlackHomeTab publishes the Home tab for the given user using the bot token.
// Optionally pass the current view hash to avoid overwriting a newer view; on
// hash_conflict, we retry once without the hash. Requires `views:write` scope.
func PublishSlackHomeTab(userID string, hash string) error {
	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}
	botToken := cfg["SLACK_BOT_TOKEN"]
	if strings.TrimSpace(botToken) == "" {
		return fmt.Errorf("SLACK_BOT_TOKEN missing in config")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("userID required")
	}
	api := slack.New(botToken)
	view := BuildSlackHomeView()
	if _, err := api.PublishView(userID, view, hash); err != nil {
		var slackErr *slack.SlackErrorResponse
		if errors.As(err, &slackErr) && slackErr.Err == slackErrorHashConflict && strings.TrimSpace(hash) != "" {
			log.Printf("[Slack Home] hash_conflict with supplied hash, retrying without hash for user %s", userID)
			if _, err2 := api.PublishView(userID, view, ""); err2 != nil {
				return fmt.Errorf("views.publish failed after retry: %w", err2)
			}
		} else {
			return fmt.Errorf("views.publish failed: %w", err)
		}
	}
	log.Printf("[Slack API] Home tab published for user %s", userID)
	return nil
}
