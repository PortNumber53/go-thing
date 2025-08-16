package utility

import (
	"fmt"
	"log"
	"strings"

	"github.com/slack-go/slack"
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
	blocks := slack.Blocks{BlockSet: []slack.Block{header, intro, divider, tips}}
	return slack.HomeTabViewRequest{Type: slack.VTHomeTab, Blocks: blocks}
}

// PublishSlackHomeTab publishes the Home tab for the given user using the bot token.
// Requires the Slack app to have the `views:write` scope.
func PublishSlackHomeTab(userID string) error {
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
	if _, err := api.PublishView(userID, view, ""); err != nil {
		return fmt.Errorf("views.publish failed: %w", err)
	}
	log.Printf("[Slack API] Home tab published for user %s", userID)
	return nil
}
