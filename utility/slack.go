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
