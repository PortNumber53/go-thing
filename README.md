# Go Thing

A Go-based AI agent with web interface and Slack integration.

## Features

- Web-based chat interface using Gemini AI
- Slack webhook integration for bot responses
- RESTful API endpoints

## Setup

### Configuration

Create a config file at `$HOME/.config/go-thing/config` with the following JSON structure:

```json
{
  "GEMINI_API_KEY": "your-gemini-api-key",
  "SLACK_BOT_TOKEN": "xoxb-your-slack-bot-token"
}
```

### Slack Integration

To set up Slack integration:

1. Create a Slack app at https://api.slack.com/apps
2. Add the following bot token scopes:
   - `chat:write` - To send messages
   - `channels:read` - To read channel information
   - `im:read` - To read direct messages
   - `mpim:read` - To read group direct messages

3. Subscribe to bot events:
   - `message.im` - Direct messages to the bot
   - `message.mpim` - Group direct messages to the bot
   - `app_mention` - When the bot is mentioned in channels

4. Set the Request URL to: `https://your-domain.com/webhook/slack`

5. Install the app to your workspace and copy the Bot User OAuth Token to your config file.

## API Endpoints

- `GET /` - Web chat interface
- `POST /chat` - Send message to AI agent
- `POST /webhook/slack` - Slack webhook endpoint
- `POST /webhook` - Generic webhook endpoint (legacy)

## Running

```bash
go run agent.go
```

The server will start on `0.0.0.0:7865`.

## Usage

### Web Interface

Visit `http://localhost:7865` to use the web chat interface.

### Slack Bot

Once configured, the bot will:
- Respond to direct messages
- Process messages sent to it
- Use Gemini AI to generate responses
- Send responses back to the original channel

The bot automatically ignores its own messages to prevent infinite loops.