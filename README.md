# Go-Thing AI Agent

An AI agent with tool calling capabilities, built with Go and Gemini API.

## Features

- **AI Chat Interface**: Web-based chat interface with Markdown support
- **Slack Integration**: Webhook support for Slack integration
- **Tool System**: Extensible tool calling system with JSON-based communication
- **Available Tools**:
  - `disk_space`: Get disk space information for any path
  - `write_file`: Write files to configured directory

## Tool System

The agent has access to a powerful tool system that allows it to interact with the host system safely.

### Tool Commands

- `/tools` - List all available tools
- `/tool <tool_name> --help` - Get help for a specific tool
- `/tool <tool_name> [--param value]` - Execute a tool with parameters

### Available Tools

#### disk_space
Get disk space information for a specified path.

**Usage:**
```
/tool disk_space                    # Check current directory
/tool disk_space --path /home       # Check /home directory
/tool disk_space --help             # Show help
```

**Output:**
```json
{
  "path": "/home",
  "total_bytes": 107374182400,
  "free_bytes": 53687091200,
  "used_bytes": 53687091200,
  "total_gb": 100.0,
  "free_gb": 50.0,
  "used_gb": 50.0,
  "usage_percent": 50.0
}
```

#### write_file
Write content to a file in the configured write directory.

**Usage:**
```
/tool write_file --path test.txt --content "Hello World"
/tool write_file --help
```

**Requirements:**
- Must be configured with `CHROOT_DIR` in config file
- File path must be within the configured chroot directory

## Setup

1. **Configuration**: Create `~/.config/go-thing/config` with:
   ```ini
   [default]
   GEMINI_API_KEY=your_gemini_api_key_here
   SLACK_BOT_TOKEN=xoxb-your_slack_bot_token_here
   CHROOT_DIR=/home/username/writable_directory
   ```

2. **Quick Start** (Recommended):
   ```bash
   ./start.sh
   ```

3. **Manual Start**:
   ```bash
   go run agent.go
   ```

## Architecture

- **Agent Server** (`agent.go`): Main web server with integrated tool system, chat interface, and Slack integration
- **Integrated Tools**: All tools run directly within the agent process
- **JSON Communication**: All tool communication uses JSON format
- **Security**: File operations restricted to configured directories

## API Endpoints

### Agent Server (Port 7866)
- `GET /` - JSON health/info endpoint (the chat UI is now a separate React/Vite SPA under `web/`)
- `POST /chat` - Chat API endpoint
- `POST /webhook/slack` - Slack webhook endpoint
- **Integrated Tool System**: All tools run directly within the agent process

## Example Usage

The agent is proactive and will automatically execute tools when you ask for information they can provide:

1. **Check disk space**:
   ```
   User: How much disk space do I have?
   Agent: Let me check your disk space for you.

   Tool disk_space executed successfully:
   ```json
   {
     "path": "/home/username",
     "total_bytes": 107374182400,
     "free_bytes": 53687091200,
     "used_bytes": 53687091200,
     "total_gb": 100.0,
     "free_gb": 50.0,
     "used_gb": 50.0,
     "usage_percent": 50.0
   }
   ```
   ```

2. **List available tools**:
   ```
   User: What tools do you have?
   Agent: Here are the tools I have available:

   Available tools:

   **disk_space** - Get disk space information for a specified path
     Parameters:
       - path: Path to check disk space for (optional, defaults to current directory)

   **write_file** - Write content to a file in the configured write directory
     Parameters:
       - path: Path to the file to write
       - content: Content to write to the file
   ```

3. **Natural language queries**:
   ```
   User: Check my disk usage
   User: Show me available tools
   User: What can you do?
   ```
   The agent will automatically execute the appropriate tools and show results.

## Security Considerations

- File operations are restricted to configured directories
- Tool server runs on localhost only
- All tool inputs are validated and sanitized
- JSON communication prevents command injection

## Testing

Test the tool system:

```bash
# Start the agent
./start.sh

# Then test the tools through the web interface
# Visit http://localhost:7866 and try:
# - "How much disk space do I have?"
# - "What tools do you have?"
# - "Check disk usage"
```

## Development

To add new tools:

1. Add tool definition to `tools` map in `toolserver.go`
2. Implement tool execution function
3. Add case to tool execution switch statement
4. Update documentation

The tool system is designed to be easily extensible while maintaining security and consistency.