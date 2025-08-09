#!/bin/bash

echo "Starting Go-Thing AI Agent with Integrated Tool System"
echo "====================================================="

# Check if config file exists
if [ ! -f "$HOME/.config/go-thing/config.ini" ]; then
    echo "Error: Config file not found at $HOME/.config/go-thing/config.ini"
    echo "Please create the config file with your API keys and settings."
    exit 1
fi

# Function to cleanup background processes
cleanup() {
    echo -e "\nShutting down server..."
    kill $AGENT_PID 2>/dev/null
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start main agent server in background
echo "Starting agent server on port 7866..."
go run agent.go &
AGENT_PID=$!

# Wait a moment for agent server to start
sleep 2

# Check if agent server is running
if ! curl -s http://localhost:7866/ >/dev/null 2>&1; then
    echo "Error: Agent server failed to start"
    kill $AGENT_PID 2>/dev/null
    exit 1
fi

echo "✓ Agent server started successfully"
echo ""
echo "Services are running:"
echo "  - Agent Server: http://localhost:7866"
echo "  - Web Chat Interface: http://localhost:7866"
echo "  - Tool System: Integrated (no separate server needed)"
echo ""
echo "Press Ctrl+C to stop the server"

# Wait for user to stop
wait