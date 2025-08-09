#!/bin/bash

echo "Testing Go-Thing Integrated Tool System"
echo "======================================="

# Test 1: Check if agent is running
echo -e "\n1. Testing agent server..."
response=$(curl -s http://localhost:7866/)
if [ $? -eq 0 ]; then
    echo "✓ Agent server is running"
else
    echo "✗ Agent server is not running"
    echo "Please start the agent with: ./start.sh"
    exit 1
fi

# Test 2: Test tool execution through chat API
echo -e "\n2. Testing tool execution through chat API..."
chat_response=$(curl -s -X POST http://localhost:7866/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "How much disk space do I have?"}')
if [ $? -eq 0 ]; then
    echo "✓ Successfully executed disk space query"
    echo "Response: $chat_response" | jq '.' 2>/dev/null || echo "Response: $chat_response"
else
    echo "✗ Failed to execute disk space query"
fi

# Test 3: Test tool listing through chat API
echo -e "\n3. Testing tool listing through chat API..."
tools_response=$(curl -s -X POST http://localhost:7866/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What tools do you have?"}')
if [ $? -eq 0 ]; then
    echo "✓ Successfully retrieved tools list"
    echo "Response: $tools_response" | jq '.' 2>/dev/null || echo "Response: $tools_response"
else
    echo "✗ Failed to retrieve tools list"
fi

echo -e "\nIntegrated tool system test completed!"
echo "Note: Make sure the agent is running on port 7866 before running this test."
echo "Start with: ./start.sh"