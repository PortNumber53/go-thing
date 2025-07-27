# Agent Behavior Test Cases

## Before (Old Behavior)
```
User: list the tools you have
Agent: I can list the tools I have! You can use the /tools command to see a list of all available tools.
```

## After (New Behavior)
```
User: list the tools you have
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

## Additional Test Cases

### Disk Space Queries
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

### Natural Language Variations
```
User: Check disk usage
User: Show me storage information
User: What's my free space?
User: Check my disk space
```
All should trigger the disk_space tool automatically.

### Tool Discovery
```
User: What tools do you have?
User: What can you do?
User: Show me your capabilities
User: List available tools
```
All should trigger the /tools command automatically.

## Key Improvements

1. **Proactive Execution**: Agent executes tools instead of explaining how to use them
2. **Natural Language Understanding**: Recognizes various ways users might ask for the same information
3. **Immediate Results**: Users get actual data instead of instructions
4. **Better UX**: No need to learn specific command syntax 