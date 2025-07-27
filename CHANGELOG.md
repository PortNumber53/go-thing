# Changelog

## [2.0.0] - 2025-07-27

### Changed
- **Consolidated Architecture**: Moved tool system from separate server to integrated within main agent
- **Single Port**: Agent now only uses port 7865 (removed dependency on port 8080)
- **Simplified Deployment**: Only one server process needed instead of two

### Added
- **Integrated Tool System**: All tools now run directly within the agent process
- **Proactive Tool Execution**: Agent automatically executes tools based on user queries
- **Natural Language Understanding**: Recognizes various ways users ask for the same information
- **Disk Space Tool**: Get detailed disk space information for any path
- **Enhanced System Prompt**: Agent understands it should execute tools, not just explain them

### Removed
- **Separate Tool Server**: No longer need `tools/toolserver.go` running on port 8080
- **HTTP Tool Communication**: Tools now execute directly without HTTP overhead
- **Complex Startup Process**: Simplified to single command startup

### Technical Details
- Tools are now defined as Go functions within `agent.go`
- Tool execution happens synchronously within the same process
- All tool functionality preserved (disk_space, write_file)
- JSON response format maintained for consistency
- Security features preserved (path validation, write directory restrictions)

### Migration Notes
- Update startup scripts to use `./start.sh` (single server)
- Remove any references to port 8080
- Tool functionality remains the same from user perspective
- Configuration file format unchanged 