# Changelog

## [2.1.7] - 2025-09-07

### Added
- Utility: new `utility/common.go` providing common helpers
  - `RunDockerExec(container, args, timeout)` to run commands inside the running Docker container with timeout and capture stdout/stderr
  - `EnsureSSHKeygenAvailable(container)` to check/install `openssh` (for `ssh-keygen`) within the container
  - `DummyBcryptCompare(password)` to normalize login timing between unknown user vs wrong password

### Changed
- Security: Enforce strict WebSocket origin checks for shell broker upgrades
  - Added `isAllowedWSOrigin` and wired it into `wsUpgrader.CheckOrigin` in `agent.go`
  - Configurable allowlist via `[default] ALLOWED_ORIGINS` (comma-separated origins). When unset, falls back to proxy-aware same-origin using `utility.IsSecure`
- Wiring updates:
  - `routes.RegisterAPIDockerRoutes` and `routes.RegisterAPISSHRoutes` now use `utility.EnsureSSHKeygenAvailable` and `utility.RunDockerExec`
  - `routes.RegisterLoginRoutes` now receives `utility.DummyBcryptCompare` for timing mitigation
- Refactor: centralize Postgres unique violation detection to `utility.IsUniqueViolation`
  - Added `utility/db_errors.go`
  - Removed duplicate helper from `agent.go` and `routes/signup_routes.go`; updated signup route to call the utility function
- Cleanup: removed a leftover local `isUniqueViolation` helper and unused imports from `agent.go` to complete the refactor
- GitHub: Restored AI follow-up logic for PR reviews from `gemini-code-assist[bot]` after routes extraction. The handler in `routes/github_routes.go` now detects `pull_request_review` and `pull_request_review_comment`, extracts the review/comment body and PR number, and asynchronously invokes `utility.GeminiAPIHandler` with a 3-minute timeout. The response is logged.
- Jira: Switch to thread-per-issue for webhook events. The handler in `routes/jira_routes.go` now uses `utility.GetOrCreateThreadByTitle("Jira: <ISSUE-KEY>")` so all events for the same issue accumulate in a single thread. Previously a new thread was created per event.
- Validation: Centralized email validation. Added `utility/validation.go` with `EmailRegex()`/`IsValidEmail()`. Updated `routes/signup_routes.go` to use it and removed the duplicate regex from `agent.go`.
- Slack: Restored error logging for App Home publishing in `routes/slack_routes.go` when `utility.PublishSlackHomeTab(...)` fails.
- Migrations: Moved CLI logic from `agent.go` (`runMigrateCLI`) to `utility/migrations.go` as exported `utility.RunMigrateCLI`. Updated `main()` to call the new function and removed the local implementation.

## [2.1.6] - 2025-09-07

### Changed
- Backend refactor: moved several helpers from `agent.go` into the `utility/` package for reuse and maintainability.
  - Password strength checker → `utility/password.go` (`IsStrongPassword`)
  - CSRF + HTTPS/HMAC helpers → `utility/security.go` (`NewCSRFToken`, `SetCSRFCookie`, `ValidateCSRF`, `IsSecure`, `IsSecureRequest`, `HMACSHA256`, `HMACEqual`)
  - Session helpers → `utility/session.go` (`SetSessionCookie`, `ClearSessionCookie`, `ParseSession`)
- Updated references across `agent.go` and tests (`agent_github_test.go`).
- Removed unused imports from `agent.go` after extraction.

### Routes extraction
- Moved HTTP handlers out of `agent.go` into `routes/`:
  - Slack webhook → `routes/slack_routes.go` (RegisterSlackRoutes)
  - GitHub webhook → `routes/github_routes.go` (RegisterGithubRoutes)
  - Signup → `routes/signup_routes.go` (RegisterSignupRoutes)
  - Login → `routes/login_routes.go` (RegisterLoginRoutes; injected limiter/session helpers)
  - Authenticated SSH key generation → `routes/api_ssh_routes.go` (RegisterAPISSHRoutes; injected Docker/ssh-keygen helpers)
  - Jira webhook → `routes/jira_routes.go` (RegisterJiraRoutes)
  - Shell session + WebSocket endpoints → `routes/shell_routes.go` (RegisterShellRoutes; reuses existing wsUpgrader for origin policy)
  - Authenticated Settings APIs (profile, password, docker) → `routes/api_settings_routes.go` (RegisterAPISettingsRoutes)
  - Docker SSH key endpoints (download/generate) → `routes/api_docker_routes.go` (RegisterAPIDockerRoutes)
  - Current user endpoint → `routes/me_routes.go` (RegisterMeRoutes)

### Jira tools refactor
- Extracted Jira create-issue helpers and executor from `tools/jira_issue_ops.go` into `tools/jira_issue_create_ops.go`.
- No behavior change; build passes.

## [2.1.5] - 2025-09-07

### Added
- Backend (`agent.go`): Docker container SSH key endpoints (authenticated):
  - `GET /api/docker/ssh-keys/download?which=public|private` streams `$HOME/.ssh/id_ed25519(.pub)` as a download.
  - `POST /api/docker/ssh-key` generates a new ed25519 keypair inside the container and returns the public key.
  - Both require session auth; POST is CSRF-protected.
- Frontend (`web/src/App.tsx`): Implemented `downloadDockerKey(which)` and wired the "Download public/private key" buttons to call the new endpoint and trigger download.

### Fixed
- Resolved Gin panic due to duplicate route registrations for `/api/docker/ssh-key` by removing duplicates and registering with inline `requireAuth()`.

## [2.1.4] - 2025-09-07

### Changed
- Frontend: Switched Settings URLs from hash fragments to path-based routes for deep-linking and consistency.
  - Old: `/account/settings#docker`
  - New: `/account/settings/docker`
- Implementation in `web/src/App.tsx`:
  - Parse tab from `window.location.pathname`.
  - Tab buttons navigate to `/account/settings`, `/account/settings/password`, `/account/settings/docker`.
  - Render Settings UI for any path starting with `/account/settings`.

## [2.1.3] - 2025-09-03

### Added
- Backend: Implemented authenticated Docker settings endpoints in `agent.go`:
  - `GET /api/settings/docker` to load per-user Docker config from `users.settings` JSONB
  - `POST /api/settings/docker` (CSRF-protected) to persist `{container,image,args,auto_remove}` using `jsonb_set`
- Frontend: Wired Docker Settings tab in `web/src/App.tsx` to load/save via the new endpoints with CSRF.

### Fixed
- Resolved 404 for `/api/settings/docker` and the missing `saveDocker` handler error in the Settings page.

## [2.1.2] - 2025-08-31

### Added
- Frontend: Added a tabbed UI to the Settings page with a new "Docker Settings" tab (placeholder form for container name, image, extra args, auto-remove). Save is disabled until backend APIs are added.

### Changed
- Frontend: Settings tabs moved to a fixed horizontal toolbar under the header for consistent navigation.
- Frontend: Increased contrast of the Settings toolbar (dark background, light text, clear active indicator) for readability.

## [2.1.1] - 2025-08-31

### Changed
- Standardized PostgreSQL config keys in `[postgres]` section to use `DB_` prefix.
  - Preferred keys: `DB_DSN` (optional), `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_SSLMODE`, `DB_MIGRATIONS_DIR`.
  - Backward compatibility preserved: legacy keys (`PG_DSN`, `HOST`, `PORT`, `USER`, `PASSWORD`, `DBNAME`, `SSLMODE`, `MIGRATIONS_DIR`) and environment variables (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`).
- Updated documentation (`README.md`) and sample config (`config.sample.ini`) to reflect new keys.

## [2.1.0] - 2025-08-09

### Added
- shell_exec tool to execute shell commands within the configured CHROOT_DIR, with:
  - CHROOT confinement identical to read_file/write_file (path resolution with filepath.Rel checks)
  - Optional workdir (must be inside CHROOT)
  - Timeout control via --timeout_sec (default 60s, max 600s)
  - Returns stdout, stderr, and exit_code for robust scripting

### Notes
- Tool is auto-discovered via the embedded tool server and available to the agent’s tool loop and /tool endpoint.
- Command is executed using /bin/sh -lc to support pipelines and shell features.

### Security/Sandboxing
- Added Docker sandbox execution for shell_exec: commands run inside an Arch Linux container with CHROOT_DIR mounted at /app.
- Agent startup ensures the container exists and is running.
- Graceful shutdown now best-effort stops the container and optionally removes it when DOCKER_AUTO_REMOVE=true in config.
- New helpers in tools/docker_start.go: StopDockerContainer, RemoveDockerContainer(force), and internal dockerStop.

## 2025-08-09

### PostgreSQL Integration
- Internal PostgreSQL support:
  - Added `db/postgres.go` for INI-driven connection via `pgx` stdlib.
  - Added `db/migrate.go` simple file-based migrations (tracked by `schema_migrations`).
  - `agent.go` initializes DB and runs migrations at startup if `[postgres]` section is present.
  - Added `config.sample.ini` and example migration `migrations/0001_init.sql`.
  - Updated README with configuration notes.
- Added migration CLI in `agent.go` with commands: `migrate up [--step N]`, `migrate down --step N`, and `migrate status`.
- Enhanced migration engine to support `.up.sql`/`.down.sql` files, step-wise up/down, and status reporting.

### Conversation storage
- Added migrations to persist chats:
  - `migrations/0002_conversations_threads_messages.up.sql` creates `threads` and `messages` with FKs and indexes.
  - `migrations/0002_conversations_threads_messages.down.sql` drops `messages` then `threads`.
  - Indexes: `messages(thread_id)`, `messages(created_at)`.
  - `migrations/0003_threads_updated_at_trigger.up.sql` adds a PL/pgSQL trigger to refresh `threads.updated_at` on UPDATE (with matching `.down.sql`).
  - `migrations/0004_bump_thread_on_message_insert.up.sql` updates `threads.updated_at` automatically when a new message is inserted (with matching `.down.sql`).

### Docker Sandbox Lifecycle
- Added graceful stop/remove on shutdown based on `DOCKER_AUTO_REMOVE`.
- New helpers in `tools/docker_start.go`: `StopDockerContainer`, `RemoveDockerContainer(force)`, and internal `dockerStop`.

## [2.0.0] - 2025-07-27

### Changed
- **Consolidated Architecture**: Moved tool system from separate server to integrated within main agent
- **Single Port**: Agent now only uses port 7866 (removed dependency on port 8080)
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