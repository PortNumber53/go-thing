-- 0008_system_prompts.down.sql
-- Drop per-user System Prompts storage

DROP TRIGGER IF EXISTS set_timestamp_on_system_prompts ON system_prompts;
DROP FUNCTION IF EXISTS trg_set_timestamp();
DROP INDEX IF EXISTS ix_system_prompts_user_active;
DROP INDEX IF EXISTS ux_system_prompts_one_default_per_user;
DROP TABLE IF EXISTS system_prompts;
