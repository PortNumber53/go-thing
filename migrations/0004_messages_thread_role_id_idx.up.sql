-- 0004_messages_thread_role_id_idx.up.sql
-- Add composite index to speed up lookups of the latest assistant message by thread

BEGIN;

CREATE INDEX IF NOT EXISTS idx_messages_thread_role_id_desc
ON messages (thread_id, role, id DESC);

COMMIT;
