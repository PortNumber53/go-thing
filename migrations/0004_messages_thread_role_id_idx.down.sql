-- 0004_messages_thread_role_id_idx.down.sql
-- Drop composite index added in 0004 up migration

BEGIN;

DROP INDEX IF EXISTS idx_messages_thread_role_id_desc;

COMMIT;
