-- 0004_bump_thread_on_message_insert.down.sql
-- Remove trigger and function that bump threads.updated_at on message insert

BEGIN;

DROP TRIGGER IF EXISTS trigger_update_thread_updated_at ON messages;
DROP FUNCTION IF EXISTS update_thread_updated_at();

COMMIT;
