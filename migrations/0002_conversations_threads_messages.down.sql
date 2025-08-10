-- 0002_conversations_threads_messages.down.sql
-- Drop messages and threads tables (reverse order)

BEGIN;

DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS threads;

COMMIT;
