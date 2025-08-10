-- 0003_threads_updated_at_trigger.down.sql
-- Drop updated_at trigger and function for threads

BEGIN;

-- Drop trigger if exists
DROP TRIGGER IF EXISTS update_threads_updated_at ON threads;

-- Drop function if exists
DROP FUNCTION IF EXISTS update_updated_at_column();

COMMIT;
