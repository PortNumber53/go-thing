-- 0004_bump_thread_on_message_insert.up.sql
-- Update threads.updated_at whenever a new message is inserted for that thread

BEGIN;

-- Function to bump the parent thread's updated_at on new messages
CREATE OR REPLACE FUNCTION update_thread_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE threads
    SET updated_at = NOW()
    WHERE id = NEW.thread_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger: after insert on messages
CREATE TRIGGER trigger_update_thread_updated_at
AFTER INSERT ON messages
FOR EACH ROW
EXECUTE FUNCTION update_thread_updated_at();

COMMIT;
