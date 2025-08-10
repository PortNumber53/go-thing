-- 0003_threads_updated_at_trigger.up.sql
-- Ensure updated_at is refreshed on UPDATE for threads

BEGIN;

-- Function to update the updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for the threads table
CREATE TRIGGER update_threads_updated_at
BEFORE UPDATE ON threads
FOR EACH ROW
EXECUTE PROCEDURE update_updated_at_column();

COMMIT;
