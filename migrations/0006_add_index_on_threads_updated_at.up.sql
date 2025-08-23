-- Add a descending index to speed up ORDER BY updated_at DESC on threads
CREATE INDEX IF NOT EXISTS idx_threads_updated_at_desc ON threads(updated_at DESC);
