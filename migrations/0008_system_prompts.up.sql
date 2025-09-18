-- 0008_system_prompts.up.sql
-- Create per-user System Prompts storage

CREATE TABLE IF NOT EXISTS system_prompts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    preferred_llms TEXT[] NOT NULL DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT FALSE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT system_prompts_default_requires_active CHECK (NOT is_default OR active)
);

-- Ensure only one default per user (at most)
CREATE UNIQUE INDEX IF NOT EXISTS ux_system_prompts_one_default_per_user
    ON system_prompts(user_id)
    WHERE is_default = TRUE;

-- Index for quick lookups by user and activity
CREATE INDEX IF NOT EXISTS ix_system_prompts_user_active
    ON system_prompts(user_id, active);

-- Trigger to bump updated_at on row updates
CREATE OR REPLACE FUNCTION trg_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_timestamp_on_system_prompts ON system_prompts;
CREATE TRIGGER set_timestamp_on_system_prompts
BEFORE UPDATE ON system_prompts
FOR EACH ROW
EXECUTE PROCEDURE trg_set_timestamp();
