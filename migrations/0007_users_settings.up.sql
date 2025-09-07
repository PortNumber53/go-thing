-- 0007_users_settings.up.sql
-- Add settings JSONB column to users for arbitrary key-value storage
ALTER TABLE users
ADD COLUMN IF NOT EXISTS settings JSONB NOT NULL DEFAULT '{}'::jsonb;
