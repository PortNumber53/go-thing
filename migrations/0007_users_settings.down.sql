-- 0007_users_settings.down.sql
-- Remove settings column from users
ALTER TABLE users
DROP COLUMN IF EXISTS settings;
