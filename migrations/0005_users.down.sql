-- 0005_users.down.sql
-- Drop users table

DROP INDEX IF EXISTS idx_users_username;
DROP TABLE IF EXISTS users;
