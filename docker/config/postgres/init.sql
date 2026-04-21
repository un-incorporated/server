-- Unincorporated Server — initial database setup
-- This runs once when the Postgres container is first created.

-- Create app user (passthrough, no logging)
CREATE USER app_user WITH PASSWORD 'change-me';

-- Create admin user (logged by proxy)
CREATE USER admin WITH PASSWORD 'change-me' SUPERUSER;

-- Grant app_user access
GRANT ALL PRIVILEGES ON DATABASE mydb TO app_user;
