-- Create the database
CREATE DATABASE secure_auth_db;

-- Create a new user with a password (for testing)
CREATE USER testuser WITH PASSWORD 'testpass';

-- Grant all privileges on the new database to your new user
GRANT ALL PRIVILEGES ON DATABASE secure_auth_db TO testuser;

-- Connect to the new database and grant schema permissions
\c secure_auth_db;
GRANT ALL ON SCHEMA public TO testuser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO testuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO testuser; 