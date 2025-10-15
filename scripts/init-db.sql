-- Database initialization script for QAuth OAuth 2.1/OIDC Server
-- Creates necessary extensions and initial configuration

-- =============================================================================
-- Extensions
-- =============================================================================

-- Enable UUID extension for generating UUIDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pgcrypto for cryptographic functions (if needed)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- Database Configuration
-- =============================================================================

-- Set timezone to UTC
SET timezone = 'UTC';

-- =============================================================================
-- Initial Data (if needed)
-- =============================================================================

-- Note: Tables will be created by Drizzle migrations
-- This script only sets up extensions and basic configuration

-- =============================================================================
-- Permissions
-- =============================================================================

-- Ensure the qauth user has necessary permissions
GRANT ALL PRIVILEGES ON DATABASE qauth_dev TO qauth;
GRANT ALL PRIVILEGES ON SCHEMA public TO qauth;
