/**
 * Test setup and teardown utilities
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL =
  process.env.TEST_DATABASE_URL || 'postgresql://qauth:password@localhost:5432/qauth_test';
process.env.REDIS_URL = process.env.TEST_REDIS_URL || 'redis://localhost:6379/1';
process.env.DEFAULT_REALM_NAME = 'test-realm';
process.env.REGISTRATION_RATE_LIMIT = '10';
process.env.REGISTRATION_RATE_WINDOW = '3600';

// Global test timeout
jest.setTimeout(30000);
