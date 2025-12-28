/**
 * PostgreSQL Enum Types
 *
 * Centralized enum definitions for type safety and database constraints
 */

import { pgEnum } from 'drizzle-orm/pg-core';

/**
 * OAuth 2.1 Token Endpoint Authentication Methods
 * RFC 7591: OAuth 2.0 Dynamic Client Registration Protocol
 */
export const tokenEndpointAuthMethodEnum = pgEnum('token_endpoint_auth_method', [
  'client_secret_post', // Client credentials in POST body (default)
  'client_secret_basic', // Client credentials in HTTP Basic Auth header
  'private_key_jwt', // JWT signed with private key
  'none', // Public client (no authentication)
]);

/**
 * SSL Requirement Levels
 * Controls when SSL/TLS is required
 */
export const sslRequiredEnum = pgEnum('ssl_required', [
  'none', // SSL never required
  'external', // SSL required for external requests only
  'all', // SSL required for all requests
]);

/**
 * PKCE Code Challenge Methods
 * RFC 7636: Proof Key for Code Exchange by OAuth Public Clients
 *
 * Note: Only S256 is supported. Plain text method is insecure and not supported.
 */
export const codeChallengeMethodEnum = pgEnum('code_challenge_method', [
  'S256', // SHA256 (only supported method)
]);

/**
 * OAuth 2.1 Grant Types
 * RFC 8252: OAuth 2.0 for Native Apps
 *
 * Supported grant types:
 * - authorization_code: Authorization Code Flow (with PKCE)
 * - refresh_token: Refresh Token Flow
 * - client_credentials: Client Credentials Flow (for service-to-service)
 *
 * Note: OAuth 2.1 removed deprecated grant types (password, implicit)
 */
const GRANT_TYPES = [
  'authorization_code', // Authorization Code Flow (with PKCE)
  'refresh_token', // Refresh Token Flow
  'client_credentials', // Client Credentials Flow
] as const;

export const grantTypeEnum = pgEnum('grant_type', GRANT_TYPES);

export type GrantType = (typeof GRANT_TYPES)[number];

/**
 * OAuth 2.1 Response Types
 * Controls what type of response is returned from authorization endpoint
 */
const RESPONSE_TYPES = [
  'code', // Authorization Code (only supported in OAuth 2.1)
] as const;

export const responseTypeEnum = pgEnum('response_type', RESPONSE_TYPES);

export type ResponseType = (typeof RESPONSE_TYPES)[number];

/**
 * Audit Log Event Types
 * Categorizes audit events for filtering and analysis
 */
export const auditEventTypeEnum = pgEnum('audit_event_type', [
  'auth', // Authentication events (login, logout, register)
  'token', // Token events (issued, refreshed, revoked)
  'client', // Client events (created, updated, deleted)
  'security', // Security events (failed login, suspicious activity)
  'user', // User management events
  'realm', // Realm management events
]);
