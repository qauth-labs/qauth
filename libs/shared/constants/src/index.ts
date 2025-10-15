// Constants for QAuth OAuth 2.1/OIDC server

// =============================================================================
// Token Expiration Times (in seconds)
// =============================================================================

/**
 * Access token lifetime: 15 minutes
 * Short-lived for security - minimizes exposure if compromised
 */
export const ACCESS_TOKEN_LIFETIME = 15 * 60; // 900 seconds

/**
 * Refresh token lifetime: 7 days
 * Balance between security and user experience
 */
export const REFRESH_TOKEN_LIFETIME = 7 * 24 * 60 * 60; // 604800 seconds

/**
 * Authorization code lifetime: 10 minutes
 * OAuth 2.1 recommendation for PKCE flows
 */
export const AUTHORIZATION_CODE_LIFETIME = 10 * 60; // 600 seconds

/**
 * Session lifetime: 7 days
 * Matches refresh token lifetime for consistency
 */
export const SESSION_LIFETIME = REFRESH_TOKEN_LIFETIME;

// =============================================================================
// OAuth 2.1 Configuration
// =============================================================================

/**
 * Supported OAuth 2.1 response types
 */
export const SUPPORTED_RESPONSE_TYPES = ['code'] as const;

/**
 * Supported OAuth 2.1 grant types
 */
export const SUPPORTED_GRANT_TYPES = ['authorization_code', 'refresh_token'] as const;

/**
 * Supported PKCE code challenge methods
 * OAuth 2.1 mandates S256 (SHA256) for public clients
 */
export const SUPPORTED_CODE_CHALLENGE_METHODS = ['S256'] as const;

/**
 * Default OAuth 2.1 scopes
 */
export const DEFAULT_SCOPES = ['openid', 'profile', 'email'] as const;

/**
 * All supported OAuth 2.1 scopes
 */
export const SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'offline_access'] as const;

// =============================================================================
// ID Generation Configuration
// =============================================================================

/**
 * Length of authorization codes
 * Must be cryptographically secure and URL-safe
 */
export const AUTHORIZATION_CODE_LENGTH = 43; // nanoid default

/**
 * Length of access tokens
 * Must be cryptographically secure
 */
export const ACCESS_TOKEN_LENGTH = 64;

/**
 * Length of refresh tokens
 * Must be cryptographically secure
 */
export const REFRESH_TOKEN_LENGTH = 64;

/**
 * Length of session IDs
 * Must be cryptographically secure
 */
export const SESSION_ID_LENGTH = 32;

/**
 * Custom alphabet for OAuth codes (alphanumeric only)
 * URL-safe and readable
 */
export const OAUTH_CODE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/**
 * Default alphabet for tokens (URL-safe)
 * Includes hyphens and underscores for better entropy
 */
export const TOKEN_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// =============================================================================
// Database Configuration
// =============================================================================

/**
 * Database connection pool settings
 */
export const DB_POOL_CONFIG = {
  min: 2,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
} as const;

/**
 * Database query timeout (in milliseconds)
 */
export const DB_QUERY_TIMEOUT = 10000;

// =============================================================================
// Redis Configuration
// =============================================================================

/**
 * Redis connection timeout (in milliseconds)
 */
export const REDIS_CONNECTION_TIMEOUT = 5000;

/**
 * Redis command timeout (in milliseconds)
 */
export const REDIS_COMMAND_TIMEOUT = 10000;

/**
 * Redis retry configuration
 */
export const REDIS_RETRY_CONFIG = {
  retries: 3,
  backoff: 'exponential' as const,
  maxDelay: 1000,
} as const;

// =============================================================================
// Security Configuration
// =============================================================================

/**
 * Password hashing configuration for Argon2id
 * OWASP recommended parameters for 2024
 */
export const ARGON2_CONFIG = {
  memory: 65536, // 64 MB
  time: 3, // 3 iterations
  parallelism: 1,
  hashLength: 32,
} as const;

/**
 * JWT configuration
 */
export const JWT_CONFIG = {
  algorithm: 'HS256' as const,
  issuer: 'qauth',
  audience: 'qauth-api',
} as const;

// =============================================================================
// HTTP Configuration
// =============================================================================

/**
 * Default server port
 */
export const DEFAULT_PORT = 3000;

/**
 * CORS configuration
 */
export const CORS_CONFIG = {
  origin: true, // Allow all origins in development
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
} as const;

/**
 * Security headers configuration
 */
export const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
} as const;

// =============================================================================
// Logging Configuration
// =============================================================================

/**
 * Log levels
 */
export const LOG_LEVELS = {
  fatal: 60,
  error: 50,
  warn: 40,
  info: 30,
  debug: 20,
  trace: 10,
} as const;

/**
 * Default log level
 */
export const DEFAULT_LOG_LEVEL = 'info';

/**
 * Fields to redact in logs (sensitive information)
 */
export const REDACTED_FIELDS = [
  'password',
  'passwordHash',
  'clientSecret',
  'clientSecretHash',
  'authorization',
  'cookie',
  'token',
  'code',
  'codeVerifier',
  'codeChallenge',
] as const;

// =============================================================================
// Rate Limiting Configuration
// =============================================================================

/**
 * Rate limiting for authentication endpoints
 */
export const RATE_LIMIT_CONFIG = {
  login: {
    max: 5, // 5 attempts
    timeWindow: 15 * 60 * 1000, // 15 minutes
  },
  register: {
    max: 3, // 3 attempts
    timeWindow: 60 * 60 * 1000, // 1 hour
  },
  passwordReset: {
    max: 3, // 3 attempts
    timeWindow: 60 * 60 * 1000, // 1 hour
  },
} as const;
