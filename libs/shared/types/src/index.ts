// Core domain types for QAuth OAuth 2.1/OIDC server

// =============================================================================
// Base Types
// =============================================================================

export type UUID = string;
export type Timestamp = Date;
export type Email = string;

// =============================================================================
// User Types
// =============================================================================

export interface User {
  id: UUID;
  email: Email;
  passwordHash: string;
  emailVerified: boolean;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

export interface CreateUserInput {
  email: Email;
  password: string;
}

export interface UpdateUserInput {
  email?: Email;
  password?: string;
  emailVerified?: boolean;
}

// =============================================================================
// OAuth 2.1 Types
// =============================================================================

export interface OAuthClient {
  id: UUID;
  clientId: string;
  clientSecretHash: string;
  name: string;
  description?: string;
  redirectUris: string[];
  developerId: UUID;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

export interface CreateOAuthClientInput {
  name: string;
  description?: string;
  redirectUris: string[];
  developerId: UUID;
}

export interface UpdateOAuthClientInput {
  name?: string;
  description?: string;
  redirectUris?: string[];
}

// =============================================================================
// Authorization Code Types (OAuth 2.1 PKCE)
// =============================================================================

export type CodeChallengeMethod = 'S256';

export interface AuthorizationCode {
  id: UUID;
  code: string;
  clientId: string;
  userId: UUID;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
  scopes: string[];
  used: boolean;
  expiresAt: Timestamp;
  createdAt: Timestamp;
}

export interface CreateAuthorizationCodeInput {
  clientId: string;
  userId: UUID;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
  scopes: string[];
}

// =============================================================================
// Token Types
// =============================================================================

export interface AccessToken {
  id: UUID;
  token: string;
  userId: UUID;
  clientId: string;
  scopes: string[];
  expiresAt: Timestamp;
  createdAt: Timestamp;
}

export interface RefreshToken {
  id: UUID;
  token: string;
  userId: UUID;
  clientId: string;
  scopes: string[];
  revoked: boolean;
  expiresAt: Timestamp;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

export interface CreateTokenInput {
  userId: UUID;
  clientId: string;
  scopes: string[];
}

// =============================================================================
// Session Types
// =============================================================================

export interface Session {
  sessionId: string;
  userId: UUID;
  clientId: string;
  createdAt: Timestamp;
  lastAccessedAt: Timestamp;
  expiresAt: Timestamp;
}

export interface CreateSessionInput {
  userId: UUID;
  clientId: string;
}

// =============================================================================
// OAuth Flow Types
// =============================================================================

export interface AuthorizationRequest {
  responseType: 'code';
  clientId: string;
  redirectUri: string;
  state?: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
  scopes: string[];
}

export interface TokenRequest {
  grantType: 'authorization_code' | 'refresh_token';
  code?: string;
  redirectUri?: string;
  codeVerifier?: string;
  refreshToken?: string;
  clientId: string;
  clientSecret: string;
}

export interface TokenResponse {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  refreshToken?: string;
  scope: string;
}

// =============================================================================
// Error Types
// =============================================================================

export interface OAuthError {
  error: string;
  errorDescription?: string;
  errorUri?: string;
  state?: string;
}

export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'access_denied'
  | 'unsupported_response_type'
  | 'server_error'
  | 'temporarily_unavailable';

// =============================================================================
// API Response Types
// =============================================================================

export interface ApiError {
  error: {
    code: string;
    message: string;
    statusCode: number;
    timestamp: string;
    path: string;
  };
}

export interface HealthCheckResponse {
  status: 'ok' | 'error';
  timestamp: string;
  uptime: number;
  dependencies: {
    database: 'connected' | 'disconnected';
    redis: 'connected' | 'disconnected';
  };
  responseTime: number;
}
