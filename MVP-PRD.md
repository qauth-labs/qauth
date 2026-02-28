# QAuth - MVP Product Requirements Document (PRD)

> **Version**: 1.5
> **Last Updated**: 2026-01-15
> **Author**: Muhammed Taha Ayan
> **Status**: Phase 1 - Core Authentication (Docker infrastructure ready)

## Executive Summary

QAuth is a post-quantum ready, headless-first identity platform designed as a developer-friendly alternative to Keycloak. This document outlines the Minimum Viable Product (MVP) roadmap for a solo developer.

**Core Philosophy**: Ship working features incrementally. Each phase should be production-ready before moving to the next.

---

## 🎯 MVP Vision

**Goal**: Create a working OAuth 2.1/OIDC authentication server that developers can use to authenticate users in their applications.

**Success Criteria**:

- A developer can register an OAuth client
- A developer can implement login/signup using QAuth
- Users can authenticate with email/password
- JWT tokens are issued and validated correctly
- Basic security practices are implemented

**Non-Goals for MVP**:

- Social login (Google, GitHub)
- Multi-factor authentication (MFA)
- WebAuthn/Passkeys
- SAML support
- Custom domains
- Advanced RBAC (basic roles supported)
- Microservices architecture
- GraphQL API

**Note**: Multi-tenancy is included in MVP via realms table for data isolation, but advanced multi-tenancy features (custom domains, tenant management UI) are not included.

---

## 📋 Phase Breakdown

### Phase 0: Foundation Setup (COMPLETED)

**Timeline**: 1-2 weeks
**Status**: Completed

**Objective**: Set up the development environment and project structure.

#### Tasks

- [x] Initialize Nx monorepo
- [x] Configure pnpm workspace
- [x] Set up ESLint + Prettier
- [x] Configure Husky + commitlint
- [x] Create project documentation
- [x] Set up database schema (PostgreSQL + Drizzle ORM)
- [x] Set up Redis connection
- [x] Create base Fastify server structure
- [x] Set up environment configuration
- [x] Set up testing infrastructure (@qauth/shared-testing)
- [x] Create Fastify plugins (db, cache, password, email)

#### Deliverables

- ✅ Working Nx workspace
- ✅ Code quality tools configured
- ✅ Database schema defined
- ✅ Basic server running
- ✅ Testing infrastructure ready
- ✅ Fastify plugin architecture established

---

### Phase 1: Core Authentication (CURRENT)

**Timeline**: 6-8 weeks
**Status**: Near Completion (Missing 1.7)

**Objective**: Implement basic email/password authentication with JWT tokens.

---

#### 1.1 Database Schema & Models

**Tasks**:

- [x] Design database schema
  - Realms table (multi-tenancy support)
  - Users table (id, realm_id, email, password_hash, email_verified, created_at, updated_at)
  - Sessions table (id, user_id, oauth_client_id, expires_at, created_at)
  - OAuth clients table (id, realm_id, client_id, client_secret_hash, name, redirect_uris, grant_types, response_types, created_at)
  - Authorization codes table (id, code, oauth_client_id, user_id, redirect_uri, code_challenge, code_challenge_method, expires_at, used)
  - Refresh tokens table (id, token_hash, user_id, oauth_client_id, expires_at, revoked)
  - Email verification tokens table (id, token, user_id, expires_at, used)
  - Audit logs table (id, user_id, oauth_client_id, event, event_type, success, ip_address, created_at)
  - Roles table (id, realm_id, name, oauth_client_id, enabled) - Phase 5+
  - User roles table (user_id, role_id) - Phase 5+
- [x] Set up Drizzle ORM schemas
- [x] Create initial database migration (0000_glamorous_valkyrie.sql)
- [x] Implement repository pattern with BaseRepository interface
- [x] Create repositories for users, realms, audit logs, and email verification tokens
- [x] Add centralized error handling library (@qauth/shared-errors)

**Acceptance Criteria**:

- ✅ Database schema is normalized
- ✅ Migrations can be run and rolled back
- ✅ Basic queries work

**Estimated Time**: 1 week

---

#### 1.2 User Registration & Password Hashing

**Tasks**:

- [x] Implement user registration endpoint (`POST /auth/register`)
- [x] Integrate @node-rs/argon2 for password hashing (@qauth/server-password)
- [x] Email validation schema (@qauth/shared-validation)
- [x] Password strength validation (zxcvbn) (@qauth/shared-validation)
- [x] Fastify password plugin (@qauth/fastify-plugin-password)
- [x] Check for duplicate emails (database unique constraint)
- [x] Rate limiting on registration

**API Endpoint**:

```typescript
POST /auth/register
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

Response:
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_verified": false,
    "created_at": "2025-10-21T..."
  }
}
```

**Password Hashing**:

```typescript
import { hash, verify } from '@node-rs/argon2';

// Hash password
const hashed = await hash(password, {
  memoryCost: 65536, // 64MB
  timeCost: 3,
  parallelism: 4,
});

// Verify password
const valid = await verify(hashed, password);
```

**Acceptance Criteria**:

- ✅ Users can register with email/password
- ✅ Passwords are hashed with Argon2id
- ✅ Duplicate emails are rejected
- ✅ Weak passwords are rejected
- ✅ Rate limiting prevents abuse

**Estimated Time**: 1 week

---

#### 1.3 Email Verification

**Tasks**:

- [x] Generate verification token (32 bytes, hex encoded)
- [x] Store token hash in database (TTL: 24 hours)
- [x] Email infrastructure ready (Resend, SMTP, Mock providers)
- [x] React Email templates for verification emails
- [x] Configure email provider from environment variables
- [x] Send verification email on registration
- [x] Implement verify endpoint (`GET /auth/verify?token=...`)
- [x] Mark email as verified
- [x] Handle expired tokens

**API Endpoints**:

```typescript
POST /auth/resend-verification
{
  "email": "user@example.com"
}

Response:
{
  "message": "Verification email sent"
}

---

GET /auth/verify?token=abc123

Response:
{
  "message": "Email verified successfully"
}
```

**Acceptance Criteria**:

- ✅ Email provider can be configured via environment variables (mock, resend, smtp)
- ✅ Provider-specific configuration validated at startup
- ✅ Verification email is sent on registration
- ✅ Valid tokens verify the email
- ✅ Expired tokens are rejected
- ✅ Used tokens cannot be reused
- ✅ Users can request new verification email

**Estimated Time**: 3-4 days

---

#### 1.4 User Login & JWT Tokens

**Tasks**:

- [x] Implement login endpoint (`POST /auth/login`)
- [x] Verify password using @node-rs/argon2
- [x] Generate JWT access tokens (Ed25519)
- [x] Generate refresh tokens
- [x] Store session in Redis
- [x] Implement JWT signing with jose library

**API Endpoint**:

```typescript
POST /auth/login
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

Response:
{
  "access_token": "eyJhbGc...",
  "refresh_token": "refresh_token_here",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

**JWT Implementation**:

```typescript
import { SignJWT, generateKeyPair } from 'jose';

// Generate EdDSA key pair
const { publicKey, privateKey } = await generateKeyPair('EdDSA');

// Sign JWT
const jwt = await new SignJWT({
  sub: userId,
  email: user.email,
})
  .setProtectedHeader({ alg: 'EdDSA' })
  .setIssuedAt()
  .setExpirationTime('15m')
  .sign(privateKey);
```

**Acceptance Criteria**:

- ✅ Users can login with correct credentials
- ✅ Invalid credentials are rejected
- ✅ Unverified emails cannot login (optional for MVP)
- ✅ JWT tokens are properly signed with EdDSA
- ✅ Tokens have correct expiration (15 minutes)
- ✅ Refresh tokens are stored securely

**Estimated Time**: 1 week

---

#### 1.5 Token Refresh & Logout

**Tasks**:

- [x] Implement token refresh endpoint (`POST /auth/refresh`)
- [x] Validate refresh token
- [x] Issue new access token
- [x] Implement logout endpoint (`POST /auth/logout`)
- [x] Revoke refresh token on logout
- [x] Clear session from Redis

**API Endpoints**:

```typescript
POST /auth/refresh
{
  "refresh_token": "refresh_token_here"
}

Response:
{
  "access_token": "eyJhbGc...",
  "expires_in": 900
}

---

POST /auth/logout
Authorization: Bearer eyJhbGc...

Response:
{
  "message": "Logged out successfully"
}
```

**Acceptance Criteria**:

- ✅ Valid refresh tokens can be exchanged for new access tokens
- ✅ Expired refresh tokens are rejected
- ✅ Logout invalidates the session
- ✅ Logged out tokens cannot be used

**Estimated Time**: 3-4 days

---

#### 1.6 OAuth 2.1 Authorization Code Flow (with PKCE)

**Tasks**:

- [x] Implement client registration (manual for MVP)
- [x] Create authorization endpoint (`GET /oauth/authorize`)
- [x] Create token endpoint (`POST /oauth/token`)
- [x] Implement PKCE (code_challenge, code_verifier)
- [x] Generate authorization codes
- [x] Exchange authorization code for tokens
- [x] Validate redirect_uri
- [x] State parameter validation

**OAuth Flow**:

```
1. Client redirects user to:
   GET /oauth/authorize?
     response_type=code&
     client_id=CLIENT_ID&
     redirect_uri=REDIRECT_URI&
     code_challenge=CHALLENGE&
     code_challenge_method=S256&
     state=STATE

2. User logs in and consents

3. QAuth redirects to:
   REDIRECT_URI?code=AUTH_CODE&state=STATE

4. Client exchanges code for tokens:
   POST /oauth/token
   {
     "grant_type": "authorization_code",
     "code": "AUTH_CODE",
     "client_id": "CLIENT_ID",
     "redirect_uri": "REDIRECT_URI",
     "code_verifier": "VERIFIER"
   }

5. Response:
   {
     "access_token": "...",
     "refresh_token": "...",
     "token_type": "Bearer",
     "expires_in": 900
   }
```

**Acceptance Criteria**:

- ✅ Authorization code flow works end-to-end
- ✅ PKCE is enforced
- ✅ Invalid redirect_uri is rejected
- ✅ Authorization codes expire after 5 minutes
- ✅ Authorization codes are single-use
- ✅ State parameter is validated

**Estimated Time**: 1.5 weeks

---

#### 1.7 Protected Resource Validation

**Tasks**:

- [x] Create JWT validation middleware
- [x] Implement token introspection endpoint (`POST /oauth/introspect`)
- [x] Create userinfo endpoint (`GET /userinfo`)
- [x] Handle expired tokens
- [x] Handle invalid signatures

**API Endpoints**:

**GET /userinfo** (OIDC userinfo):

```typescript
GET /userinfo
Authorization: Bearer eyJhbGc...

Response:
{
  "sub": "user_id",
  "email": "user@example.com",
  "email_verified": true
}
```

- **Auth**: `Authorization: Bearer <access_token>` (required). JWT middleware verifies the token and attaches the payload.
- **Response**: `sub` (required), `email` (optional), `email_verified` (optional). Claims reflect the authenticated user.

**POST /oauth/introspect** (RFC 7662 token introspection):

```typescript
POST /oauth/introspect
Content-Type: application/x-www-form-urlencoded

token=access_token_here&client_id=client_123&client_secret=client_secret_here

Response (active token):
{
  "active": true,
  "sub": "user_id",
  "client_id": "client_123",
  "exp": 1234567890,
  "iat": 1234567800,
  "iss": "https://auth.example.com",
  "token_type": "Bearer"
}

Response (invalid, expired, or cross-client token):
{
  "active": false
}
```

- **Body**: `token` (required), `client_id` (required), `client_secret` (required), `token_type_hint` (optional). Confidential client authentication (client_secret_post).
- **Response**: RFC 7662 2.2 — `active` (required); when active, optional claims `sub`, `client_id`, `exp`, `iat`, `iss`, `token_type` may be returned.

**Acceptance Criteria**:

- ✅ Valid tokens can access protected resources
- ✅ Invalid tokens are rejected with 401
- ✅ Expired tokens are rejected
- ✅ Token introspection returns correct data

**Estimated Time**: 3-4 days

---

#### 1.8 Health Check Endpoint

**Status**: ✅ Completed

**Tasks**:

- [x] Implement health check endpoint (`GET /health`)
- [x] Check database connection
- [x] Check Redis connection
- [x] Return service status

**API Endpoint**:

```typescript
GET /health

Response:
{
  "status": "ok",
  "timestamp": "2025-10-21T...",
  "services": {
    "database": "connected",
    "redis": "connected"
  }
}
```

**Acceptance Criteria**:

- ✅ Health endpoint returns 200 when all services are healthy
- ✅ Health endpoint returns 503 when services are down
- ✅ Docker health check configured

**Estimated Time**: 1 hour

---

### Phase 1 Summary

**Total Estimated Time**: 6-8 weeks

**Deliverables**:

- ✅ Working auth server with email/password authentication
- ✅ OAuth 2.1 authorization code flow (with PKCE)
- ✅ JWT token generation and validation (EdDSA)
- ✅ Email verification
- ✅ Basic user management
- ✅ Secure password hashing (Argon2id)
- ✅ Health check endpoint

**What You Can Do After Phase 1**:

- Register users
- Verify emails
- Login users
- Issue OAuth 2.1 compliant tokens
- Validate tokens in your application
- Build applications with QAuth authentication

---

## Phase 2: Developer Portal

**Timeline**: 3-4 weeks  
**Status**: Not Started

**Objective**: Allow developers to register and manage OAuth clients without manual intervention.

---

#### 2.1 Developer Registration

**Tasks**:

- [ ] Create developer registration page (TanStack Start)
- [ ] Implement email verification (reuse Phase 1 logic)
- [ ] Create developer dashboard UI
- [ ] Set up TanStack Start app structure
- [ ] Implement login/logout for developers

**UI Pages**:

- `/register` - Developer registration
- `/login` - Developer login
- `/verify` - Email verification
- `/dashboard` - Developer dashboard

**Acceptance Criteria**:

- ✅ Developers can register with email/password
- ✅ Email verification works
- ✅ Developers can login to dashboard
- ✅ Basic dashboard layout exists

**Estimated Time**: 1 week

---

#### 2.2 OAuth Client Management

**Tasks**:

- [ ] Create REST API for client management
- [ ] Create "New Client" form
- [ ] Generate client_id and client_secret
- [ ] Store client credentials securely (hash client_secret)
- [ ] Display client details
- [ ] Edit client (redirect URIs, name)
- [ ] Delete/revoke client
- [ ] List all clients for a developer

**REST API Endpoints**:

```typescript
GET    /api/clients
POST   /api/clients
GET    /api/clients/:id
PATCH  /api/clients/:id
DELETE /api/clients/:id
POST   /api/clients/:id/regenerate-secret
```

**UI Features**:

- Client creation form
- Client list view
- Client details view
- Copy client_id / client_secret
- Regenerate client_secret
- Delete confirmation modal

**Acceptance Criteria**:

- ✅ Developers can create OAuth clients
- ✅ Client credentials are generated securely
- ✅ Developers can view/edit/delete clients
- ✅ Client secrets are only shown once
- ✅ Client secrets can be regenerated

**Estimated Time**: 1.5 weeks

---

#### 2.3 API Keys & Documentation

**Tasks**:

- [ ] Generate API keys for developers
- [ ] Display API keys in dashboard
- [ ] Create API reference documentation (manual)
- [ ] Add code examples (JavaScript/TypeScript)
- [ ] Create quick start guide
- [ ] Document OAuth flow with examples

**Documentation Pages**:

- Getting Started
- OAuth 2.1 Flow
- API Reference
- Code Examples (React, Node.js, etc.)

**Acceptance Criteria**:

- ✅ Developers can generate API keys
- ✅ API reference is complete
- ✅ Quick start guide exists
- ✅ Code examples are working

**Estimated Time**: 1 week

---

### Phase 2 Summary

**Total Estimated Time**: 3-4 weeks

**Deliverables**:

- ✅ Developer portal (TanStack Start)
- ✅ Self-service client registration
- ✅ REST API for client management
- ✅ API key management
- ✅ Basic documentation

**What You Can Do After Phase 2**:

- Developers can register and create OAuth clients
- No manual intervention needed
- Developers have API keys
- Documentation available

---

## Phase 3: Production Readiness

**Timeline**: 4-6 weeks  
**Status**: Not Started

**Objective**: Make the system production-ready with security, monitoring, and OIDC compliance.

---

#### 3.1 Security Hardening

**Tasks**:

- [ ] Implement rate limiting (fastify-rate-limit)
  - `/auth/register`: 3 requests/hour per IP
  - `/auth/login`: 5 requests/15min per IP
  - `/auth/resend-verification`: 3 requests/hour per email
  - `/oauth/token`: 10 requests/min per client
- [ ] Add CSRF protection
- [ ] Secure cookie settings (HttpOnly, Secure, SameSite)
- [ ] Input validation and sanitization (zod)
- [ ] SQL injection prevention (Drizzle parameterized queries)
- [ ] XSS protection
- [ ] Security headers (helmet)
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Frame-Options
  - X-Content-Type-Options
- [ ] Audit logging (all auth events)
- [ ] Failed login attempt tracking

**Security Headers**:

```typescript
import helmet from '@fastify/helmet';

fastify.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
});
```

**Acceptance Criteria**:

- ✅ Rate limiting is enforced
- ✅ CSRF attacks are prevented
- ✅ Security headers are set
- ✅ All inputs are validated
- ✅ Audit logs capture all events

**Estimated Time**: 1.5 weeks

---

#### 3.2 OIDC 1.0 Compliance

**Tasks**:

- [ ] Implement OIDC discovery endpoint (`/.well-known/openid-configuration`)
- [ ] Implement JWKS endpoint (`/.well-known/jwks.json`)
- [ ] Add ID token support
- [ ] Add nonce parameter support
- [ ] Implement OIDC claims (sub, email, email_verified)
- [ ] Test with OIDC validator

**OIDC Discovery Response**:

```json
{
  "issuer": "https://auth.qauth.dev",
  "authorization_endpoint": "https://auth.qauth.dev/oauth/authorize",
  "token_endpoint": "https://auth.qauth.dev/oauth/token",
  "userinfo_endpoint": "https://auth.qauth.dev/userinfo",
  "jwks_uri": "https://auth.qauth.dev/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["EdDSA"],
  "scopes_supported": ["openid", "email", "profile"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "claims_supported": ["sub", "email", "email_verified", "name"]
}
```

**ID Token**:

```typescript
const idToken = await new SignJWT({
  sub: userId,
  email: user.email,
  email_verified: user.emailVerified,
  nonce: nonce, // From authorization request
})
  .setProtectedHeader({ alg: 'EdDSA' })
  .setIssuedAt()
  .setExpirationTime('15m')
  .setIssuer('https://auth.qauth.dev')
  .setAudience(clientId)
  .sign(privateKey);
```

**Acceptance Criteria**:

- ✅ OIDC discovery endpoint works
- ✅ JWKS endpoint returns public keys
- ✅ ID tokens are issued correctly
- ✅ OIDC validator tests pass
- ✅ Nonce parameter is validated

**Estimated Time**: 1.5 weeks

---

#### 3.3 Monitoring & Logging

**Tasks**:

- [ ] Set up structured logging (pino)
- [ ] Add metrics endpoint (`/metrics`) - Prometheus format
- [ ] Log all authentication events
- [ ] Log failed login attempts
- [ ] Monitor token generation rate
- [ ] Set up basic alerts (optional)
- [ ] Add request ID tracking

**Structured Logging**:

```typescript
import pino from 'pino';

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,
    },
  },
});

logger.info(
  {
    event: 'user.login',
    userId: user.id,
    email: user.email,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  },
  'User logged in successfully'
);
```

**Metrics**:

```typescript
GET /metrics

# HELP auth_login_total Total number of login attempts
# TYPE auth_login_total counter
auth_login_total{status="success"} 1234
auth_login_total{status="failure"} 56

# HELP auth_token_issued_total Total number of tokens issued
# TYPE auth_token_issued_total counter
auth_token_issued_total{type="access"} 5678
auth_token_issued_total{type="refresh"} 3456
```

**Acceptance Criteria**:

- ✅ Structured logs are written
- ✅ Metrics endpoint works
- ✅ All auth events are logged
- ✅ Failed attempts are tracked
- ✅ Request IDs are present

**Estimated Time**: 1 week

---

#### 3.4 Docker & Deployment

**Status**: ✅ Completed (2026-01-15)

**Tasks**:

- [x] Create Dockerfile for auth-server
- [x] Create Dockerfile for migration-runner (separate service for DB migrations)
- [ ] Create Dockerfile for developer-portal (Phase 2)
- [x] Create docker-compose.yml (PostgreSQL 18 + Redis 7 + QAuth)
- [x] Write deployment documentation (README.md, docs/docker.md)
- [x] Environment variable configuration (.env.docker.example)
- [x] Database migration strategy (migration-runner service using Nx targets)
- [x] Add .dockerignore
- [x] Multi-stage builds for optimization
- [x] Health checks for all services
- [x] Non-root user in containers
- [x] JWT key management strategy (ADR-001)

**docker-compose.yml** (simplified, see actual file for full config):

```yaml
services:
  postgres:
    image: postgres:18-alpine # PostgreSQL 18 for uuidv7() support
    environment:
      POSTGRES_DB: qauth
      POSTGRES_USER: qauth
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U qauth -d qauth']
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    healthcheck:
      test: ['CMD', 'redis-cli', 'ping']
    volumes:
      - redis_data:/data

  migration-runner:
    build:
      context: .
      dockerfile: apps/migration-runner/Dockerfile
    depends_on:
      postgres:
        condition: service_healthy
    restart: 'no' # Run once and exit

  auth-server:
    build:
      context: .
      dockerfile: apps/auth-server/Dockerfile
    environment:
      # See .env.docker.example for all variables
      JWT_PRIVATE_KEY: ${JWT_PRIVATE_KEY}
      JWT_PUBLIC_KEY: ${JWT_PUBLIC_KEY}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      migration-runner:
        condition: service_completed_successfully
    healthcheck:
      test: ['CMD', 'node', '-e', "require('http').get('http://localhost:3000/health')"]

volumes:
  postgres_data:
  redis_data:
```

**Dockerfile (auth-server)** - Multi-stage build with corepack:

```dockerfile
# Stage 1: Dependencies
FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml nx.json tsconfig.base.json ./
RUN corepack enable && pnpm install --frozen-lockfile

# Stage 2: Builder
FROM deps AS builder
COPY vitest.config.ts libs apps ./
RUN pnpm nx build auth-server --prod

# Stage 3: Runner (minimal production image)
FROM node:24-alpine AS runner
WORKDIR /app
RUN corepack enable

# Copy built application and dependencies
COPY --from=builder /app/dist/apps/auth-server ./
COPY --from=builder /app/dist/libs ./dist/libs
COPY --from=builder /app/package.json /app/pnpm-lock.yaml /app/node_modules ./

# Security: non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
USER nodejs

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"
ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]
```

**Acceptance Criteria**:

- ✅ Docker images build successfully
- ✅ docker-compose starts all services
- ✅ Health checks work in Docker
- ✅ Migrations run on startup
- ✅ Deployment documentation is complete

**Estimated Time**: 1 week

---

### Phase 3 Summary

**Total Estimated Time**: 4-6 weeks

**Deliverables**:

- ✅ Production-ready security
- ✅ OIDC 1.0 compliance
- ✅ Monitoring and structured logging
- ✅ Docker deployment
- ✅ Deployment documentation

**What You Can Do After Phase 3**:

- Deploy to production
- Use QAuth for real applications
- Monitor system health
- Comply with OIDC 1.0 standards

---

## Phase 4+: Future Enhancements (Post-MVP)

These features are NOT part of the MVP:

### Phase 4: Social Login & MFA (4-5 weeks)

- Google OAuth
- GitHub OAuth
- Microsoft OAuth
- TOTP-based MFA
- SMS-based MFA (optional)

### Phase 5: Advanced Features (6-8 weeks)

- WebAuthn/Passkeys
- Magic link authentication
- Custom roles and permissions (Advanced RBAC)
- Organizations & Teams
- Email templates customization
- Webhook system
- GraphQL API

### Phase 6: Enterprise Features (8-10 weeks)

- SAML 2.0 support
- LDAP/Active Directory integration
- Multi-tenancy
- Custom domains
- SSO (Single Sign-On)
- Audit logs UI

### Phase 7: Post-Quantum & Scale (6-8 weeks)

- Hybrid ML-DSA + Ed25519 JWT signing
- Microservices extraction (Token service, TypeScript)
- Session service microservice (TypeScript, Rust optional for extreme scale)
- gRPC communication
- Horizontal scaling
- CDN integration

### Phase 8: Agent Authentication & Authorization (TBD)

- "Agent" client type on QAuth (register and identify agents)
- Agent session state / mode (ReadOnly, Admin, Exec)
- Granular scopes (e.g. `fs:read`, `fs:write`, `exec:run`) enforced per client/mode
- Step-up auth (MFA/OTP) before critical operations (e.g. destructive or high-impact)
- QAuth-side audit log of agent actions by mode for compliance

---

## 📊 MVP Development Timeline

**Total Estimated Time**: 14-20 weeks (3.5-5 months)

| Phase                     | Duration        | Status       |
| ------------------------- | --------------- | ------------ |
| Phase 0: Foundation Setup | 1-2 weeks       | ✅ Completed |
| Phase 1: Core Auth        | 6-8 weeks       | In Progress  |
| Phase 2: Developer Portal | 3-4 weeks       | Not Started  |
| Phase 3: Production Ready | 4-6 weeks       | Not Started  |
| **Total MVP**             | **14-20 weeks** | **Phase 1**  |

---

## 🎯 Success Metrics (Post-MVP)

**Technical Metrics**:

- 100% OAuth 2.1 compliance
- 100% OIDC 1.0 compliance
- <100ms token validation time
- <1s authorization flow completion
- Zero critical security vulnerabilities

**Developer Experience**:

- Developer can create client in <5 minutes
- Developer can integrate QAuth in <30 minutes
- Clear error messages for all failures
- Documentation covers common use cases

**Business Metrics**:

- First paying customer
- 10 active OAuth clients
- 100+ authenticated users across all clients
- 99.9% uptime

---

## 🚀 Development Principles

1. **Ship Early, Ship Often** - Each phase should be deployable
2. **Security First** - Never compromise security for speed
3. **Documentation Later** - Focus on working code first
4. **Test Critical Paths** - Focus on auth flows
5. **Use Existing Tools** - Don't reinvent the wheel
6. **Simplify** - If complex, break down or defer
7. **No Gold Plating** - MVP means minimum
8. **Ask for Help** - Use communities when stuck

---

## 🛠️ Tech Stack for MVP

**Backend**:

- **Fastify** - Web framework
- **Drizzle ORM** - Database access
- **PostgreSQL** - Database
- **Redis** - Sessions and caching
- **@node-rs/argon2** - Password hashing (Rust native binding)
- **zxcvbn** - Password strength validation
- **jose** - JWT generation (EdDSA)
- **resend** - Email delivery (production)
- **nodemailer** - SMTP email delivery
- **@react-email/components** - Email templates
- **zod** - Schema validation

**Frontend (Developer Portal)**:

- **TanStack Start** - Full-stack React framework
- **React 19** - UI library
- **Tailwind CSS** - Styling
- **Radix UI** - Accessible components

**Testing**:

- **Vitest** - Unit and integration testing
- **Supertest** - HTTP API testing
- **@qauth/shared-testing** - Test utilities and fixtures

**DevOps**:

- **Docker** - Containerization
- **docker-compose** - Local development
- **pino** - Structured logging
- **helmet** - Security headers
- **fastify-rate-limit** - Rate limiting

---

## 📝 Key Decisions

### Password Hashing

- **Decision**: @node-rs/argon2 (Rust native binding)
- **Rationale**: Fast, secure, quantum-resistant, no WASM complexity

### JWT Algorithm

- **Decision**: EdDSA (Ed25519) for MVP
- **Rationale**: Fast, secure, simple. Hybrid PQC later (Phase 7)

### JWT Expiration

- **Decision**: 15 minutes (access), 7 days (refresh)
- **Rationale**: Balance security and UX

### Email Verification

- **Decision**: Required for production use
- **Rationale**: Prevent spam, improve security

### API Style

- **Decision**: REST for MVP
- **Rationale**: Simple, standards-compliant. GraphQL in Phase 5+

### Rate Limiting

- **Decision**: Redis-based token bucket
- **Rationale**: Fast, scalable, shared across instances

---

## 🔗 Related Documents

- [README.md](./README.md) - Project overview
- [Docker Guide](./docs/docker.md) - Local development with Docker
- [ADR Index](./docs/adr/README.md) - Architecture Decision Records

---

## Appendix A: Database Schema

> **Note**: This is a simplified SQL representation. The actual implementation uses Drizzle ORM with TypeScript schemas. For the complete, up-to-date schema, see `libs/infra/db/src/lib/schema/` or the DBML file at `libs/infra/db/src/qauth-schema.dbml`.

### Key Design Decisions

- **UUIDv7 Primary Keys**: Time-ordered UUIDs for better B-tree index performance and chronological sorting
- **BIGINT Timestamps**: Epoch milliseconds (not TIMESTAMP) for efficient storage and timezone-independent queries
- **JSONB Columns**: Flexible storage for metadata, arrays (grant_types, scopes), and policies (password_policy)
- **PostgreSQL Enums**: Type-safe enums for grant types, response types, token endpoint auth methods, etc.
- **Multi-tenancy**: All data scoped to realms for complete isolation
- **Optimized Indexes**: Composite indexes, partial indexes for active records, unique constraints at column level

### Schema Overview

```sql
-- PostgreSQL Enums (must be created first)
CREATE TYPE token_endpoint_auth_method AS ENUM ('client_secret_post', 'client_secret_basic', 'private_key_jwt', 'none');
CREATE TYPE ssl_required AS ENUM ('none', 'external', 'all');
CREATE TYPE code_challenge_method AS ENUM ('S256');
CREATE TYPE grant_type AS ENUM ('authorization_code', 'refresh_token', 'client_credentials');
CREATE TYPE response_type AS ENUM ('code');
CREATE TYPE audit_event_type AS ENUM ('auth', 'token', 'client', 'security', 'user', 'realm');

-- Realms (Multi-tenancy)
CREATE TABLE realms (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  name VARCHAR(255) UNIQUE NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  access_token_lifespan BIGINT DEFAULT 900,
  refresh_token_lifespan BIGINT DEFAULT 604800,
  ssl_required ssl_required DEFAULT 'external',
  password_policy JSONB,
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000),
  updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000)
);

-- Users
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
  email VARCHAR(255) NOT NULL,
  email_normalized VARCHAR(255) NOT NULL,
  password_hash TEXT NOT NULL,
  email_verified BOOLEAN DEFAULT FALSE,
  enabled BOOLEAN DEFAULT TRUE,
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000),
  updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000)
);

CREATE UNIQUE INDEX idx_users_realm_email_normalized_unique ON users(realm_id, email_normalized);

-- Email Verification Tokens
CREATE TABLE email_verification_tokens (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  token VARCHAR(255) UNIQUE NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at BIGINT NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000)
);

-- OAuth Clients
CREATE TABLE oauth_clients (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
  client_id VARCHAR(255) NOT NULL,
  client_secret_hash TEXT NOT NULL,
  name VARCHAR(255) NOT NULL,
  redirect_uris JSONB NOT NULL,
  grant_types JSONB NOT NULL DEFAULT '["authorization_code","refresh_token"]'::jsonb,
  response_types JSONB NOT NULL DEFAULT '["code"]'::jsonb,
  token_endpoint_auth_method token_endpoint_auth_method NOT NULL DEFAULT 'client_secret_post',
  require_pkce BOOLEAN DEFAULT TRUE,
  enabled BOOLEAN DEFAULT TRUE,
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000),
  updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000)
);

CREATE UNIQUE INDEX idx_oauth_clients_realm_client_id_unique ON oauth_clients(realm_id, client_id);

-- Authorization Codes
CREATE TABLE authorization_codes (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  code VARCHAR(255) UNIQUE NOT NULL,
  oauth_client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method code_challenge_method NOT NULL DEFAULT 'S256',
  expires_at BIGINT NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000)
);

-- Refresh Tokens
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  token_hash TEXT UNIQUE NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  oauth_client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  expires_at BIGINT NOT NULL,
  revoked BOOLEAN DEFAULT FALSE,
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000)
);

-- Audit Logs
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  oauth_client_id UUID REFERENCES oauth_clients(id) ON DELETE SET NULL,
  event VARCHAR(100) NOT NULL,
  event_type audit_event_type NOT NULL,
  success BOOLEAN DEFAULT TRUE,
  ip_address VARCHAR(45),
  user_agent TEXT,
  metadata JSONB,
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000)
);

-- Sessions (optional, can use Redis instead)
CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  oauth_client_id UUID REFERENCES oauth_clients(id) ON DELETE SET NULL,
  expires_at BIGINT NOT NULL,
  revoked BOOLEAN DEFAULT FALSE,
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000)
);
```

### Foreign Key Relationships

- All foreign keys use UUID primary keys (not VARCHAR client_id) for better performance
- `oauth_client_id` references `oauth_clients.id` (UUID), not `oauth_clients.client_id` (VARCHAR)
- Cascade deletes for dependent records, SET NULL for optional relationships

---

## Appendix B: API Endpoints Summary

| Endpoint                             | Method | Description                  | Phase |
| ------------------------------------ | ------ | ---------------------------- | ----- |
| `/auth/register`                     | POST   | Register new user            | 1.2   |
| `/auth/resend-verification`          | POST   | Resend verification email    | 1.3   |
| `/auth/verify`                       | GET    | Verify email                 | 1.3   |
| `/auth/login`                        | POST   | Login with email/password    | 1.4   |
| `/auth/refresh`                      | POST   | Refresh access token         | 1.5   |
| `/auth/logout`                       | POST   | Logout and revoke session    | 1.5   |
| `/oauth/authorize`                   | GET    | OAuth authorization endpoint | 1.6   |
| `/oauth/token`                       | POST   | Token exchange endpoint      | 1.6   |
| `/oauth/introspect`                  | POST   | Token introspection          | 1.7   |
| `/userinfo`                          | GET    | OIDC userinfo endpoint       | 1.7   |
| `/health`                            | GET    | Health check                 | 1.8   |
| `/.well-known/openid-configuration`  | GET    | OIDC discovery               | 3.2   |
| `/.well-known/jwks.json`             | GET    | JWKS public keys             | 3.2   |
| `/metrics`                           | GET    | Prometheus metrics           | 3.3   |
| `/api/clients`                       | GET    | List OAuth clients           | 2.2   |
| `/api/clients`                       | POST   | Create OAuth client          | 2.2   |
| `/api/clients/:id`                   | GET    | Get client details           | 2.2   |
| `/api/clients/:id`                   | PATCH  | Update client                | 2.2   |
| `/api/clients/:id`                   | DELETE | Delete client                | 2.2   |
| `/api/clients/:id/regenerate-secret` | POST   | Regenerate client secret     | 2.2   |

---

## Appendix C: Library Structure

The QAuth monorepo is organized into the following libraries:

### Server Libraries (`libs/server/`)

| Library    | Package                  | Description                                                |
| ---------- | ------------------------ | ---------------------------------------------------------- |
| `config`   | `@qauth/server-config`   | Environment configuration with Zod schemas                 |
| `email`    | `@qauth/server-email`    | Email service with multiple providers (Resend, SMTP, Mock) |
| `password` | `@qauth/server-password` | Password hashing with Argon2id                             |

### Infrastructure Libraries (`libs/infra/`)

| Library | Package              | Description                                        |
| ------- | -------------------- | -------------------------------------------------- |
| `db`    | `@qauth/infra-db`    | PostgreSQL database with Drizzle ORM, repositories |
| `cache` | `@qauth/infra-cache` | Redis connection and caching utilities             |

### Shared Libraries (`libs/shared/`)

| Library      | Package                    | Description                                         |
| ------------ | -------------------------- | --------------------------------------------------- |
| `errors`     | `@qauth/shared-errors`     | Centralized error handling (auth, database, common) |
| `validation` | `@qauth/shared-validation` | Validation utilities (email, password strength)     |
| `testing`    | `@qauth/shared-testing`    | Test helpers (Fastify, Supertest, fixtures)         |

### Fastify Plugins (`libs/fastify/plugins/`)

| Plugin     | Package                          | Description                                     |
| ---------- | -------------------------------- | ----------------------------------------------- |
| `db`       | `@qauth/fastify-plugin-db`       | Database plugin with repository injection       |
| `cache`    | `@qauth/fastify-plugin-cache`    | Redis cache plugin                              |
| `password` | `@qauth/fastify-plugin-password` | Password hasher and validator injection         |
| `email`    | `@qauth/fastify-plugin-email`    | Email service injection with provider selection |

---

**End of MVP-PRD v1.4**
