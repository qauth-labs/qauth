# QAuth - MVP Product Requirements Document (PRD)

> **Version**: 1.0
> **Last Updated**: 2025-10-14
> **Author**: Taha (Solo Developer)
> **Status**: Planning Phase

## Executive Summary

QAuth is a post-quantum ready, headless-first identity platform designed as a developer-friendly alternative to Keycloak. This document outlines the Minimum Viable Product (MVP) roadmap broken into achievable phases for a solo developer.

**Core Philosophy**: Ship working features incrementally. Each phase should be production-ready before moving to the next.

---

## 🎯 MVP Vision

**Goal**: Create a working OAuth 2.1/OIDC authentication server that a developer can use to authenticate users in their application.

**Success Criteria**:

- A developer can register an OAuth client
- A developer can implement login/signup in their app using QAuth
- Users can authenticate with email/password
- JWT tokens are issued and validated correctly
- Basic security practices are implemented

**Non-Goals for MVP**:

- Social login (Google, GitHub, etc.)
- Multi-factor authentication (MFA)
- WebAuthn/Passkeys
- SAML support
- Multi-tenancy
- Custom domains
- Advanced RBAC
- Microservices architecture

---

## 📋 Phase Breakdown

### Phase 0: Foundation Setup (CURRENT)

**Timeline**: 1-2 weeks
**Status**: In Progress

**Objective**: Set up the development environment and project structure.

#### Tasks

- [x] Initialize Nx monorepo
- [x] Configure pnpm workspace
- [x] Set up ESLint + Prettier
- [x] Configure Husky + commitlint
- [x] Create project documentation (CLAUDE.md, README.md)
- [ ] Set up database schema (PostgreSQL + Drizzle ORM)
- [ ] Set up Redis connection
- [ ] Create base Fastify server structure
- [ ] Set up environment configuration

#### Deliverables

- ✅ Working Nx workspace
- ✅ Code quality tools configured
- ⏳ Database schema defined
- ⏳ Basic server running

---

### Phase 1: Core Authentication (MVP Foundation)

**Timeline**: 4-6 weeks
**Status**: Not Started

**Objective**: Implement basic email/password authentication with JWT tokens.

#### 1.1 Database Schema & Models

**Tasks**:

- [ ] Design database schema
  - Users table (id, email, password_hash, created_at, updated_at, verified, etc.)
  - Sessions table (id, user_id, token, expires_at, created_at)
  - OAuth clients table (id, client_id, client_secret, name, redirect_uris, created_at)
  - Authorization codes table (id, code, client_id, user_id, redirect_uri, expires_at)
  - Refresh tokens table (id, token, user_id, client_id, expires_at)
- [ ] Set up Drizzle ORM schemas
- [ ] Create database migrations
- [ ] Write basic CRUD operations

**Acceptance Criteria**:

- ✅ Database schema is normalized and follows best practices
- ✅ Migrations can be run and rolled back
- ✅ Basic queries work (create user, find user, etc.)

**Estimated Time**: 1 week

---

#### 1.2 User Registration & Password Hashing

**Tasks**:

- [ ] Implement user registration endpoint (`POST /auth/register`)
- [ ] Integrate Argon2id password hashing (via Rust WASM)
  - Create Rust WASM module for password hashing
  - Export hash() and verify() functions
  - Integrate with TypeScript auth service
- [ ] Email validation
- [ ] Password strength validation
- [ ] Check for duplicate emails
- [ ] Basic rate limiting on registration

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
    "created_at": "2025-10-14T..."
  }
}
```

**Acceptance Criteria**:

- ✅ Users can register with email/password
- ✅ Passwords are hashed with Argon2id
- ✅ Duplicate emails are rejected
- ✅ Weak passwords are rejected
- ✅ Rate limiting prevents abuse

**Estimated Time**: 1 week

---

#### 1.3 User Login & JWT Tokens

**Tasks**:

- [ ] Implement login endpoint (`POST /auth/login`)
- [ ] Verify password using Argon2id
- [ ] Generate JWT access tokens
- [ ] Generate refresh tokens
- [ ] Store session in Redis
- [ ] Implement JWT signing (initially Ed25519, later hybrid ML-DSA)

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
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

**Acceptance Criteria**:

- ✅ Users can login with correct credentials
- ✅ Invalid credentials are rejected
- ✅ JWT tokens are properly signed
- ✅ Tokens have correct expiration
- ✅ Refresh tokens are stored securely

**Estimated Time**: 1 week

---

#### 1.4 Token Refresh & Logout

**Tasks**:

- [ ] Implement token refresh endpoint (`POST /auth/refresh`)
- [ ] Validate refresh token
- [ ] Issue new access token
- [ ] Implement logout endpoint (`POST /auth/logout`)
- [ ] Revoke refresh token on logout
- [ ] Clear session from Redis

**API Endpoints**:

```typescript
POST /auth/refresh
{
  "refresh_token": "refresh_token_here"
}

Response:
{
  "access_token": "eyJhbGc...",
  "expires_in": 3600
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

#### 1.5 OAuth 2.1 Authorization Code Flow (with PKCE)

**Tasks**:

- [ ] Implement client registration (manual for MVP)
- [ ] Create authorization endpoint (`GET /oauth/authorize`)
- [ ] Create token endpoint (`POST /oauth/token`)
- [ ] Implement PKCE (code_challenge, code_verifier)
- [ ] Generate authorization codes
- [ ] Exchange authorization code for tokens
- [ ] Validate redirect_uri

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
     "expires_in": 3600
   }
```

**Acceptance Criteria**:

- ✅ Authorization code flow works end-to-end
- ✅ PKCE is enforced (no authorization without code_challenge)
- ✅ Invalid redirect_uri is rejected
- ✅ Authorization codes expire after use
- ✅ State parameter is validated

**Estimated Time**: 1.5 weeks

---

#### 1.6 Protected Resource Validation

**Tasks**:

- [ ] Create JWT validation middleware
- [ ] Implement token introspection endpoint (`POST /oauth/introspect`)
- [ ] Create `/userinfo` endpoint (OIDC)
- [ ] Handle expired tokens
- [ ] Handle invalid signatures

**API Endpoints**:

```typescript
GET /userinfo
Authorization: Bearer eyJhbGc...

Response:
{
  "sub": "user_id",
  "email": "user@example.com",
  "email_verified": false
}

---

POST /oauth/introspect
{
  "token": "access_token_here"
}

Response:
{
  "active": true,
  "sub": "user_id",
  "client_id": "client_id",
  "exp": 1234567890
}
```

**Acceptance Criteria**:

- ✅ Valid tokens can access protected resources
- ✅ Invalid tokens are rejected with 401
- ✅ Expired tokens are rejected
- ✅ Token introspection returns correct data

**Estimated Time**: 3-4 days

---

### Phase 1 Summary

**Total Estimated Time**: 4-6 weeks

**Deliverables**:

- ✅ Working auth server with email/password authentication
- ✅ OAuth 2.1 authorization code flow (with PKCE)
- ✅ JWT token generation and validation
- ✅ Basic user management
- ✅ Secure password hashing (Argon2id via Rust WASM)

**What You Can Do After Phase 1**:

- Register users
- Login users
- Issue OAuth 2.1 compliant tokens
- Validate tokens in your application
- Build a basic application with QAuth authentication

---

## Phase 2: Developer Portal (Self-Service)

**Timeline**: 3-4 weeks
**Status**: Not Started

**Objective**: Allow developers to register and manage their OAuth clients without manual intervention.

#### 2.1 Developer Registration

**Tasks**:

- [ ] Create developer registration page
- [ ] Implement email verification
- [ ] Create developer dashboard UI
- [ ] Set up TanStack Start app structure

**Estimated Time**: 1 week

---

#### 2.2 OAuth Client Management

**Tasks**:

- [ ] Create "New Client" form
- [ ] Generate client_id and client_secret
- [ ] Store client credentials securely
- [ ] Display client details
- [ ] Edit client (redirect URIs, name, etc.)
- [ ] Delete/revoke client
- [ ] List all clients for a developer

**UI Features**:

- Client creation form
- Client list view
- Client details view
- Copy client_id / client_secret
- Regenerate client_secret

**Estimated Time**: 1.5 weeks

---

#### 2.3 API Keys & Documentation

**Tasks**:

- [ ] Generate API keys for developers
- [ ] Create API reference documentation (manual)
- [ ] Add code examples (JavaScript/TypeScript SDK)
- [ ] Quick start guide in portal

**Estimated Time**: 1 week

---

### Phase 2 Summary

**Total Estimated Time**: 3-4 weeks

**Deliverables**:

- ✅ Developer portal (TanStack Start)
- ✅ Self-service client registration
- ✅ API key management
- ✅ Basic documentation

**What You Can Do After Phase 2**:

- Developers can register and create OAuth clients
- No manual intervention needed for client creation
- Developers have API keys to use the service

---

## Phase 3: Production Readiness

**Timeline**: 3-4 weeks
**Status**: Not Started

**Objective**: Make the system production-ready with proper security, monitoring, and deployment.

#### 3.1 Security Hardening

**Tasks**:

- [ ] Implement rate limiting (all endpoints)
- [ ] Add CSRF protection
- [ ] Secure cookie settings (HttpOnly, Secure, SameSite)
- [ ] Input validation and sanitization
- [ ] SQL injection prevention (verify Drizzle usage)
- [ ] XSS protection
- [ ] Security headers (CSP, HSTS, etc.)
- [ ] Audit logging (all auth events)

**Estimated Time**: 1 week

---

#### 3.2 OIDC 1.0 Compliance

**Tasks**:

- [ ] Implement OIDC discovery endpoint (`/.well-known/openid-configuration`)
- [ ] Implement JWKS endpoint (`/.well-known/jwks.json`)
- [ ] Add ID token support
- [ ] Add `nonce` parameter support
- [ ] Implement OIDC claims (sub, email, email_verified, etc.)

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
  "id_token_signing_alg_values_supported": ["EdDSA", "RS256"]
}
```

**Estimated Time**: 1 week

---

#### 3.3 Monitoring & Logging

**Tasks**:

- [ ] Set up structured logging (pino or winston)
- [ ] Add health check endpoint (`/health`)
- [ ] Add metrics endpoint (`/metrics`) - Prometheus format
- [ ] Log all authentication events
- [ ] Log failed login attempts
- [ ] Monitor token generation rate
- [ ] Set up basic alerts (optional)

**Estimated Time**: 3-4 days

---

#### 3.4 Docker & Deployment

**Tasks**:

- [ ] Create Dockerfile for auth-server
- [ ] Create Dockerfile for developer-portal
- [ ] Create docker-compose.yml (PostgreSQL + Redis + QAuth)
- [ ] Write deployment documentation
- [ ] Environment variable configuration
- [ ] Database migration strategy for production

**Estimated Time**: 3-4 days

---

### Phase 3 Summary

**Total Estimated Time**: 3-4 weeks

**Deliverables**:

- ✅ Production-ready security
- ✅ OIDC 1.0 compliance
- ✅ Monitoring and logging
- ✅ Docker deployment
- ✅ Basic deployment documentation

**What You Can Do After Phase 3**:

- Deploy to production
- Use QAuth for real applications
- Monitor system health
- Comply with OIDC standards

---

## Phase 4+: Future Enhancements (Post-MVP)

These features are NOT part of the MVP but can be added later:

### Phase 4: Social Login & MFA (4-5 weeks)

- Google OAuth
- GitHub OAuth
- Microsoft OAuth
- TOTP-based MFA
- SMS-based MFA (optional)

### Phase 5: Advanced Features (6-8 weeks)

- WebAuthn/Passkeys
- Magic link authentication
- Custom roles and permissions (RBAC)
- Organizations & Teams
- Email templates customization
- Webhook system

### Phase 6: Enterprise Features (8-10 weeks)

- SAML 2.0 support
- LDAP/Active Directory integration
- Multi-tenancy
- Custom domains
- SSO (Single Sign-On)
- Audit logs UI

### Phase 7: Performance & Scale (4-6 weeks)

- Microservices extraction (Token service → Rust)
- Session service → Rust microservice
- gRPC communication
- Horizontal scaling
- CDN integration

---

## 📊 MVP Development Timeline

**Total Estimated Time**: 10-14 weeks (2.5-3.5 months)

| Phase                     | Duration        | Status       |
| ------------------------- | --------------- | ------------ |
| Phase 0: Foundation Setup | 1-2 weeks       | ✅ Complete  |
| Phase 1: Core Auth        | 4-6 weeks       | Not Started  |
| Phase 2: Developer Portal | 3-4 weeks       | Not Started  |
| Phase 3: Production Ready | 3-4 weeks       | Not Started  |
| **Total MVP**             | **11-16 weeks** | **Planning** |

---

## 🎯 Success Metrics (Post-MVP)

After completing the MVP, measure success by:

**Technical Metrics**:

- ✅ 100% OAuth 2.1 compliance
- ✅ 100% OIDC 1.0 compliance
- ✅ <100ms token validation time
- ✅ <1s authorization flow completion
- ✅ Zero critical security vulnerabilities

**Developer Experience**:

- ✅ Developer can create client in <5 minutes
- ✅ Developer can integrate QAuth in <30 minutes
- ✅ Clear error messages for all failures
- ✅ Documentation covers common use cases

**Business Metrics**:

- ✅ First paying customer (post-MVP)
- ✅ 10 active OAuth clients
- ✅ 100+ authenticated users across all clients
- ✅ 99.9% uptime

---

## 🚀 Development Principles

As a solo developer, follow these principles:

1. **Ship Early, Ship Often**: Each phase should be deployable
2. **Security First**: Never compromise on security for speed
3. **Documentation Later**: Focus on working code, document when stable
4. **Test Critical Paths**: Focus testing on auth flows, not 100% coverage
5. **Use Existing Tools**: Don't reinvent the wheel (Drizzle, Fastify, etc.)
6. **Simplify**: If a feature is complex, break it down or defer it
7. **No Gold Plating**: MVP means minimum - resist feature creep
8. **Ask for Help**: Use communities, Stack Overflow, Claude when stuck

---

## 🛠️ Tech Stack for MVP

**Backend**:

- ✅ **Fastify** - Web framework
- ✅ **Drizzle ORM** - Database access
- ✅ **PostgreSQL** - Database
- ✅ **Redis** - Sessions and caching
- ✅ **Rust WASM** - Password hashing (Argon2id)
- ✅ **jsonwebtoken** (Node.js) - JWT generation (Phase 1)
  - Later: Rust WASM for JWT signing (Phase 4+)

**Frontend (Developer Portal)**:

- ✅ **TanStack Start** - Full-stack React framework
- ✅ **React 19** - UI library
- ✅ **Tailwind CSS** - Styling
- ✅ **Radix UI** - Accessible components

**DevOps**:

- ✅ **Docker** - Containerization
- ✅ **docker-compose** - Local development
- ✅ **GitHub Actions** - CI/CD (later)

---

## 📝 Open Questions & Decisions Needed

### For Phase 1:

- [ ] **Decision**: Use bcrypt or Argon2id for password hashing?
  - **Recommendation**: Argon2id (OWASP recommended, post-quantum resistant)
- [ ] **Decision**: JWT expiration time (access token)?
  - **Recommendation**: 15 minutes (access), 7 days (refresh)
- [ ] **Decision**: Which JWT algorithm for MVP?
  - **Recommendation**: Ed25519 (fast, secure) → Migrate to ML-DSA later

### For Phase 2:

- [ ] **Decision**: GraphQL or REST for developer portal API?
  - **Recommendation**: REST for MVP (simpler), GraphQL later
- [ ] **Decision**: Email verification required for developer registration?
  - **Recommendation**: Yes (prevent spam)

### For Phase 3:

- [ ] **Decision**: Which cloud provider for hosted version?
  - **Recommendation**: Defer until post-MVP
- [ ] **Decision**: Rate limiting strategy?
  - **Recommendation**: Redis-based, 100 req/15min for auth endpoints

---

## 🔗 Related Documents

- [README.md](./README.md) - Project overview
- [CLAUDE.md](./CLAUDE.md) - Development guidelines for Claude
- [Architecture Overview](./docs/architecture.md) - System architecture (to be created)
- [Development Setup](./docs/development.md) - Local setup guide (to be created)

---

## 📞 Contact & Feedback

**Developer**: Taha
**Project**: QAuth
**Repository**: https://github.com/qauth-labs/qauth
**License**: Apache 2.0

---

**Last Updated**: 2025-10-14
**Next Review**: After Phase 1 completion

---

## Appendix A: Database Schema (Initial Draft)

```sql
-- Users
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email_verified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- OAuth Clients
CREATE TABLE oauth_clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id VARCHAR(255) UNIQUE NOT NULL,
  client_secret_hash TEXT NOT NULL,
  name VARCHAR(255) NOT NULL,
  redirect_uris TEXT[] NOT NULL,
  developer_id UUID REFERENCES users(id),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Authorization Codes
CREATE TABLE authorization_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code VARCHAR(255) UNIQUE NOT NULL,
  client_id VARCHAR(255) REFERENCES oauth_clients(client_id),
  user_id UUID REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method VARCHAR(10) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Refresh Tokens
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token TEXT UNIQUE NOT NULL,
  user_id UUID REFERENCES users(id),
  client_id VARCHAR(255) REFERENCES oauth_clients(client_id),
  expires_at TIMESTAMP NOT NULL,
  revoked BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Sessions (Redis for MVP, optionally PostgreSQL for persistence)
-- Stored in Redis:
-- Key: session:{token}
-- Value: { user_id, client_id, expires_at }
```

---

## Appendix B: API Endpoints Summary (Phase 1)

| Endpoint                            | Method | Description                  |
| ----------------------------------- | ------ | ---------------------------- |
| `/auth/register`                    | POST   | Register new user            |
| `/auth/login`                       | POST   | Login with email/password    |
| `/auth/logout`                      | POST   | Logout and revoke session    |
| `/auth/refresh`                     | POST   | Refresh access token         |
| `/oauth/authorize`                  | GET    | OAuth authorization endpoint |
| `/oauth/token`                      | POST   | Token exchange endpoint      |
| `/oauth/introspect`                 | POST   | Token introspection          |
| `/userinfo`                         | GET    | OIDC userinfo endpoint       |
| `/.well-known/openid-configuration` | GET    | OIDC discovery (Phase 3)     |
| `/.well-known/jwks.json`            | GET    | JWKS public keys (Phase 3)   |
| `/health`                           | GET    | Health check (Phase 3)       |

---

**End of MVP-PRD v1.0**
