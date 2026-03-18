<br /><br />

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="logos/qauth-logo-light.svg">
    <img src="logos/qauth-logo.svg" alt="QAuth Logo" height="140">
  </picture>
</div>

<br /><br />

<div align="center">
  <h2>Open-source federated identity platform.<br />OAuth 2.1 · OIDC 1.0 · eIDAS 2.0 bridge · Post-quantum ready.</h2>
</div>

**QAuth** is an open-source identity server and federation hub. It accepts identity from multiple upstream sources — including EUDI Wallets (OID4VC / SIOPv2), email/password, and external OIDC providers — normalises them through a common federation layer, and issues standard OAuth 2.1 access tokens and OIDC ID tokens to downstream applications. Applications integrate once against QAuth's OIDC layer and require no changes to support new upstream identity sources.

<div align="center">
  <h3>🇪🇺 Made in Europe · 🇪🇪 Made in Estonia · 🇹🇷 Made in Türkiye</h3>
</div>

## 🎯 How to Use QAuth

### 1. ⚡ Auth as a Service (Headless Backend)

Use QAuth's hosted backend with your own branded UI and custom domain.

```typescript
// Your branded login page, QAuth backend
const auth = new QAuth({
  domain: 'auth.yourapp.com',
  mode: 'headless',
});
```

**Perfect for:**

- Applications that need eIDAS 2.0 EUDI Wallet login without rewriting auth infrastructure
- Custom branding requirements with a headless API-first backend
- Startups and products that want auth without managing infrastructure

### 2. 🏠 Self-hosted (Full Control)

Deploy QAuth on your own infrastructure with complete control.

```bash
# Docker deployment
docker run -p 3000:3000 qauth/auth-server

# Or with docker-compose
curl -O https://qauth.dev/docker-compose.yml
docker-compose up -d
```

**Perfect for:**

- Regulated industries (banking, healthcare, transport) with eIDAS 2.0 compliance requirements
- Data sovereignty and GDPR requirements
- Organisations that need full control over their identity infrastructure

## 🔐 Post-Quantum Cryptography

QAuth implements a security-first hybrid approach with NIST-standardized post-quantum algorithms.

### Primary Standard

- **ML-DSA-65 (NIST FIPS 204)** — Digital signatures for JWT tokens. Level 3 (192-bit security), the minimum floor recommended by BSI (Germany) and ANSSI (France).

### Hybrid Strategy

Defense in depth with composite dual-signing — tokens carry both an ML-DSA-65 and an Ed25519 signature, following the IETF LAMPS composite signatures model (`draft-ietf-lamps-pq-composite-sigs`). Both classical and post-quantum verifiers can validate without coordination.

```typescript
// Hybrid PQC JWT signing (Phase 5)
import { signHybrid } from '@qauth/crypto';

// Composite ML-DSA-65 + Ed25519 — verifiable by classical and PQC verifiers
const token = await signHybrid(payload, { mlDsaKey, ed25519Key });
```

**Implementation:**

`@qauth/crypto` is a native Node.js binding (napi-rs) wrapping `aws-lc-rs` (AWS-LC, a production-hardened BoringSSL fork with FIPS 140-3 validation in progress). This follows the same pattern as `@node-rs/argon2` — prebuilt binaries per platform, no build tooling required for consumers. `@noble/post-quantum` (pure TypeScript, audited) is used as the fallback in development environments and CI.

The `libs/core/crypto` abstraction layer exposes algorithm-agnostic `sign` / `verify` / `generateKeyPair` interfaces so business logic is never coupled to a specific implementation. Swapping the underlying library requires no changes to the auth server.

**Token size considerations:**

ML-DSA-65 signatures are 3,309 bytes vs. Ed25519's 64 bytes. QAuth's architecture defaults to **reference tokens with introspection** (RFC 7662) rather than large self-contained JWTs — mitigating HTTP header limits and cookie size constraints during the PQC transition period.

**Migration Timeline:**

- **Phase 1** (complete): Ed25519 / EdDSA for JWT signatures
- **Phase 5**: Hybrid composite ML-DSA-65 + Ed25519 (JOSE WG draft adopted Jan 2026)
- **Future**: FN-DSA (NIST FIPS 206, pending) evaluation — compact signatures (~666 B) may make self-contained PQC JWTs practical

## 🎯 Vision

A federated identity hub for the next generation of the internet:

- **Federation-first** — accepts identity from multiple upstream sources (Verifiable Credential wallets, email/password, external OIDC providers, W3C DIDs) through a common `federation-core` layer; downstream applications see standard OIDC tokens regardless of source
- **Wallet-agnostic** — any standards-compliant VC wallet (OID4VC / SIOPv2) is a valid upstream; EUDI Wallet under eIDAS 2.0 is one concrete deployment target, not the only one
- **Post-quantum ready** — crypto-agile architecture with a clear ML-DSA-65 hybrid transition path, designed so algorithm upgrades never touch application business logic
- **Headless-first** — API-first, bring your own branded UI
- **Standards compliant** — OAuth 2.1 (RFC 9700), OIDC 1.0, OID4VC, SIOPv2, W3C DID, NIST FIPS 204
- **Open and self-hostable** — Apache 2.0, no telemetry, runs anywhere

## 🏗️ Architecture

### Phase 1: Modular Monolith (TypeScript)

```
┌──────────────────────────────────────────────────────┐
│              Auth Server (TypeScript/Node.js)        │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │  API Layer (REST)                              │  │
│  │  OAuth 2.1 · OIDC 1.0 · OID4VC · SIOPv2       │  │
│  └────────────────────────────────────────────────┘  │
│                          ↓                           │
│  ┌────────────────────────────────────────────────┐  │
│  │  federation-core                               │  │
│  │  • Upstream normalisation (VC wallet / OIDC /  │  │
│  │    password → internal user model)             │  │
│  │  • Downstream token issuance                   │  │
│  └────────────────────────────────────────────────┘  │
│                          ↓                           │
│  ┌────────────────────────────────────────────────┐  │
│  │  Native Bindings Layer (@qauth/crypto)         │  │
│  │  • JWT signing / verification (EdDSA → ML-DSA) │  │
│  │  • Password hashing (Argon2id)                 │  │
│  │  • DID resolution utilities                    │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
              ↓                           ↓
        PostgreSQL                     Redis
```

### Phase 2: Microservices (When Needed)

```
┌──────────────────────┐
│  API Gateway (TS)    │
│  • REST              │
└──────────────────────┘
          ↓ gRPC
    ┌─────┴─────┬─────────────┬──────────────┐
    ↓           ↓             ↓              ↓
┌────────┐ ┌─────────┐ ┌──────────┐ ┌─────────────┐
│ Auth   │ │ Token   │ │ Session  │ │ Developer   │
│ (TS)   │ │ (TS)    │ │ (TS)     │ │ Portal (TS) │
└────────┘ └─────────┘ └──────────┘ └─────────────┘
```

### Nx Monorepo Structure

```
qauth/
├── apps/
│   ├── auth-server/          # Core auth server (Fastify/TypeScript)
│   │                         #   OAuth 2.1, OIDC 1.0, OID4VC, SIOPv2 endpoints
│   ├── developer-portal/     # Self-service OAuth client management (TanStack Start)
│   ├── auth-ui/              # Brandable authentication UI (TanStack Start, SPA)
│   └── admin-panel/          # Admin dashboard (TanStack Start)
│
├── libs/
│   ├── core/
│   │   ├── oauth/            # OAuth 2.1 implementation
│   │   ├── oidc/             # OIDC 1.0, OID4VC, SIOPv2
│   │   └── crypto/           # @qauth/crypto — crypto abstraction layer (ADR-005)
│   │                         #   Algorithm-agnostic: sign/verify/generateKeyPair
│   │                         #   Prod: native Node.js binding (napi-rs + aws-lc-rs)
│   │                         #   Dev/CI: @noble/post-quantum (pure TypeScript fallback)
│   │                         #   Ed25519 (Phase 1) → hybrid ML-DSA-65+Ed25519 (Phase 5)
│   │
│   ├── server/
│   │   ├── federation/       # CredentialProvider interface + registry (ADR-003)
│   │   │                     #   password.provider.ts, wallet.provider.ts (Phase 4)
│   │   │                     #   Normalises upstream identity → VerifiedIdentity → user_attributes
│   │   ├── config/           # Environment configuration & Zod validation
│   │   ├── password/         # Argon2id password hashing (Rust native binding)
│   │   ├── email/            # Email service — Resend, SMTP, Mock providers
│   │   └── jwt/              # JWT signing & verification (EdDSA; delegates to @qauth/crypto)
│   │
│   ├── sdk/
│   │   ├── js/               # Vanilla JS SDK
│   │   ├── react/            # React SDK + hooks
│   │   └── node/             # Server-side SDK
│   │
│   ├── infra/
│   │   ├── db/               # PostgreSQL with Drizzle ORM, repository pattern
│   │   └── cache/            # Redis connection and caching utilities
│   │
│   ├── shared/
│   │   ├── errors/           # Centralised error classes (@qauth/shared-errors)
│   │   ├── validation/       # Validation utilities (email, password)
│   │   └── testing/          # Test helpers and utilities
│   │
│   ├── fastify-plugin/
│   │   ├── db/               # Fastify plugin for database
│   │   ├── cache/            # Fastify plugin for Redis
│   │   └── password/         # Fastify plugin for password hashing & validation
│   │
│   └── ui/
│       └── components/       # Shared React components
│
└── services/                 # Future microservices (when needed)
    ├── token-service/        # Token generation (gRPC)
    └── session-service/      # Session management (gRPC)
```

## 🚀 Features

### Phase 1 — Core Auth Server (completed)

**Core Authentication:**

- OAuth 2.1 / OpenID Connect 1.0
- Email/password authentication with Argon2id hashing
- JWT token issuance, refresh, and revocation (Ed25519 / EdDSA)
- Token introspection (RFC 7662)
- OIDC userinfo endpoint
- Multi-tenancy via Realms for complete data isolation
- Mandatory PKCE on all authorization code flows

**Infrastructure:**

- Email verification — Resend, SMTP, and Mock providers
- PostgreSQL 18 + Redis 7
- Docker deployment with automated migrations and health checks
- Structured audit logging

**Developer Tools:**

- REST API (OAuth 2.1 / OIDC endpoints)
- Self-service developer portal (Phase 2)
- TypeScript / React / Node.js SDKs (Phase 3)

### Post-MVP

**Phase 2 — Developer Portal:**

- Self-service OAuth client registration and management
- API key management
- Federation provider configuration UI

**Phase 3 — Production Hardening:**

- OIDC 1.0 conformance (OpenID Foundation test suite)
- OIDC discovery + JWKS endpoint, ID tokens, nonce, scopes
- Rate limiting (Redis token bucket, per-IP and per-email)
- Security headers (Helmet: HSTS, CSP, X-Frame-Options)
- Prometheus metrics, Kubernetes manifests

**Phase 4 — Wallet Federation Bridge (OID4VC / SIOPv2):**

- SIOPv2 authentication request handling
- OID4VC Verifiable Presentation endpoint
- Trust anchor validation (extensible: EU Trusted List and other registries)
- `federation-core`: normalises Verifiable Credentials → standard OAuth 2.1 tokens
- Wallet login UI flow in `auth-ui`
- Inverse: QAuth as a Verifiable Credential issuer

**Phase 5 — Post-Quantum Crypto:**

- `@qauth/crypto`: native Node.js binding (napi-rs + aws-lc-rs)
- Hybrid composite ML-DSA-65 + Ed25519 JWT signing (IETF LAMPS composite model)
- Reference-token architecture to handle PQC JWT size constraints
- Crypto-agile abstraction: algorithm swaps require no changes to business logic
- `@noble/post-quantum` fallback for dev/CI environments

**Phase 6+ — Enterprise & Scale:**

- Social login (Google, GitHub, Microsoft)
- WebAuthn / Passkeys, TOTP / MFA
- SAML 2.0, LDAP / Active Directory
- W3C Decentralised Identifiers (DIDs)
- Organizations, Teams, advanced RBAC
- GraphQL API, webhook system
- Multi-region, CDN, microservices extraction

## 🛠️ Technology Stack

**Backend:**

- **Runtime**: Node.js 24 LTS
- **Language**: TypeScript
- **Framework**: Fastify
- **API**: REST (OAuth 2.1 / OIDC)
- **ORM**: Drizzle ORM
- **Database**: PostgreSQL 18
- **Cache/Session**: Redis 7
- **Crypto**: `@qauth/crypto` — native Node.js binding (napi-rs + aws-lc-rs); `@noble/post-quantum` in dev/CI (ADR-005)
- **Password hashing**: `@node-rs/argon2` (Rust native binding, Argon2id)
- **JWT**: `jose` (EdDSA; algorithm selection via `@qauth/crypto` abstraction)

**Frontend:**

- **Meta-framework**: TanStack Start
- **Framework**: React 19
- **Router**: TanStack Router
- **Data Fetching**: TanStack Query
- **Build Tool**: Vite
- **UI Primitives**: Radix UI
- **Styling**: Tailwind CSS
- **Tables**: TanStack Table
- **Forms**: TanStack Form

**Infrastructure:**

- **Monorepo**: Nx 22.3+
- **Package Manager**: pnpm
- **Containerization**: Docker
- **Orchestration**: Kubernetes ready
- **Observability**: OpenTelemetry
- **Cache/Session**: Redis with ioredis

## 🚀 Quick Start

### Local Development with Docker

The easiest way to get started with QAuth locally is using Docker Compose. This will set up PostgreSQL, Redis, and the auth-server with a single command.

**Prerequisites:**

- Docker 20.10+ and Docker Compose 2.0+
- OpenSSL (for generating JWT keys)

**Quick Start:**

1. **Generate JWT keys** (required for authentication):

```bash
# Generate EdDSA key pair
openssl genpkey -algorithm Ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

2. **Set up environment variables**:

```bash
# Copy the example environment file
cp .env.docker.example .env

# Edit .env and add your JWT keys:
# JWT_PRIVATE_KEY="$(cat private.pem)"
# JWT_PUBLIC_KEY="$(cat public.pem)"
```

3. **Start all services**:

```bash
docker-compose up -d
```

This will:

- Start PostgreSQL 18 (with uuidv7() support)
- Start Redis 7
- Build and start the auth-server
- Run database migrations automatically
- Expose the API on http://localhost:3000

4. **Verify the setup**:

```bash
# Check service health
curl http://localhost:3000/health

# Check service logs
docker-compose logs -f auth-server
```

**Accessing Services:**

- **Auth API**: http://localhost:3000
- **PostgreSQL**: localhost:5432 (user: `qauth`, password: from `.env` `DB_PASSWORD`)
- **Redis**: localhost:6379

**Running Migrations Manually:**

Migrations run automatically via the `migration-runner` service before auth-server starts. You can also run them manually:

```bash
docker-compose run --rm migration-runner
```

**Stopping Services:**

```bash
docker-compose down

# To also remove volumes (deletes all data):
docker-compose down -v
```

**Testing the Setup:**

A comprehensive test script is available to verify everything works:

```bash
# Run the test script
./scripts/test-docker.sh
```

This script will:

- Check environment configuration
- Build Docker images
- Start all services
- Run migrations
- Verify health checks
- Test API endpoints
- Verify data persistence

**Troubleshooting:**

- **Port conflicts**: If ports 3000, 5432, or 6379 are already in use, modify the port mappings in `docker-compose.yml`
- **Migration errors**: Check that PostgreSQL is healthy: `docker-compose ps`
- **JWT errors**: Ensure your JWT keys are properly formatted in `.env` (include BEGIN/END lines)
- **Build failures**: Ensure you have enough disk space and Docker has sufficient resources allocated
- **Migration runner fails**: Check logs with `docker-compose logs migration-runner`

For more details, see the [Docker documentation](./docs/docker.md).

### Auth as a Service Mode

```typescript
// Your custom domain, QAuth backend
import { QAuth } from '@qauth/core';

const auth = new QAuth({
  domain: 'auth.yourapp.com',
  mode: 'headless',
});
```

### Self-hosted Mode (Production)

```bash
# Docker deployment
docker run -p 3000:3000 qauth/auth-server

# Or with docker-compose
curl -O https://qauth.dev/docker-compose.yml
docker-compose up -d
```

## 🗺️ Roadmap

### Phase 1: Core Auth Server (completed)

- [x] Database schema design (PostgreSQL + Drizzle ORM, UUIDv7)
- [x] Multi-tenancy via Realms
- [x] Repository pattern with BaseRepository interface
- [x] Centralised error handling (@qauth/shared-errors)
- [x] Core auth server (Fastify/TypeScript)
- [x] Email/password authentication with Argon2id
- [x] OAuth 2.1 authorization code flow + PKCE
- [x] JWT issuance / refresh / revocation (EdDSA)
- [x] Token introspection (RFC 7662), OIDC userinfo
- [x] Email verification (Resend, SMTP, Mock providers)
- [x] PostgreSQL + Redis setup
- [x] Docker deployment with automated migrations

### Phase 2: Developer Portal (current)

- [ ] Developer registration/login
- [ ] Self-service OAuth client management (CRUD)
- [ ] API key management
- [ ] Federation provider configuration UI
- [ ] JavaScript / React / Node.js SDKs

### Phase 3: Production Hardening

- [ ] OIDC 1.0 conformance (OpenID Foundation test suite)
- [ ] OIDC discovery (`/.well-known/openid-configuration`) + JWKS endpoint
- [ ] ID tokens, nonce, scope handling
- [ ] Rate limiting (Redis token bucket, per-IP and per-email)
- [ ] CSRF protection, security headers (Helmet)
- [ ] Prometheus metrics, structured audit logging
- [ ] Kubernetes manifests

### Phase 4: Wallet Federation Bridge (OID4VC / SIOPv2)

- [ ] SIOPv2 authentication request handling
- [ ] OID4VC Verifiable Presentation endpoint
- [ ] Trust anchor validation (extensible: EU Trusted List and other registries)
- [ ] `federation-core` library: VC wallet → standard OAuth 2.1 / OIDC tokens
- [ ] Wallet login UI flow in `auth-ui`
- [ ] Inverse direction: QAuth as a Verifiable Credential issuer
- [ ] Integration tests against EUDI reference wallet

### Phase 5: Post-Quantum Crypto

- [ ] `@qauth/crypto`: native Node.js binding (napi-rs + aws-lc-rs)
- [ ] Hybrid composite ML-DSA-65 + Ed25519 JWT signing
- [ ] Reference-token architecture for PQC JWT size compatibility
- [ ] Crypto-agile abstraction layer (`sign` / `verify` / `generateKeyPair`)
- [ ] `@noble/post-quantum` dev/CI fallback
- [ ] Security review of cryptographic implementation

### Phase 6+: Enterprise & Scale

- [ ] Social login (Google, GitHub, Microsoft)
- [ ] WebAuthn / Passkeys, TOTP / MFA
- [ ] SAML 2.0, LDAP / Active Directory
- [ ] W3C DIDs, advanced RBAC, Organizations & Teams
- [ ] GraphQL API, webhooks, multi-region, microservices extraction

## 🧩 SDK Usage Examples

### Auth as a Service Mode

```typescript
// Installation
npm install @qauth/core

// Usage
import { QAuth } from '@qauth/core';

const auth = new QAuth({
  domain: 'auth.yourapp.com',
  projectId: 'your-project-id',
  apiKey: 'your-api-key',
});

// Sign in
const { user, session } = await auth.signInWithPassword({
  email: 'user@example.com',
  password: 'password',
});

// Sign up
await auth.signUp({
  email: 'newuser@example.com',
  password: 'securepass',
  metadata: { plan: 'pro' },
});

// Get session
const session = await auth.getSession();
```

### Self-hosted Mode

```typescript
import { QAuth } from '@qauth/core';

const auth = new QAuth({
  mode: 'self-hosted',
  baseUrl: 'https://auth.yourcompany.com',
  clientId: 'internal-app',
});

await auth.loginWithRedirect();
```

### React SDK

```typescript
import { QAuthProvider, useAuth } from '@qauth/react';

// Auth as a Service
function App() {
  return (
    <QAuthProvider
      domain="auth.yourapp.com"
      projectId="..."
      apiKey="..."
    >
      <Dashboard />
    </QAuthProvider>
  );
}

// Self-hosted
function App() {
  return (
    <QAuthProvider
      mode="self-hosted"
      baseUrl="https://auth.yourcompany.com"
      clientId="..."
    >
      <Dashboard />
    </QAuthProvider>
  );
}

// Use in components
function Dashboard() {
  const { user, login, logout, loading } = useAuth();

  if (loading) return <Spinner />;
  if (!user) return <button onClick={login}>Login</button>;

  return <div>Welcome {user.name}</div>;
}
```

## 📊 Deployment Modes

| Feature             | Auth as a Service | Self-hosted            |
| ------------------- | ----------------- | ---------------------- |
| **Setup Time**      | 15 minutes        | 1-2 hours              |
| **Infrastructure**  | None (we host)    | You manage             |
| **Custom Domain**   | ✅                | ✅                     |
| **Custom Branding** | ✅                | ✅                     |
| **Data Location**   | Our servers       | Your servers           |
| **Compliance**      | Standard          | Full control           |
| **Pricing**         | Usage-based       | Free (self-host costs) |
| **Best For**        | Startups/Products | Enterprise/Compliance  |
| **Maintenance**     | Zero              | You manage             |

### Quick Decision Guide

**Choose Auth as a Service if:**

- You need custom branding without infrastructure
- You're building a startup/product
- You want API-first headless auth
- You want to focus on your product

**Choose Self-hosted if:**

- You have compliance requirements (GDPR, HIPAA)
- You need complete data sovereignty
- You're an enterprise with existing infrastructure
- You want to avoid vendor lock-in

## 📚 Documentation

**Available Documentation:**

- [Product Requirements Document](./MVP-PRD.md) — Full phase breakdown, API specs, database schema
- [Docker Development Guide](./docs/docker.md) - Local development with Docker
- [Architecture Decision Records](./docs/adr/README.md) - Key architectural decisions

**Library Documentation:**

- [@qauth/infra-db](./libs/infra/db/README.md) - Database schema and repositories
- [@qauth/infra-cache](./libs/infra/cache/README.md) - Redis caching utilities
- [@qauth/server-config](./libs/server/config/README.md) - Environment configuration
- [@qauth/server-email](./libs/server/email/README.md) - Email service with multiple providers
- [@qauth/server-password](./libs/server/password/README.md) - Password hashing with Argon2
- [@qauth/server-jwt](./libs/server/jwt/README.md) - JWT signing and verification
- [@qauth/shared-errors](./libs/shared/errors/README.md) - Centralized error handling
- [@qauth/shared-validation](./libs/shared/validation/README.md) - Input validation utilities
- [@qauth/shared-testing](./libs/shared/testing/README.md) - Test helpers and fixtures

**Planned Documentation** (coming in future phases):

- Quick Start Guide
- API Reference
- SDK Documentation
- Authentication Flow
- Multi-tenancy Guide
- Security Best Practices

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](./CONTRIBUTING.md).

## 📄 License

Apache License 2.0 - see [LICENSE](./LICENSE) file for details.

Copyright © 2025–2026 QAuth Labs

## 🔗 Links

- [Website](https://qauth.dev)
- [Documentation](https://docs.qauth.dev)
- [Developer Portal](https://developers.qauth.dev)
- [Foundation](https://qauth.org)
- [Status Page](https://status.qauth.dev)

---

**Note**: This project is under active development. Phase 1 is complete; Phase 2 (Developer Portal) is in progress. Not yet recommended for production use.

## 🤲 Acknowledgments

Inspired by: Keycloak, Ory, Auth0, Clerk, and Supabase Auth.

Standards and prior art this project builds on: [OAuth 2.1 RFC 9700](https://datatracker.ietf.org/doc/rfc9700/), [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [OID4VC](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html), [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final), [W3C DID v1.0](https://www.w3.org/TR/did-core/).
