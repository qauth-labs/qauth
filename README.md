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

**QAuth** is an open-source identity server, designed from day one as a federation hub. Today it ships OAuth 2.1 / OIDC 1.0 with email/password authentication, both `authorization_code` (PKCE) and `client_credentials` grants, and per-client audience (`aud`) on issued JWTs. The architecture — documented across [ADR-003](./docs/adr/003-credential-provider-interface.md), [ADR-004](./docs/adr/004-wallet-agnostic-federation.md), [ADR-005](./docs/adr/005-pqc-hybrid-signing.md), and [ADR-006](./docs/adr/006-oauth-grants-and-audience.md) — is built so that wallet-based upstreams (EUDI Wallets via OID4VC / SIOPv2), external OIDC providers, and post-quantum signing algorithms slot in behind stable interfaces without changes to downstream applications. Applications integrate against QAuth's OIDC layer once.

<div align="center">
  <h3>🇪🇺 Made in Europe · 🇪🇪 Made in Estonia · 🇹🇷 Made in Türkiye</h3>
</div>

> **Status:** Early. Core OAuth 2.1 / OIDC flows are working; conformance hardening, observability, and the developer portal are in progress. See [Current Status](#-current-status-april-2026) and the [MVP milestone](https://github.com/qauth-labs/qauth/milestone/1). Not yet recommended for production use.

## 🎯 How to Use QAuth

### 1. 🏠 Self-hosted (today)

The self-hostable auth server is what ships today. Run it locally with Docker Compose in a few minutes:

```bash
# Clone and start the stack (auth-server + Postgres 18 + Redis 7)
git clone https://github.com/qauth-labs/qauth.git
cd qauth
cp .env.docker.example .env   # then add your JWT keys — see Quick Start below
docker compose up -d

# Verify
curl http://localhost:3000/health
```

You can then drive it directly via the standard OAuth 2.1 / OIDC endpoints:

```bash
# Token endpoint — authorization code + PKCE (user-context)
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=...&code_verifier=...&client_id=..."

# Token endpoint — client_credentials (service-to-service, RFC 6749 4.4)
# Client auth via HTTP Basic (client_secret_basic, RFC 6749 2.3.1)
curl -X POST http://localhost:3000/oauth/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=read:foo"
```

Interactive API docs (OpenAPI / Swagger UI) are served at `/docs` on the running instance.

**Good fit for:**

- Data sovereignty and GDPR requirements
- Self-hosted OAuth 2.1 / OIDC without the Keycloak footprint
- Organisations planning for eIDAS 2.0 wallet login as it lands (Phase 4)

### 2. ⚡ Auth as a Service _(planned)_

> 📋 **Planned — Phase 3+.** The hosted QAuth backend and `@qauth-labs/core` SDK described in the examples below are not available yet. The self-hosted path above is the supported deployment today.

```typescript
// 📋 Planned SDK surface — not yet published
import { QAuth } from '@qauth-labs/core';

const auth = new QAuth({
  domain: 'auth.yourapp.com',
  mode: 'headless',
});
```

**Target audience when available:**

- Applications that need eIDAS 2.0 EUDI Wallet login without rewriting their auth layer
- Teams that want a headless API-first backend with custom branding
- Startups that want to skip identity infrastructure entirely

## 🔐 Post-Quantum Cryptography

QAuth's PQC strategy is documented in [ADR-005](./docs/adr/005-pqc-hybrid-signing.md) and is **design-stage today**. Phase 1 signs JWTs with Ed25519; the hybrid transition is planned for Phase 5.

### Primary standard (target)

- **ML-DSA-65 (NIST FIPS 204)** — Digital signatures for JWT tokens. Level 3 (192-bit security), the minimum floor recommended by BSI (Germany) and ANSSI (France).

### Hybrid strategy (target)

Defense in depth via composite dual-signing — tokens will carry both an ML-DSA-65 and an Ed25519 signature, following the IETF LAMPS composite signatures model (`draft-ietf-lamps-pq-composite-sigs`). Both classical and post-quantum verifiers can validate without coordination.

```typescript
// ⚙️ Planned API — Phase 5 (2027 target, per ADR-005).
// @qauth-labs/crypto is not yet published. The interface below is a design
// sketch aligned with draft-prabel-jose-pq-composite-sigs.
import { signHybrid } from '@qauth-labs/crypto';

const token = await signHybrid(payload, { mlDsaKey, ed25519Key });
```

**Planned implementation:**

`@qauth-labs/crypto` will be a native Node.js binding (napi-rs) wrapping `aws-lc-rs` (AWS-LC, a production-hardened BoringSSL fork with FIPS 140-3 validation in progress). This follows the same pattern as `@node-rs/argon2` — prebuilt binaries per platform, no build tooling required for consumers. `@noble/post-quantum` (pure TypeScript, audited) is planned as the fallback for development environments and CI.

ADR-005 specifies a `libs/core/crypto` abstraction that will expose algorithm-agnostic `sign` / `verify` / `generateKeyPair` interfaces so that business logic is never coupled to a specific implementation. Swapping the underlying library will require no changes to the auth server.

**Token size considerations:**

ML-DSA-65 signatures are 3,309 bytes vs. Ed25519's 64 bytes. QAuth's architecture is being designed to default to **reference tokens with introspection** (RFC 7662) rather than large self-contained JWTs — mitigating HTTP header limits and cookie size constraints during the PQC transition period.

**Migration timeline:**

- **Phase 1** (in progress): Ed25519 / EdDSA for JWT signatures, plus crypto-agile interfaces
- **Phase 5** (2027 target): Hybrid composite ML-DSA-65 + Ed25519 (JOSE WG draft adopted Jan 2026)
- **Future**: FN-DSA (NIST FIPS 206, pending) evaluation — compact signatures (~666 B) may make self-contained PQC JWTs practical

## 🎯 Vision

A federated identity hub for the next generation of the internet:

- **Federation-first** — a single `federation-core` layer will normalise upstream identity (Verifiable Credential wallets, email/password, external OIDC providers, W3C DIDs) into a common internal model; downstream applications see standard OIDC tokens regardless of source
- **Wallet-agnostic** — any standards-compliant VC wallet (OID4VC / SIOPv2) will be a valid upstream; EUDI Wallet under eIDAS 2.0 is one concrete deployment target, not the only one
- **Post-quantum ready** — crypto-agile architecture with a clear ML-DSA-65 hybrid transition path, designed so algorithm upgrades never touch application business logic
- **Headless-first** — API-first, bring your own branded UI
- **Standards compliant** — OAuth 2.1 (RFC 9700), OIDC 1.0, OID4VC, SIOPv2, W3C DID, NIST FIPS 204
- **Open and self-hostable** — Apache 2.0, no telemetry, runs anywhere

## 📍 Current Status (April 2026)

QAuth is **early and not yet production-ready**. An honest snapshot:

**✅ Working today**

- OAuth 2.1 authorization code flow with mandatory PKCE
- OIDC 1.0 userinfo + token introspection (RFC 7662)
- Email/password registration with Argon2id hashing
- JWT issuance, refresh, revocation (Ed25519)
- Email verification (Resend / SMTP / Mock providers)
- Multi-tenancy via Realms for data isolation
- PostgreSQL 18 + Redis 7 with Docker Compose
- OpenAPI / Swagger UI at `/docs`
- Phase 1.7 test coverage for JWT middleware, introspect, and userinfo

**🚧 In progress**

- Developer portal skeleton (Phase 2)
- OIDC conformance items: ID tokens, nonce, scope/claims handling
- Structured logging (pino), Prometheus metrics, rate limiting
- Full OIDC discovery endpoint + JWKS

**📋 Designed but not yet implemented**

- Wallet federation (OID4VC / SIOPv2) — architecture in [ADR-004](./docs/adr/004-wallet-agnostic-federation.md)
- Post-quantum hybrid signing — roadmap in [ADR-005](./docs/adr/005-pqc-hybrid-signing.md)
- `@qauth-labs/crypto` native binding package
- SDKs (`@qauth-labs/core`, `@qauth-labs/react`, `@qauth-labs/node`)
- `auth-ui` (brandable login UI) and `admin-panel`

**Tracking:** [MVP milestone](https://github.com/qauth-labs/qauth/milestone/1) · [ADR index](./docs/adr/README.md) · [MVP-PRD](./MVP-PRD.md)

## 🏗️ Architecture

### Phase 1: Modular Monolith (TypeScript)

```
┌──────────────────────────────────────────────────────┐
│              Auth Server (TypeScript/Node.js)        │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │  API Layer (REST)                              │  │
│  │  OAuth 2.1 · OIDC 1.0 (✅)                     │  │
│  │  OID4VC · SIOPv2 (📋 Phase 4)                  │  │
│  └────────────────────────────────────────────────┘  │
│                          ↓                           │
│  ┌────────────────────────────────────────────────┐  │
│  │  federation-core  (📋 Phase 2/4)               │  │
│  │  • Upstream normalisation (VC wallet / OIDC /  │  │
│  │    password → internal user model)             │  │
│  │  • Downstream token issuance                   │  │
│  └────────────────────────────────────────────────┘  │
│                          ↓                           │
│  ┌────────────────────────────────────────────────┐  │
│  │  Crypto Layer                                  │  │
│  │  • JWT signing / verification                  │  │
│  │      ✅ Ed25519 via `jose`                     │  │
│  │      📋 Phase 5 — native bindings via napi-rs  │  │
│  │  • Password hashing ✅ Argon2id (@node-rs)     │  │
│  │  • DID resolution 📋 Phase 6+                  │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
              ↓                           ↓
        PostgreSQL 18                  Redis 7
```

### Phase 6+: Microservices extraction (when needed)

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

Legend: ✅ implemented · 🚧 in progress · 📋 planned

```
qauth/
├── apps/
│   ├── auth-server/          ✅ Fastify OAuth 2.1 / OIDC 1.0 server
│   ├── developer-portal/     🚧 skeleton scaffolded (PR #137); Phase 2
│   ├── migration-runner/     ✅ Drizzle migrations runner
│   ├── auth-ui/              📋 planned — brandable login UI, Phase 2/4
│   └── admin-panel/          📋 planned — Phase 6+
│
├── libs/
│   ├── server/
│   │   ├── config/           ✅ environment config + Zod validation
│   │   ├── jwt/              ✅ EdDSA signing / verification via `jose`
│   │   ├── password/         ✅ Argon2id via @node-rs/argon2
│   │   ├── pkce/             ✅ PKCE utilities
│   │   ├── email/            ✅ Resend / SMTP / Mock providers
│   │   └── federation/       📋 CredentialProvider interface (ADR-003)
│   │                         #     password.provider.ts, wallet.provider.ts
│   │                         #     Normalises upstream → VerifiedIdentity
│   │
│   ├── fastify/plugins/      ✅ db · cache · email · jwt · password · pkce
│   ├── infra/
│   │   ├── db/               ✅ PostgreSQL 18 + Drizzle ORM, repository pattern
│   │   └── cache/            ✅ Redis 7 connection + caching utilities
│   │
│   ├── shared/
│   │   ├── errors/           ✅ centralised error classes
│   │   ├── validation/       ✅ email / password validation utilities
│   │   └── testing/          ✅ test helpers and fixtures
│   │
│   ├── ui/                   ✅ shared React primitives (early)
│   │
│   ├── core/                 📋 planned extraction (ADR-005)
│   │   ├── oauth/            #   currently inlined in apps/auth-server
│   │   ├── oidc/             #   currently inlined in apps/auth-server
│   │   └── crypto/           #   @qauth-labs/crypto — napi-rs + aws-lc-rs (Phase 5)
│   │                         #     @noble/post-quantum dev/CI fallback
│   │
│   └── sdk/                  📋 planned — Phase 3
│       ├── js/               #   Vanilla JS SDK
│       ├── react/            #   React SDK + hooks
│       └── node/             #   Server-side SDK
│
└── services/                 📋 planned microservices — Phase 6+
    ├── token-service/        #   Token generation (gRPC)
    └── session-service/      #   Session management (gRPC)
```

## 🚀 Features

### Phase 1 — Core Auth Server (core flows complete; conformance & ops in progress)

> **Status:** Core OAuth 2.1 / OIDC flows work end-to-end with Ed25519 JWTs, Argon2id, PKCE, and multi-tenancy via Realms. The MVP milestone tracks at **43 of 95 issues closed**. The remaining Phase 1 work is OIDC conformance detail (ID tokens, nonce, claims), Prometheus + structured logging, rate limiting, and the developer-portal Dockerfile. See the [MVP milestone](https://github.com/qauth-labs/qauth/milestone/1).

**Core authentication (working today):**

- OAuth 2.1 / OpenID Connect 1.0 authorization code flow
- OAuth 2.1 `client_credentials` grant for service-to-service auth (RFC 6749 4.4)
- Client authentication via `client_secret_post` and `client_secret_basic` (RFC 6749 2.3.1)
- Email/password authentication with Argon2id hashing
- JWT token issuance with `aud` and `scope` claims, refresh, and revocation (Ed25519 / EdDSA)
- Token introspection (RFC 7662)
- OIDC userinfo endpoint
- Multi-tenancy via Realms for complete data isolation
- Mandatory PKCE on all authorization code flows

**Infrastructure (working today):**

- Email verification — Resend, SMTP, and Mock providers
- PostgreSQL 18 + Redis 7
- Docker deployment with automated migrations and health checks
- Structured audit logging (basic)

**Developer tools:**

- REST API (OAuth 2.1 / OIDC endpoints) ✅
- OpenAPI / Swagger UI at `/docs` ✅
- Self-service developer portal 🚧 (Phase 2)
- TypeScript / React / Node.js SDKs 📋 (Phase 3)

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

- `@qauth-labs/crypto`: native Node.js binding (napi-rs + aws-lc-rs)
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
- **Password hashing**: `@node-rs/argon2` (Rust native binding, Argon2id)
- **JWT (today)**: `jose` (Ed25519 / EdDSA)
- **Crypto (planned, ADR-005)**: `@qauth-labs/crypto` — native Node.js binding (napi-rs + aws-lc-rs); `@noble/post-quantum` in dev/CI

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
- **Orchestration**: Kubernetes ready (manifests planned, Phase 3)
- **Observability**: OpenTelemetry (planned, Phase 3)
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
docker compose up -d
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

# Browse interactive API docs
open http://localhost:3000/docs

# Check service logs
docker compose logs -f auth-server
```

**Accessing Services:**

- **Auth API**: http://localhost:3000
- **API docs (OpenAPI / Swagger UI)**: http://localhost:3000/docs
- **PostgreSQL**: localhost:5432 (user: `qauth`, password: from `.env` `DB_PASSWORD`)
- **Redis**: localhost:6379

**Running Migrations Manually:**

Migrations run automatically via the `migration-runner` service before auth-server starts. You can also run them manually:

```bash
docker compose run --rm migration-runner
```

**Stopping Services:**

```bash
docker compose down

# To also remove volumes (deletes all data):
docker compose down -v
```

**Testing the Setup:**

A comprehensive test script is available to verify everything works:

```bash
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
- **Migration errors**: Check that PostgreSQL is healthy: `docker compose ps`
- **JWT errors**: Ensure your JWT keys are properly formatted in `.env` (include BEGIN/END lines)
- **Build failures**: Ensure you have enough disk space and Docker has sufficient resources allocated
- **Migration runner fails**: Check logs with `docker compose logs migration-runner`

For more details, see the [Docker documentation](./docs/docker.md).

### Self-hosted Mode (Production)

> ⚠️ Not yet recommended for production. Phase 3 (production hardening — rate limiting, security headers, metrics, Kubernetes manifests, OIDC conformance) is required before any production deployment.

```bash
# Docker deployment (once tagged images are published)
docker run -p 3000:3000 qauth/auth-server

# Or with docker-compose
curl -O https://qauth.dev/docker-compose.yml
docker compose up -d
```

## 🗺️ Roadmap

### Phase 1: Core Auth Server (core flows complete; conformance & ops in progress)

- [x] Database schema design (PostgreSQL + Drizzle ORM, UUIDv7)
- [x] Multi-tenancy via Realms
- [x] Repository pattern with BaseRepository interface
- [x] Centralised error handling (@qauth-labs/shared-errors)
- [x] Core auth server (Fastify/TypeScript)
- [x] Email/password authentication with Argon2id
- [x] OAuth 2.1 authorization code flow + PKCE
- [x] JWT issuance / refresh / revocation (EdDSA)
- [x] Token introspection (RFC 7662), OIDC userinfo
- [x] Email verification (Resend, SMTP, Mock providers)
- [x] PostgreSQL + Redis setup
- [x] Docker deployment with automated migrations
- [x] OpenAPI / Swagger UI docs
- [ ] OIDC 1.0 ID tokens, nonce, scope/claims handling
- [ ] Structured logging (pino) + Prometheus metrics
- [ ] Rate limiting (Redis token bucket)

### Phase 2: Developer Portal (current)

- [ ] Developer registration / login
- [ ] Self-service OAuth client management (CRUD)
- [ ] API key management
- [ ] Federation provider configuration UI

### Phase 3: Production Hardening & SDKs

- [ ] OIDC 1.0 conformance (OpenID Foundation test suite)
- [ ] OIDC discovery (`/.well-known/openid-configuration`) + JWKS endpoint
- [ ] CSRF protection, security headers (Helmet)
- [ ] Kubernetes manifests
- [ ] JavaScript / React / Node.js SDKs (`@qauth-labs/core`, `@qauth-labs/react`, `@qauth-labs/node`)

### Phase 4: Wallet Federation Bridge (OID4VC / SIOPv2)

- [ ] SIOPv2 authentication request handling
- [ ] OID4VC Verifiable Presentation endpoint
- [ ] Trust anchor validation (extensible: EU Trusted List and other registries)
- [ ] `federation-core` library: VC wallet → standard OAuth 2.1 / OIDC tokens
- [ ] Wallet login UI flow in `auth-ui`
- [ ] Inverse direction: QAuth as a Verifiable Credential issuer
- [ ] Integration tests against EUDI reference wallet

### Phase 5: Post-Quantum Crypto

- [ ] `@qauth-labs/crypto`: native Node.js binding (napi-rs + aws-lc-rs)
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

## 🧩 Planned SDK Usage (Phase 3)

> 📋 **Not yet published.** The SDK packages (`@qauth-labs/core`, `@qauth-labs/react`, `@qauth-labs/node`) are planned for Phase 3. The examples below show the intended API surface — they will not work until the packages are released. For Phase 1 integration today, call the OAuth 2.1 / OIDC endpoints directly (see `/docs` on a running instance).

### Auth as a Service Mode _(planned)_

```typescript
// 📋 Planned — not yet published
npm install @qauth-labs/core

import { QAuth } from '@qauth-labs/core';

const auth = new QAuth({
  domain: 'auth.yourapp.com',
  projectId: 'your-project-id',
  apiKey: 'your-api-key',
});

const { user, session } = await auth.signInWithPassword({
  email: 'user@example.com',
  password: 'password',
});

await auth.signUp({
  email: 'newuser@example.com',
  password: 'securepass',
  metadata: { plan: 'pro' },
});

const session = await auth.getSession();
```

### Self-hosted Mode _(planned)_

```typescript
// 📋 Planned — not yet published
import { QAuth } from '@qauth-labs/core';

const auth = new QAuth({
  mode: 'self-hosted',
  baseUrl: 'https://auth.yourcompany.com',
  clientId: 'internal-app',
});

await auth.loginWithRedirect();
```

### React SDK _(planned)_

```typescript
// 📋 Planned — not yet published
import { QAuthProvider, useAuth } from '@qauth-labs/react';

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

function Dashboard() {
  const { user, login, logout, loading } = useAuth();

  if (loading) return <Spinner />;
  if (!user) return <button onClick={login}>Login</button>;

  return <div>Welcome {user.name}</div>;
}
```

## 📊 Deployment Modes

| Feature             | Self-hosted (today)    | Auth as a Service _(planned)_ |
| ------------------- | ---------------------- | ----------------------------- |
| **Availability**    | ✅ Today (early)       | 📋 Phase 3+                   |
| **Setup Time**      | ~15 min with Docker    | 15 minutes                    |
| **Infrastructure**  | You manage             | None (hosted)                 |
| **Custom Domain**   | ✅                     | ✅                            |
| **Custom Branding** | ✅                     | ✅                            |
| **Data Location**   | Your servers           | Our servers                   |
| **Compliance**      | Full control           | Standard                      |
| **Pricing**         | Free (self-host costs) | Usage-based                   |
| **Best For**        | Enterprise/Compliance  | Startups/Products             |
| **Maintenance**     | You manage             | Zero                          |

### Quick Decision Guide

**Self-hosted fits if:**

- You have compliance requirements (GDPR, HIPAA, eIDAS 2.0)
- You need complete data sovereignty
- You're an enterprise with existing infrastructure
- You want to avoid vendor lock-in

**Auth as a Service will fit (when available) if:**

- You need custom branding without running infrastructure
- You're building a startup / product
- You want API-first headless auth
- You want to focus on your product, not identity plumbing

## 📚 Documentation

**Available documentation:**

- [Product Requirements Document](./MVP-PRD.md) — full phase breakdown, API specs, database schema
- [Docker Development Guide](./docs/docker.md) — local development with Docker
- [Architecture Decision Records](./docs/adr/README.md) — key architectural decisions
- **API docs** (OpenAPI / Swagger UI) — served at `/docs` on the running instance

**Library documentation:**

- [@qauth-labs/infra-db](./libs/infra/db/README.md) — database schema and repositories
- [@qauth-labs/infra-cache](./libs/infra/cache/README.md) — Redis caching utilities
- [@qauth-labs/server-config](./libs/server/config/README.md) — environment configuration
- [@qauth-labs/server-email](./libs/server/email/README.md) — email service with multiple providers
- [@qauth-labs/server-password](./libs/server/password/README.md) — password hashing with Argon2id
- [@qauth-labs/server-jwt](./libs/server/jwt/README.md) — JWT signing and verification
- [@qauth-labs/shared-errors](./libs/shared/errors/README.md) — centralized error handling
- [@qauth-labs/shared-validation](./libs/shared/validation/README.md) — input validation utilities
- [@qauth-labs/shared-testing](./libs/shared/testing/README.md) — test helpers and fixtures

**Planned documentation** (future phases):

- Quick Start Guide (external site)
- API Reference
- SDK Documentation (Phase 3)
- Authentication Flow guide
- Multi-tenancy Guide
- Security Best Practices

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](./CONTRIBUTING.md).

## 📄 License

Apache License 2.0 — see [LICENSE](./LICENSE) file for details.

Copyright © 2025–2026 QAuth Labs

## 🔗 Links

- [Website](https://qauth.dev)
- [Documentation](https://docs.qauth.dev)
- [Developer Portal](https://developers.qauth.dev)
- [Foundation](https://qauth.org)
- [Status Page](https://status.qauth.dev)

---

**Note:** This project is under active development. Phase 1 core flows work; Phase 1 conformance, observability, and Phase 2 (Developer Portal) are in progress. **Not yet recommended for production use.**

## 🤲 Acknowledgments

Inspired by: Keycloak, Ory, Auth0, Clerk, and Supabase Auth.

Standards and prior art this project builds on: [OAuth 2.1 RFC 9700](https://datatracker.ietf.org/doc/rfc9700/), [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [OID4VC](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html), [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final), [W3C DID v1.0](https://www.w3.org/TR/did-core/).
