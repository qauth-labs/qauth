# QAuth

> Post-quantum ready, headless-first identity platform. A developer-friendly alternative to Keycloak.

**QAuth** is a modern, open-source authentication platform that provides flexible deployment modes with post-quantum cryptography built-in from day one.

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

- Startups wanting auth without infrastructure
- Custom branding requirements
- API-first applications

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

- Enterprise compliance requirements
- Data sovereignty needs
- Complete customization control

## 🔐 Post-Quantum Cryptography

QAuth implements a security-first hybrid approach with NIST-standardized post-quantum algorithms.

### Primary Standards (NIST 2024)

- **ML-DSA (Dilithium3)** - Digital signatures
- **ML-KEM (Kyber)** - Key exchange
- **SLH-DSA (SPHINCS+)** - Backup signatures

### Hybrid Strategy

Defense in depth with dual protection:

```typescript
// Hybrid PQC JWT signing (future)
const token = await signJWT(payload, {
  algorithm: 'hybrid-mldsa-ed25519',
  primary: 'ML-DSA-65',
  fallback: 'Ed25519',
});
```

**Implementation:**

Uses Node.js 24.7.0+ built-in PQC support via `node:crypto` WebCrypto API:

```typescript
// Hybrid PQC JWT signing (Phase 7: 2027)
import { webcrypto } from 'node:crypto';
import { SignJWT, generateKeyPair } from 'jose'; // Ed25519 fallback

// Generate ML-DSA key pair (Node.js built-in)
const mlDsaKeyPair = await webcrypto.subtle.generateKey({ name: 'ML-DSA-65' }, true, [
  'sign',
  'verify',
]);

// Generate Ed25519 key pair (jose)
const { publicKey: ed25519PublicKey, privateKey: ed25519PrivateKey } =
  await generateKeyPair('EdDSA');

// Hybrid signing: Both ML-DSA + Ed25519 signatures
const pqcSignature = await webcrypto.subtle.sign('ML-DSA-65', mlDsaKeyPair.privateKey, message);
const classicalSignature = await new SignJWT(payload)
  .setProtectedHeader({ alg: 'EdDSA' })
  .sign(ed25519PrivateKey);
```

**Migration Timeline:**

- **2026**: Ed25519 for JWT signatures (MVP)
- **2027**: Hybrid ML-DSA + Ed25519 transition
- **2028**: Pure PQC evaluation

## 🎯 Vision

A modern, developer-first alternative to Keycloak:

- **Headless-first** - API-first architecture, use any UI
- **Modern Stack** - TypeScript with native performance
- **Developer Experience** - Simple setup, excellent DX
- **Standards Compliant** - OAuth 2.1, OIDC 1.0, PKCE
- **Production Ready** - Security-first, scalable
- **Flexible Deployment** - Cloud, self-hosted, or hybrid

## 🏗️ Architecture

### Phase 1: Modular Monolith (TypeScript)

```
┌────────────────────────────────────────────────┐
│         Auth Server (TypeScript/Node.js)       │
│                                                │
│  ┌──────────────────────────────────────────┐  │
│  │  API Layer (REST)                        │  │
│  └──────────────────────────────────────────┘  │
│                      ↓                         │
│  ┌──────────────────────────────────────────┐  │
│  │  Business Logic Modules                  │  │
│  │  • Auth Module                           │  │
│  │  • User Module                           │  │
│  │  • Client Module                         │  │
│  │  • Session Module                        │  │
│  └──────────────────────────────────────────┘  │
│                      ↓                         │
│  ┌──────────────────────────────────────────┐  │
│  │  Performance Layer (Native Bindings)     │  │
│  │  • Crypto operations (JWT, hashing)      │  │
│  │  • Token validation                      │  │
│  │  • Password verification                 │  │
│  └──────────────────────────────────────────┘  │
└────────────────────────────────────────────────┘
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
│   ├── auth-server/          # Core auth server (Fastify)
│   ├── developer-portal/     # Developer console (TanStack Start)
│   ├── auth-ui/              # Login/Register UI (TanStack Start, SPA)
│   └── admin-panel/          # Admin dashboard (TanStack Start)
│
├── libs/
│   ├── core/
│   │   ├── auth/             # Auth business logic (TS)
│   │   ├── oauth/            # OAuth 2.1 implementation (TS)
│   │   ├── oidc/             # OIDC implementation (TS)
│   │   └── (Native crypto via npm packages: @node-rs/argon2, jose)
│   │
│   ├── sdk/
│   │   ├── js/               # Vanilla JS SDK
│   │   ├── react/            # React SDK + hooks
│   │   └── node/             # Server-side SDK
│   │
│   ├── data-access/
│   │   ├── db/               # Drizzle ORM schema, queries & repositories
│   │   └── cache/            # Redis client & caching utilities
│   │
│   ├── common/
│   │   └── errors/           # Centralized error classes & utilities
│   │
│   ├── server/
│   │   ├── config/           # Environment configuration & validation
│   │   ├── password/         # Password hashing (Argon2) with factory pattern
│   │   └── validation/       # Password & email validation with factory pattern
│   │
│   ├── fastify-plugin/
│   │   ├── db/               # Fastify plugin for database
│   │   ├── cache/            # Fastify plugin for Redis cache
│   │   └── password/         # Fastify plugin for password hashing & validation
│   │
│   ├── ui/
│   │   └── components/       # Shared React components
│   │
│   ├── proto/                # gRPC/Protobuf definitions (future)
│   │   ├── token.proto
│   │   └── session.proto
│   │
│   └── shared/
│       ├── types/            # Shared TypeScript types
│       ├── utils/            # Utilities
│       └── constants/        # Constants
│
└── services/                 # Future microservices (TypeScript, Rust optional)
    ├── token-service/        # Token generation (gRPC)
    └── session-service/      # Session management (gRPC)
```

## 🚀 Features

### MVP (Q1 2026)

**Core Authentication:**

- OAuth 2.1 / OpenID Connect 1.0 support
- Email/Password authentication
- JWT token management
- Session management
- Multi-tenancy (Realms) for data isolation
- Role-based access control (RBAC)
- Rate limiting
- Audit logging

**Developer Tools:**

- Developer portal
- Client app management
- REST API
- Basic documentation
- TypeScript SDK

**Deployment:**

- Docker deployment
- Self-hosted support
- PostgreSQL + Redis

### Post-MVP (Q2+ 2026)

**Advanced Authentication:**

- Social login (Google, GitHub, Microsoft)
- Multi-factor authentication (TOTP, SMS)
- WebAuthn / Passkeys
- Magic link authentication

**Enterprise Features:**

- SAML 2.0 support
- LDAP/Active Directory integration
- Advanced multi-tenancy features (custom domains, tenant management UI)
- Custom domains
- Organizations & Teams
- Advanced RBAC

**Platform:**

- Webhook notifications
- Usage metrics and analytics
- Custom branding support
- High availability
- Multi-region support
- GraphQL API

## 🛠️ Technology Stack

**Backend:**

- **Runtime**: Node.js 24.7.0+ LTS (PQC support via built-in WebCrypto API)
- **Language**: TypeScript (Native bindings: npm packages like @node-rs/argon2, jose)
- **Framework**: Fastify
- **API**: REST (OAuth 2.1/OIDC)
- **ORM**: Drizzle ORM
- **Database**: PostgreSQL
- **Cache/Session**: Redis

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

- **Monorepo**: Nx 22.1.3
- **Package Manager**: pnpm
- **Containerization**: Docker
- **Orchestration**: Kubernetes ready
- **Observability**: OpenTelemetry
- **Cache/Session**: Redis with ioredis

**Performance Critical (Native Bindings):**

- Crypto operations (JWT, password hashing)
- Token validation
- High-throughput encoding/decoding

## 🚀 Quick Start

### Auth as a Service Mode

```typescript
// Your custom domain, QAuth backend
import { QAuth } from '@qauth/core';

const auth = new QAuth({
  domain: 'auth.yourapp.com',
  mode: 'headless',
});
```

### Self-hosted Mode

```bash
# Docker deployment
docker run -p 3000:3000 qauth/auth-server

# Or with docker-compose
curl -O https://qauth.dev/docker-compose.yml
docker-compose up -d
```

## 🗺️ Roadmap

### Phase 1: Foundation (MVP) - Q1 2026

- [x] Database schema design (PostgreSQL + Drizzle ORM)
- [x] Initial database migration created
- [x] Multi-tenancy support (Realms)
- [x] Repository pattern implementation with BaseRepository interface
- [x] Centralized error handling library (@qauth/shared-errors)
- [ ] Core auth server (TypeScript/Fastify)
- [ ] Email/Password authentication
- [ ] OAuth 2.1 flows (Authorization Code + PKCE)
- [ ] PostgreSQL + Redis setup
- [ ] Basic REST API
- [x] Native crypto modules (@node-rs/argon2, jose)

### Phase 2: Developer Portal - Q2 2026

- [ ] Developer registration/login
- [ ] Client app management (CRUD)
- [ ] API keys & secrets
- [ ] Basic documentation
- [ ] JavaScript/TypeScript SDK

### Phase 3: Production Ready - Q3 2026

- [ ] OIDC 1.0 compliance
- [ ] Social login providers
- [ ] Multi-factor authentication (TOTP)
- [ ] Audit logs
- [ ] Rate limiting
- [ ] Monitoring & alerts

### Phase 4: Advanced Features - Q4 2026

- [ ] WebAuthn / Passkeys
- [ ] SAML 2.0 support
- [ ] Organizations & Teams
- [ ] Advanced RBAC
- [ ] Advanced multi-tenancy (custom domains, tenant management UI)
- [ ] Microservices extraction (Token service, TypeScript)

### Phase 5: Scale & Optimize - 2027

- [ ] Session service microservice (TypeScript, Rust optional for extreme scale)
- [ ] Global CDN integration
- [ ] Advanced analytics
- [ ] GraphQL API
- [ ] Enterprise features
- [ ] Multi-region support

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

**Getting Started:**

- [Quick Start Guide](./docs/quick-start.md)
- [Architecture Overview](./docs/architecture.md)
- [Setup Guide](./docs/setup.md)

**Deployment Modes:**

- [Auth as a Service Mode](./docs/auth-service.md)
- [Self-hosted Mode](./docs/self-hosted.md)

**Technical Documentation:**

- [Authentication Flow](./docs/authentication.md)
- [API Reference](./docs/api.md)
- [SDK Documentation](./docs/sdk.md)
- [Hybrid Architecture](./docs/hybrid-architecture.md)

**Advanced Topics:**

- [Multi-tenancy](./docs/multi-tenancy.md)
- [Custom Domains](./docs/custom-domains.md)
- [Migration Guide](./docs/migration.md)
- [Security Best Practices](./docs/security.md)

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](./CONTRIBUTING.md).

## 📄 License

Apache License 2.0 - see [LICENSE](./LICENSE) file for details.

Copyright © 2025 QAuth Labs

## 🔗 Links

- [Website](https://qauth.dev)
- [Documentation](https://docs.qauth.dev)
- [Developer Portal](https://developers.qauth.dev)
- [Foundation](https://qauth.org)
- [Status Page](https://status.qauth.dev)

---

**Note**: This project is under active development and is not yet ready for production use.

## 🤲 Acknowledgments

Inspired by: Keycloak, Ory, Auth0, Clerk, and Supabase Auth.
