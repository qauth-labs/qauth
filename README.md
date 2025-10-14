# QAuth

> Post-quantum ready, headless-first identity platform. A developer-friendly alternative to Keycloak.

**QAuth** is a modern, open-source authentication platform that provides flexible deployment modes to fit any use case, with post-quantum cryptography built-in from day one.

## 🎯 How to Use QAuth

### 1. ⚡ Auth as a Service (Headless Backend)

Like Supabase Auth or Auth0 - use QAuth's hosted backend with your own branded UI and domain.

```typescript
// Your branded login page, QAuth backend
const auth = new QAuth({
  domain: 'auth.yourapp.com', // Your custom domain
  mode: 'headless',
});
```

**Perfect for:**

- Startups wanting auth without infrastructure
- Custom branding requirements
- API-first applications

### 2. 🏠 Self-hosted (Full Control)

Like Keycloak or AuthJS - deploy QAuth on your own infrastructure with complete control.

```bash
# Docker deployment
docker run -p 3000:3000 qauth/auth-server

# Or Kubernetes
kubectl apply -f qauth-k8s.yaml
```

**Perfect for:**

- Enterprise compliance requirements
- Data sovereignty needs
- Complete customization control

## 🔐 Post-Quantum Cryptography

QAuth is **quantum-ready** from day one, implementing security-first hybrid approach with NIST-standardized post-quantum algorithms.

### **Primary Standards (NIST 2024)**

- ✅ **ML-DSA (Dilithium3)** - Digital signatures (primary)
- ✅ **ML-KEM (Kyber)** - Key exchange
- ✅ **SLH-DSA (SPHINCS+)** - Backup signatures

### **Security-First Hybrid Strategy**

**Defense in depth** - we use **hybrid post-quantum cryptography**:

```typescript
// Hybrid PQC JWT signing
const token = await signJWT(payload, {
  algorithm: 'hybrid-mldsa-ed25519',
  primary: 'ML-DSA-65', // PQC primary
  fallback: 'Ed25519', // Classical fallback
});
```

**Security Benefits:**

- 🛡️ **Quantum-safe** (NIST primary standard)
- 🔒 **Defense in depth** (dual protection)
- 📈 **Risk mitigation** (PQC + classical backup)
- 🚀 **Future-proof** (ready for pure PQC transition)

**Implementation:**

```rust
// libs/core/crypto-wasm/src/lib.rs
use pqcrypto_mldsa::dilithium3::*;
use ed25519_dalek::{SigningKey, VerifyingKey};

pub struct HybridSigner {
    pqc_keypair: (PublicKey, SecretKey),
    classical_keypair: (SigningKey, VerifyingKey),
}

impl HybridSigner {
    pub fn sign_hybrid(&self, message: &[u8]) -> HybridSignature {
        let pqc_sig = sign(message, &self.pqc_keypair.1);
        let classical_sig = self.classical_keypair.0.sign(message);

        HybridSignature {
            pqc: pqc_sig,
            classical: classical_sig,
        }
    }
}
```

**Migration Timeline:**

- **2026**: Hybrid ML-DSA + Ed25519 for JWT signatures
- **2027**: Data-driven decision (pure PQC if mature)
- **2028**: Gradual transition based on real-world validation

## 🎯 Vision

A modern, developer-first alternative to Keycloak:

- ✅ **Headless-first** - API-first architecture, use any UI you want
- ✅ **Modern Stack** - TypeScript + Rust hybrid
- ✅ **Developer Experience** - Excellent DX, simple setup
- ✅ **Standards Compliant** - OAuth 2.1, OIDC 1.0, PKCE
- ✅ **Production Ready** - Security-first, scalable
- ✅ **Flexible Deployment** - Cloud, self-hosted, or hybrid

Whatever your needs, QAuth adapts to you:

- Avoid building user registration and login systems from scratch
- Use OAuth 2.0 / OpenID Connect protocols out of the box
- Manage client applications through the developer portal
- Deploy on our cloud, your cloud, or on-premise

## 🏗️ Architecture

**Modular Monolith → Microservices Evolution Strategy**

### Phase 1: Modular Monolith (TypeScript + Rust WASM)

```
┌────────────────────────────────────────────────┐
│         Auth Server (TypeScript/Bun)           │
│                                                │
│  ┌──────────────────────────────────────────┐  │
│  │  API Layer (GraphQL + REST)              │  │
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
│  │  Performance Layer (Rust WASM)           │  │
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
│  • GraphQL           │
│  • REST              │
└──────────────────────┘
          ↓ gRPC
    ┌─────┴─────┬─────────────┬──────────────┐
    ↓           ↓             ↓              ↓
┌────────┐ ┌─────────┐ ┌──────────┐ ┌─────────────┐
│ Auth   │ │ Token   │ │ Session  │ │ Developer   │
│ (TS)   │ │ (Rust)  │ │ (Rust)   │ │ Portal (TS) │
└────────┘ └─────────┘ └──────────┘ └─────────────┘
```

### Nx Monorepo Structure

```
qauth/
├── apps/
│   ├── auth-server/          # Core auth server (Fastify)
│   ├── developer-portal/     # Developer console (TanStack Start)
│   ├── auth-ui/              # Login/Register UI (TanStack Start, SPA mode)
│   └── admin-panel/          # Admin dashboard (TanStack Start)
│
├── libs/
│   ├── core/
│   │   ├── auth/             # Auth business logic (TS)
│   │   ├── oauth/            # OAuth 2.1 implementation (TS)
│   │   ├── oidc/             # OIDC implementation (TS)
│   │   └── crypto-wasm/      # Crypto operations (Rust → WASM)
│   │
│   ├── sdk/
│   │   ├── js/               # Vanilla JS SDK
│   │   ├── react/            # React SDK + hooks
│   │   └── node/             # Server-side SDK
│   │
│   ├── data-access/
│   │   ├── db/               # Drizzle ORM schema & queries
│   │   └── redis/            # Redis client
│   │
│   ├── ui/
│   │   └── components/       # Shared React components
│   │
│   ├── proto/                # gRPC/Protobuf definitions
│   │   ├── token.proto
│   │   └── session.proto
│   │
│   └── shared/
│       ├── types/            # Shared TypeScript types
│       ├── utils/            # Utilities
│       └── constants/        # Constants
│
└── services/                 # Future microservices (Rust)
    ├── token-service/        # Token generation (gRPC)
    └── session-service/      # Session management (gRPC)
```

## 🚀 Features

### Core Authentication Features (All Modes)

- ✅ OAuth 2.1 / OpenID Connect 1.0 support
- ✅ Email/Password authentication
- ✅ Social login (Google, GitHub, etc.)
- ✅ Multi-factor authentication (MFA)
- ✅ WebAuthn / Passkeys
- ✅ Role-based access control (RBAC)
- ✅ Session management
- ✅ JWT token management

### Auth as a Service Mode Features

- ✅ Multi-tenancy support
- ✅ Custom domains (auth.yourapp.com)
- ✅ White-label authentication
- ✅ Headless REST API (bring your own UI)
- ✅ Webhook notifications
- ✅ Usage metrics and analytics
- ✅ Developer portal with GraphQL API
- ✅ OAuth 2.1 & OIDC compliant endpoints

### Self-hosted Mode Features

- ✅ Docker + Kubernetes deployment
- ✅ Complete data ownership
- ✅ On-premise installation
- ✅ Custom extensions & plugins
- ✅ LDAP/Active Directory integration
- ✅ Air-gapped environment support
- ✅ Migration tools from other platforms

### Platform Features (All Modes)

- ✅ Audit logging
- ✅ Rate limiting
- ✅ Custom branding support
- ✅ High performance (Rust WASM)
- ✅ OpenTelemetry observability
- ✅ TypeScript SDKs

## 🛠️ Technology Stack

**Backend:**

- **Runtime**: Node.js 24 LTS (active October 28, 2025)
- **Language**: TypeScript + Rust (WASM)
- **Framework**: Fastify (high performance)
- **API**: REST (OAuth 2.1/OIDC) + GraphQL (Developer Portal)
- **ORM**: Drizzle ORM (lightweight, type-safe)
- **Database**: PostgreSQL
- **Cache/Session**: Redis

**Frontend:**

- **Meta-framework**: TanStack Start (full-stack, type-safe)
- **Framework**: React 19
- **Router**: TanStack Router (file-based, type-safe)
- **Data Fetching**: TanStack Query + Server Functions
- **Build Tool**: Vite
- **UI Primitives**: Radix UI (accessible, headless)
- **Styling**: Tailwind CSS
- **Tables**: TanStack Table (admin/portal)
- **Forms**: TanStack Form (type-safe forms)

**Infrastructure:**

- **Monorepo**: Nx 21.x
- **Package Manager**: pnpm
- **Containerization**: Docker
- **Orchestration**: Kubernetes ready
- **Observability**: OpenTelemetry

**Performance Critical (Rust WASM):**

- **Crypto**: JWT signing/verification, password hashing (Argon2id, ML-DSA)
- **Token Validation**: High-frequency token validation
- **Encoding**: High-throughput encoding/decoding operations

**Why This Stack?**

- **Node.js 24 LTS**: V8 13.6, URLPattern API, enhanced permissions model
- **Fastify**: High-performance, security-focused, perfect for auth
- **REST + GraphQL Hybrid**: Standards-compliant auth (REST) + flexible portal (GraphQL)
- **TanStack Start**: Full-stack type-safety, SSR optional per route, server functions
- **TanStack Ecosystem**: Router, Query, Table, Form - all type-safe and integrated
- **Radix UI + Tailwind**: Accessible primitives + utility-first CSS, fully customizable
- **Drizzle ORM**: Lightweight (~7KB), SQL-like, zero overhead, type-safe
- **Rust WASM**: Performance-critical crypto operations (JWT, hashing)
- **PostgreSQL**: ACID compliance, perfect for auth data integrity

**API Architecture:**

```
Core Auth (REST):           Developer Portal (GraphQL):
├── /oauth/*               ├── Client management
├── /oidc/*                ├── Analytics queries
├── /auth/*                ├── User management
└── /.well-known/*         └── Webhook configuration
```

**Frontend Architecture:**

```typescript
// Auth UI routes - SPA mode (fast load critical)
export const Route = createFileRoute('/login')({
  component: Login,
  // No SSR - fastest possible load
});

// Developer Portal - SSR for SEO
export const Route = createFileRoute('/dashboard')({
  loader: async () => getClients(), // Server-side
  component: Dashboard,
});

// Type-safe server functions
const createClient = createServerFn('POST', async (data) => {
  return await db.client.create({ data });
});
```

## 🚀 Quick Start

### **1. Auth as a Service Mode (Recommended)**

```typescript
// Your custom domain, QAuth backend
import { QAuth } from '@qauth/core';

const auth = new QAuth({
  domain: 'auth.yourapp.com',
  mode: 'headless',
});
```

### **2. Self-hosted Mode**

```bash
# Docker deployment
docker run -p 3000:3000 qauth/auth-server

# Or with docker-compose
curl -O https://qauth.dev/docker-compose.yml
docker-compose up -d
```

**For developers:** See [Development Setup](./docs/development.md)  
**For production:** See [Deployment Guide](./docs/deployment.md)

## 🗺️ Roadmap

### Phase 1: Foundation (MVP) - Q1 2026

- [ ] Core auth server (TypeScript)
- [ ] Email/Password authentication
- [ ] OAuth 2.1 flows (Authorization Code + PKCE)
- [ ] PostgreSQL + Redis setup
- [ ] Basic admin API
- [ ] Rust WASM crypto module

### Phase 2: Developer Portal - Q2 2026

- [ ] Developer registration/login
- [ ] Client app management (CRUD)
- [ ] API keys & secrets
- [ ] Basic documentation
- [ ] SDK (JavaScript/TypeScript)

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
- [ ] Custom domains
- [ ] Microservices extraction (Token service → Rust)

### Phase 5: Scale & Optimize - 2027

- [ ] Session service → Rust microservice
- [ ] Global CDN integration
- [ ] Advanced analytics
- [ ] Enterprise features
- [ ] Multi-region support

## 🧩 SDK Usage Examples (Future)

### Auth as a Service Mode

```typescript
// Installation
npm install @qauth/core

// Usage
import { QAuth } from '@qauth/core';

const auth = new QAuth({
  domain: 'auth.yourapp.com', // Your custom domain
  projectId: 'your-project-id',
  apiKey: 'your-api-key',
});

// Your own login UI
const { user, session } = await auth.signInWithPassword({
  email: 'user@example.com',
  password: 'password',
});

// Your own signup UI
await auth.signUp({
  email: 'newuser@example.com',
  password: 'securepass',
  metadata: { plan: 'pro' }, // Your custom data
});

// Get user session
const session = await auth.getSession();
// { accessToken: '...', refreshToken: '...', user: {...} }
```

### Self-hosted Mode

```typescript
// Point SDK to your self-hosted instance
import { QAuth } from '@qauth/core';

const auth = new QAuth({
  mode: 'self-hosted',
  baseUrl: 'https://auth.yourcompany.com', // Your server
  clientId: 'internal-app',
});

// Same API, your infrastructure
await auth.loginWithRedirect();
```

### React SDK Examples

```typescript
import { QAuthProvider, useAuth } from '@qauth/react';

// Auth as a Service mode
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

// Self-hosted mode
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

## 📊 Which Mode Should I Choose?

| Feature             | Auth as a Service  | Self-hosted            |
| ------------------- | ------------------ | ---------------------- |
| **Setup Time**      | 15 minutes         | 1-2 hours              |
| **Infrastructure**  | None (we host)     | You manage             |
| **Custom Domain**   | ✅                 | ✅                     |
| **Custom Branding** | ✅                 | ✅                     |
| **Data Location**   | Our servers        | Your servers           |
| **Compliance**      | Standard           | Full control           |
| **Pricing**         | Usage-based        | Free (self-host costs) |
| **Best For**        | Branded apps       | Enterprise/Compliance  |
| **User Experience** | Your branded login | Your branded login     |
| **Maintenance**     | Zero               | You manage             |

### Quick Decision Guide

**Choose Auth as a Service if:**

- You need custom branding but don't want infrastructure
- You're building a startup/product
- You want API-first headless auth
- You want to focus on your product, not auth infrastructure

**Choose Self-hosted if:**

- You have compliance requirements (GDPR, HIPAA, etc.)
- You need complete data sovereignty
- You're an enterprise with existing infrastructure
- You want to avoid vendor lock-in
- You want to customize everything

## 📚 Documentation

**Getting Started:**

- [Quick Start Guide](./docs/quick-start.md) - Get started in 5 minutes
- [Architecture Overview](./docs/architecture.md) - System architecture details
- [Setup Guide](./docs/setup.md) - Development environment setup

**Deployment Modes:**

- [Auth as a Service Mode](./docs/auth-service.md) - Headless auth backend setup
- [Self-hosted Mode](./docs/self-hosted.md) - Deploy on your infrastructure

**Technical Documentation:**

- [Authentication Flow](./docs/authentication.md) - Auth flow explanations
- [API Reference](./docs/api.md) - REST & GraphQL API documentation
- [SDK Documentation](./docs/sdk.md) - Client SDK usage
- [Hybrid Architecture](./docs/hybrid-architecture.md) - TypeScript + Rust integration

**Advanced Topics:**

- [Multi-tenancy](./docs/multi-tenancy.md) - Multi-tenant architecture
- [Custom Domains](./docs/custom-domains.md) - Setup custom domains
- [Migration Guide](./docs/migration.md) - Migrate from other platforms
- [Security Best Practices](./docs/security.md) - Security guidelines

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](./CONTRIBUTING.md).

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.

Copyright © 2025 QAuth Labs

## 🔗 Links

- [Website](https://qauth.dev)
- [Documentation](https://docs.qauth.dev)
- [Developer Portal](https://developers.qauth.dev)
- [Foundation](https://qauth.org)
- [Status Page](https://status.qauth.dev)

---

**Note**: This project is under active development and is not yet ready for production use.

## 🙏 Acknowledgments

Inspired by excellent projects: Keycloak, Ory, Auth0, Clerk, and Supabase Auth.
