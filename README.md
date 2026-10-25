<br />

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="logos/qauth-logo-light.svg">
    <img src="logos/qauth-logo.svg" alt="QAuth Logo" height="140">
  </picture>
</div>

<br />

<div align="center">

<h3>Open-source identity for the agent era.<br />OAuth 2.1 · OpenID Connect · MCP and AI-agent authorization · federation · post-quantum ready</h3>

[![Latest release](https://img.shields.io/github/v/release/qauth-labs/qauth?include_prereleases&sort=semver)](https://github.com/qauth-labs/qauth/releases)
[![CI](https://github.com/qauth-labs/qauth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/qauth-labs/qauth/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE)

🇪🇺 Made in Europe · 🇪🇪 Made in Estonia · 🇹🇷 Made in Türkiye

</div>

QAuth is an open-source OAuth 2.1 and OpenID Connect 1.0 server. You run it
yourself. Your apps, MCP servers and AI agents get standard access tokens and
ID tokens from it.

It is built for three jobs:

- **Agents.** An AI agent acts for a user with narrower rights than the user,
  and every step is audited ([ADR-007](./docs/adr/007-mcp-first-positioning.md)).
- **Federation.** Identity sources plug in behind one interface. Apps
  integrate once, whatever the user signs in with
  ([ADR-003](./docs/adr/003-credential-provider-interface.md)).
- **Post-quantum.** Signing sits behind algorithm-agnostic interfaces. A
  hybrid ML-DSA-65 + Ed25519 mode already ships
  ([ADR-005](./docs/adr/005-pqc-hybrid-signing.md)).

## Status

QAuth is pre-1.0. Releases are 0.x, and `main` runs ahead of the latest one.
The [changelog](./CHANGELOG.md) lists every change.

The road to 1.0 runs through 0.x betas, one area at a time: the core and its
UIs, then the Authority Tree, then federation.
[ADR-018](./docs/adr/018-1-0-scope-and-stability.md) sets what 1.0 covers and
what it promises. An independent security audit and OpenID Foundation
certification come before 1.0.

The [status page](https://docs.qauth.dev/reference/status/) tracks each
feature. The [milestones](https://github.com/qauth-labs/qauth/milestones) hold
the open work.

## What works today

**OAuth 2.1 and OpenID Connect**

- Authorization code flow with mandatory PKCE (S256), for confidential and
  public clients.
- `client_credentials` and `refresh_token` grants. Refresh tokens rotate, and
  a replayed one revokes its whole family.
- Discovery, JWKS, ID tokens, userinfo, introspection (RFC 7662) and
  revocation (RFC 7009).
- Resource indicators (RFC 8707): each token is bound to its audience.
- Client registration by Client ID Metadata Document (CIMD). RFC 7591 dynamic
  registration remains as a fallback.
- DPoP-bound tokens (RFC 9449).

**MCP servers and AI agents**

- The MCP authorization profile: protected-resource metadata (RFC 9728),
  audience binding and step-up challenges.
  [`@qauth-labs/resource-guard`](./libs/sdk/resource-guard/README.md) handles
  the resource-server side.
- An agent client type. An agent acts for a user through token exchange
  (RFC 8693), and the `act` claim names it.
- Scope modes (read-only, admin, exec), step-up before dangerous operations,
  and an audit trail per agent.
- A policy per environment (development, staging, production). It sets token
  lifetimes, PKCE, redirects, rate limits and step-up
  ([ADR-008](./docs/adr/008-environment-aware-authorization.md)).

**Accounts and operations**

- Email and password sign-up with account verification. Passwords are hashed
  with Argon2id. Repeated failed logins lock the account.
- Realms: separate tenants, each with its own issuer and hosts.
- A developer portal for OAuth clients and API keys.
- Security headers, CSRF protection and `__Host-` cookies.
- Structured logs, Prometheus `/metrics`, and events exported as OpenTelemetry
  logs.
- Signing keys stored encrypted under a key-encryption key (KEK).

**Behind switches that are off by default**

| Switch                      | What it turns on                                                                                                                                                          |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WALLET_FEDERATION_ENABLED` | Linking a wallet to an account and signing in with it, over OID4VP 1.0 with SD-JWT VC. Tested against a mock wallet so far; the pass against a real wallet is still open. |
| `HYBRID_SIGNING_ENABLED`    | Hybrid ML-DSA-65 + Ed25519 token signatures and a mixed JWKS. See the [verifier guide](https://docs.qauth.dev/operate/pqc-verifier-guide/).                               |
| `ID_JAG_ENABLED`            | Enterprise-managed authorization: accepting and minting ID-JAG assertions ([ADR-011](./docs/adr/011-enterprise-managed-authorization.md)).                                |

## Quick start

You need Docker 23 or later with Compose 2, and OpenSSL.

```bash
git clone https://github.com/qauth-labs/qauth.git
cd qauth
cp .env.docker.example .env
```

Fill in these values in `.env`:

| Variable                            | How to make it                                                                                                                                                      |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY` | `openssl genpkey -algorithm Ed25519 -out private.pem`, then `openssl pkey -in private.pem -pubout -out public.pem`. Paste both files, BEGIN and END lines included. |
| `KEK`                               | `openssl rand -base64 32`. Keep a copy with your backups: without it, the stored keys cannot be read.                                                               |
| `SESSION_COOKIE_SECRET`             | `openssl rand -base64 48`                                                                                                                                           |
| `DB_PASSWORD`                       | Any strong password.                                                                                                                                                |

Then start the stack and check it:

```bash
docker compose up -d
curl http://localhost:3000/health
```

Compose builds the images from source and runs the database migrations. It
then starts the auth server on port 3000 and the developer portal on port
3001, with PostgreSQL 18 and Redis 7. The interactive API docs at `/docs` are
off in production; `ENABLE_SWAGGER=true` turns them on.

The [Docker guide](https://docs.qauth.dev/operate/docker/) covers the
development setup and troubleshooting.

## Documentation

Guides and reference live at **[docs.qauth.dev](https://docs.qauth.dev)**:

| Section                                        | Start with                                                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Integrate](https://docs.qauth.dev/integrate/) | [MCP quickstart](https://docs.qauth.dev/integrate/mcp-quickstart/) · [OAuth 2.1 flow](https://docs.qauth.dev/integrate/oauth-flow/) · [Agent authorization](https://docs.qauth.dev/integrate/agent-authorization/) · [API reference](https://docs.qauth.dev/integrate/api-reference/)                                           |
| [Operate](https://docs.qauth.dev/operate/)     | [Docker](https://docs.qauth.dev/operate/docker/) · [Configuration](https://docs.qauth.dev/operate/configuration/) · [Keys](https://docs.qauth.dev/operate/keys/) · [Reverse proxy](https://docs.qauth.dev/operate/reverse-proxy/) · [Upgrades](https://docs.qauth.dev/operate/upgrades/)                                        |
| [Extend](https://docs.qauth.dev/extend/)       | [Architecture](https://docs.qauth.dev/extend/architecture/) · [Repository map](https://docs.qauth.dev/extend/repo-map/) · [Adding a credential provider](https://docs.qauth.dev/extend/adding-a-credential-provider/) · [Testing](https://docs.qauth.dev/extend/testing/)                                                       |
| [Reference](https://docs.qauth.dev/reference/) | [Status](https://docs.qauth.dev/reference/status/) · [Events](https://docs.qauth.dev/reference/events/) · [API conventions](https://docs.qauth.dev/reference/api-conventions/) · [Experimental features](https://docs.qauth.dev/reference/experimental-features/) · [Design records](https://docs.qauth.dev/reference/records/) |

In this repository:

- [`docs/adr/`](./docs/adr/README.md): the architecture decision records.
- [`docs/security/threat-model.md`](./docs/security/threat-model.md): what
  QAuth promises and how findings are rated.
- [`docs/`](./docs/README.md): the other engineering records, such as the
  spec pin log and the conformance matrix.
- Each library documents itself in its own `README.md` under `libs/`.

## Repository layout

| Path                                   | What it holds                                                     |
| -------------------------------------- | ----------------------------------------------------------------- |
| `apps/auth-server`                     | The OAuth 2.1 and OpenID Connect server                           |
| `apps/developer-portal`                | The developer portal                                              |
| `apps/migration-runner`                | Applies the database migrations                                   |
| `apps/docs-site`                       | The documentation site, docs.qauth.dev                            |
| `apps/wire-suite`, `apps/upgrade-test` | Black-box HTTP tests and upgrade tests against a running server   |
| `libs/`                                | Server, Fastify plugin, database, crypto, SDK, shared and UI code |
| `docs/`                                | Design records and other engineering records                      |

The stack is TypeScript on Node.js 26: Fastify, Drizzle ORM, PostgreSQL 18 and
Redis 7 on the server; React 19 and TanStack Start for the UIs. The monorepo
runs on Nx and pnpm.

## Contributing

[CONTRIBUTING.md](./CONTRIBUTING.md) covers setup, conventions and the pull
request checklist. Everyone who takes part follows the
[Code of Conduct](./CODE_OF_CONDUCT.md).

## Security

Report a vulnerability privately, as [SECURITY.md](./SECURITY.md) describes.
Please do not open a public issue for it.

## License

Apache License 2.0. See [LICENSE](./LICENSE).

Copyright © 2025–2026 QAuth Labs

## Acknowledgments

QAuth learns from the open-source identity servers that came before it. It
builds on the open standards of the IETF, the OpenID Foundation, the W3C and
NIST.

[Website](https://qauth.dev) · [Documentation](https://docs.qauth.dev) ·
[Foundation](https://qauth.org)
