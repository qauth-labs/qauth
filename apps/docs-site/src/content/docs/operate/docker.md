---
title: Docker Guide
description: Running QAuth with Docker Compose — production and development, service details, and troubleshooting.
sidebar:
  order: 1
lastVerified: '2026-07-27'
---

This guide covers the Docker setup for QAuth: **production** (prod build, no watch) and **development** (dev image, Compose Watch + `nx serve --watch`).

## Overview

QAuth uses Docker Compose to orchestrate the following services:

| Service              | Image                | Purpose                                                  |
| -------------------- | -------------------- | -------------------------------------------------------- |
| **postgres**         | `postgres:18-alpine` | Primary database (PostgreSQL 18 with `uuidv7()` support) |
| **redis**            | `redis:7-alpine`     | Session cache and rate limiting                          |
| **migration-runner** | Custom               | Runs database migrations via Nx                          |
| **auth-server**      | Custom               | Main authentication API server                           |
| **developer-portal** | Custom               | TanStack Start web UI for registration/login/consents    |

### Production vs development

| Use case        | Compose file(s)                                 | Service image                                | Watch                |
| --------------- | ----------------------------------------------- | -------------------------------------------- | -------------------- |
| **Production**  | `docker-compose.yml`                            | `Dockerfile` (multi-stage prod build)        | No                   |
| **Development** | `docker-compose.yml` + `docker-compose.dev.yml` | `Dockerfile.dev` (deps + source, dev server) | Yes (sync + rebuild) |

Both `auth-server` and `developer-portal` follow this convention: a multi-stage
`Dockerfile` for production and a `Dockerfile.dev` for the watch-based dev flow.

## Prerequisites

- Docker **23.0+** (BuildKit on by default) or earlier Docker with `DOCKER_BUILDKIT=1` set. The auth-server and migration-runner Dockerfiles use `# syntax=docker/dockerfile:1.7` and a `--mount=type=cache` pnpm-store mount, both of which require BuildKit.
- Docker Compose 2.0+
- Docker Compose **2.22+** for development watch (`docker-compose.dev.yml` + `--watch`)
- OpenSSL (for generating JWT keys)

## Quick Start

### 1. Generate JWT Keys

QAuth uses EdDSA (Ed25519) for JWT signing. Generate a key pair:

```bash
# Generate private key
openssl genpkey -algorithm Ed25519 -out private.pem

# Extract public key
openssl pkey -in private.pem -pubout -out public.pem
```

See the [Keys guide](/operate/keys/) for RS256 and ML-DSA key generation, and a
pitfall (`openssl genrsa` emits the wrong private-key format) that wastes an
afternoon if you hit it.

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.docker.example .env

# Edit .env and add your JWT keys
# The keys should include the BEGIN/END lines
```

Example `.env` content:

```bash
DB_PASSWORD=your_secure_password

JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKx...
-----END PRIVATE KEY-----"

JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...
-----END PUBLIC KEY-----"

JWT_ISSUER=http://localhost:3000
```

> **Set `JWT_PUBLIC_KEY` explicitly.** `.env.docker.example` marks it optional,
> but omitting it currently fails EdDSA key setup at boot — see the
> [Keys guide](/operate/keys/#the-eddsa-public-key-is-not-actually-optional-359)
> before you skip it.

### 3. Start Services

**Production** (prod build, no watch):

```bash
docker compose up -d
docker compose logs -f
```

**Development** (dev image, Compose Watch, `nx serve --watch`; requires Docker Compose 2.22+):

```bash
# In .env: NODE_ENV=development, LOG_LEVEL=debug
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --watch
```

- Sync: changes in `apps/auth-server/` and `libs/` are synced into the container; `nx serve --watch` rebuilds and restarts.
- Rebuild: changes to `package.json`, lockfile, `nx.json`, etc. trigger a full image rebuild.
- See [Compose file watch](https://docs.docker.com/compose/file-watch/).

### 4. Verify Setup

```bash
# Check all services are healthy
docker-compose ps

# Test the auth-server health endpoint
curl http://localhost:3000/health
```

Expected response:

```json
{
  "status": "ok",
  "timestamp": "2026-01-15T05:15:47.887Z",
  "services": {
    "database": "connected",
    "redis": "connected"
  }
}
```

The developer-portal has no dedicated health endpoint (see
[Developer Portal](#developer-portal) below); confirm it's up by opening
`http://localhost:3001` in a browser, or checking that Compose reports its
container `healthy`:

```bash
docker compose ps developer-portal
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Docker Network                          │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │   postgres   │  │    redis     │  │ migration-runner │   │
│  │   :5432      │  │    :6379     │  │   (runs once)    │   │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘   │
│         │                 │                   │              │
│         │  health check   │                   │ waits for    │
│         │  dependency     │                   │ postgres     │
│         ▼                 ▼                   ▼              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                    auth-server                          │  │
│  │                      :3000                              │  │
│  │  Waits for: postgres (healthy), redis (healthy),       │  │
│  │             migration-runner (completed)                │  │
│  └───────────────────────────┬────────────────────────────┘  │
│                              │ health check dependency        │
│                              ▼                                 │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                 developer-portal                        │  │
│  │                      :3001                              │  │
│  │  Waits for: auth-server (healthy). Calls it server-     │  │
│  │  side at http://auth-server:3000 over the network.      │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Service Details

### PostgreSQL

- **Image**: `postgres:18-alpine`
- **Port**: 5432 (mapped to host)
- **Database**: `qauth`
- **User**: `qauth`
- **Features**: `uuidv7()` native support (PostgreSQL 18+)

Connect via psql:

```bash
docker exec -it qauth-postgres psql -U qauth -d qauth
```

### Redis

- **Image**: `redis:7-alpine` (Redis 7)
- **Port**: 6379 (mapped to host)

Connect via redis-cli:

```bash
docker exec -it qauth-redis redis-cli
```

### Migration Runner

A dedicated service that runs database migrations before auth-server starts.

- Executes `pnpm nx run infra-db:db:migrate`
- Exits after completion (restart: "no")
- Auth-server waits for this to complete successfully

Run migrations manually:

```bash
docker-compose run --rm migration-runner
```

> Upgrading an existing deployment past the ADR-002 identity migration
> (0011)? Read the [Upgrades runbook](/operate/upgrades/) before running this
> — that migration is destructive and has a required backfill precondition.

### Auth Server

The main authentication API server.

- **Port**: 3000 (mapped to host)
- **Health Check**: `GET /health`
- **Production**: `Dockerfile` → a `pnpm deploy --prod` bundle, started by
  `docker-entrypoint.sh` via `exec tsx src/main.ts`
  (`apps/auth-server/docker-entrypoint.sh:5`).
- **Development**: `Dockerfile.dev` → `pnpm nx serve auth-server --watch`; use with `docker-compose.dev.yml` and `--watch`.

### Developer Portal

The TanStack Start web UI for user registration, email verification, login, and
OAuth consent management. It renders server-side and calls the auth-server only
from its server functions — tokens never reach the browser.

- **Port**: 3001 (mapped to host)
- **Health Check**: a raw TCP connect check on port 3001
  (`docker-compose.yml`, `developer-portal.healthcheck`) — liveness only, and
  does **not** depend on the auth-server being reachable. The Nitro build has
  no dedicated `/healthz` route, so there is nothing to `curl`.
- **Production**: `Dockerfile` → runs `node server/index.mjs`, the
  self-contained server the build emits (see below).
- **Development**: `Dockerfile.dev` → `pnpm nx dev developer-portal` (Vite dev
  server); use with `docker-compose.dev.yml` and `--watch`.
- **Depends on**: `auth-server` (healthy).

The portal is built with TanStack Start's Nitro v2 Vite plugin, which emits a
**self-contained, self-listening** Node server at
`dist/apps/developer-portal/server/index.mjs` (Nitro bundles its runtime
dependencies into `server/node_modules`) plus static assets under `public/`.
The production image's runner stage just copies `server/` and `public/` and
runs `node server/index.mjs` — no custom adapter and no separate `pnpm deploy`
step are needed (`apps/developer-portal/Dockerfile`).

> **Build context note:** the portal source is excluded from the auth-server /
> migration-runner build contexts by the root `.dockerignore` (see the build
> note below). The portal image lifts that exclusion for its own build via a
> sibling `apps/developer-portal/Dockerfile.dockerignore`, which BuildKit
> prefers over the root file when present. No action is needed — this is wired
> up already.

Open the portal at `http://localhost:3001` once the stack is up. Set a
`PORTAL_SESSION_SECRET` in `.env` first (see Environment Variables).

## Common Operations

### Rebuild Images

**Production:**

```bash
docker compose up -d --build
# Or rebuild a single service
docker compose build auth-server && docker compose up -d auth-server
docker compose build developer-portal && docker compose up -d developer-portal
```

Build the portal image directly (from the repo root, BuildKit on):

```bash
DOCKER_BUILDKIT=1 docker build -f apps/developer-portal/Dockerfile -t qauth-developer-portal .
```

**Development:** use `docker compose -f docker-compose.yml -f docker-compose.dev.yml up --watch`; sync/rebuild is automatic. For dependency or config changes, the dev setup will rebuild the auth-server image when those files change.

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f auth-server

# Last 100 lines
docker-compose logs --tail=100 auth-server
```

### Stop Services

```bash
# Stop all services (keeps data)
docker-compose stop

# Stop and remove containers (keeps volumes)
docker-compose down

# Stop and remove everything including volumes
docker-compose down -v
```

### Reset Database

```bash
# Remove postgres volume and restart
docker-compose down -v
docker-compose up -d
```

### Shell Access

```bash
# Auth server
docker exec -it qauth-auth-server sh

# PostgreSQL
docker exec -it qauth-postgres sh

# Redis
docker exec -it qauth-redis sh
```

## Environment Variables

See `.env.docker.example` for all available variables. Key variables:

| Variable          | Required | Description                                        |
| ----------------- | -------- | -------------------------------------------------- |
| `DB_PASSWORD`     | Yes      | PostgreSQL password                                |
| `JWT_PRIVATE_KEY` | Yes      | EdDSA private key (PEM format)                     |
| `JWT_PUBLIC_KEY`  | Yes      | EdDSA public key (PEM format)                      |
| `JWT_ISSUER`      | No       | JWT issuer URL (default: http://localhost:3000)    |
| `EMAIL_PROVIDER`  | No       | Email provider: mock, resend, smtp (default: mock) |
| `NODE_ENV`        | No       | `production` (default) or `development` for dev    |
| `LOG_LEVEL`       | No       | `info` (default); use `debug` for development      |

`JWT_PUBLIC_KEY` is listed as **Yes** here, not because the schema requires
it, but because omitting it fails at boot today — see the
[Keys guide](/operate/keys/#the-eddsa-public-key-is-not-actually-optional-359).

#### Developer Portal

| Variable                 | Required | Default                   | Description                                                 |
| ------------------------ | -------- | ------------------------- | ----------------------------------------------------------- |
| `PORTAL_SESSION_SECRET`  | Yes      | —                         | 32+ char secret signing the portal session cookie           |
| `PORTAL_SESSION_TTL`     | No       | `900`                     | Session cookie lifetime in seconds                          |
| `PORTAL_AUTH_SERVER_URL` | No       | `http://auth-server:3000` | Base URL the portal uses (server-side) to reach auth-server |

Generate a secret with `openssl rand -hex 32`. The portal will not start without
`PORTAL_SESSION_SECRET`.

For **development** with `docker-compose.dev.yml`, set `NODE_ENV=development` and `LOG_LEVEL=debug` in `.env`.

### Client ID Metadata Documents (CIMD)

CIMD is the recommended MCP client-registration mechanism (see [ADR-007](/reference/records/adr/007-mcp-first-positioning/)) — MCP Authorization 2026-07-28 says authorization servers and MCP clients **SHOULD** support it, and deprecates RFC 7591 dynamic registration in its favour. When a `client_id` is an HTTPS URL, the auth-server fetches and validates the client's metadata document on demand instead of persisting a registration record. All settings have safe defaults — none are required to run.

| Variable                       | Required | Default            | Description                                                                                                                                                     |
| ------------------------------ | -------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CIMD_ENABLED`                 | No       | `true`             | Master switch. When `false`, URL-formatted `client_id`s are rejected with `invalid_client`.                                                                     |
| `CIMD_TRUST_POLICY`            | No       | `accept-any-https` | `accept-any-https` (any validating HTTPS document) or `allowlist` (only hosts in `CIMD_TRUSTED_DOMAINS`).                                                       |
| `CIMD_TRUSTED_DOMAINS`         | No       | _(empty)_          | Comma/space-separated host allowlist for `allowlist` policy. A leading `*.` permits subdomains.                                                                 |
| `CIMD_CACHE_DEFAULT_TTL`       | No       | `300`              | Cache TTL (seconds) when the document carries no usable `Cache-Control`/`Expires`.                                                                              |
| `CIMD_CACHE_MAX_TTL`           | No       | `3600`             | Hard upper bound (seconds) on any cached document, regardless of upstream `max-age`.                                                                            |
| `CIMD_MAX_DOCUMENT_BYTES`      | No       | `65536`            | Maximum document size in bytes.                                                                                                                                 |
| `CIMD_FETCH_TIMEOUT_MS`        | No       | `5000`             | Per-fetch timeout in milliseconds.                                                                                                                              |
| `CIMD_ALLOW_PRIVATE_ADDRESSES` | No       | `false`            | Allow fetches to non-public IPs (loopback/private/link-local). **Keep `false` in production** — it disables the SSRF guard; for dev/integration harnesses only. |

> **Note:** `.env.docker.example` does not yet list the `CIMD_*` variables. They are optional and default-safe, so the stack runs without them; add them to `.env` only to override the defaults above.

### ID-JAG / enterprise-managed authorization (ADR-011)

**Off by default**, and doubly fail-closed: with `ID_JAG_ENABLED` off the
`jwt-bearer` grant is neither advertised nor accepted, and even with it on an
empty `ID_JAG_TRUSTED_ISSUERS` rejects every assertion. See
[ID-JAG](/integrate/oauth-flow/#id-jag--enterprise-managed-authorization-adr-011).

| Variable                         | Required          | Default   | Description                                                                                                                                  |
| -------------------------------- | ----------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `ID_JAG_ENABLED`                 | No                | `false`   | Master switch. Gates both the `jwt-bearer` grant and the discovery members that advertise it.                                                |
| `ID_JAG_TRUSTED_ISSUERS`         | Yes, when enabled | _(empty)_ | Allowlist of enterprise IdP issuers whose assertions may be redeemed. Empty rejects everything — an assertion never nominates its own trust. |
| `ID_JAG_MAX_ASSERTION_LIFETIME`  | No                | `300`     | Seconds. Bounds the replay window a `jti` is tracked for.                                                                                    |
| `ID_JAG_ISSUED_LIFETIME`         | No                | `300`     | Seconds. Lifetime stamped on assertions QAuth **mints**.                                                                                     |
| `ID_JAG_CLOCK_SKEW_LEEWAY`       | No                | `60`      | Seconds of tolerance on `exp` / `nbf` / `iat`.                                                                                               |
| `ID_JAG_JWKS_CACHE_TTL`          | No                | `300`     | Seconds to cache a trusted issuer's JWKS.                                                                                                    |
| `ID_JAG_FETCH_TIMEOUT_MS`        | No                | `5000`    | Timeout for issuer discovery / JWKS fetches.                                                                                                 |
| `ID_JAG_MAX_DOCUMENT_BYTES`      | No                | `65536`   | Size cap on a fetched discovery or JWKS document.                                                                                            |
| `ID_JAG_ALLOW_PRIVATE_ADDRESSES` | No                | `false`   | SSRF guard. Leave off outside local development.                                                                                             |

### Wallet federation (OID4VP, T4)

Wallet sign-in is **off by default**. With `WALLET_FEDERATION_ENABLED` unset or
`false` the wallet routes are never registered and the paths 404 — nothing below
has any effect. See the [wallet sign-in guide](/integrate/wallet-login/) for the
full flow and [ADR-009](/reference/records/adr/009-wallet-account-resolution/)
for the resolution model.

| Variable                            | Required          | Default        | Description                                                                                                                                                                              |
| ----------------------------------- | ----------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WALLET_FEDERATION_ENABLED`         | No                | `false`        | Master switch. When off, the wallet-login UI and the `direct_post` endpoint are not registered.                                                                                          |
| `OID4VP_VERIFIER_PROFILE`           | Yes, when enabled | _(unset)_      | `oid4vp-1.0-base` or `haip-1.0`. There is no fallback — an unset or unprovisioned profile refuses every flow. `haip-1.0` awaits #377.                                                    |
| `OID4VP_REQUESTED_VCT`              | Yes, when enabled | _(unset)_      | The credential type to request. Unset means a DCQL query with no type constraint, which is refused.                                                                                      |
| `OID4VP_TRUSTED_ISSUERS`            | Yes, when enabled | _(unset)_      | Per-realm issuer allowlist. An issuer absent here is refused before any claim is read.                                                                                                   |
| `OID4VP_ISSUER_JWKS`                | Yes, when enabled | _(unset)_      | The key each trusted issuer signs with.                                                                                                                                                  |
| `OID4VP_SUBJECT_RESOLUTION`         | No                | _(unset)_      | `asserted-lookup` (the ADR-009 default), `issuer-scoped-claim`, `session-binding`, `key-thumbprint`, or `rp-pseudonym`.                                                                  |
| `OID4VP_SUBJECT_BINDING_CLAIMS`     | Yes, when enabled | _(unset)_      | Comma-separated claims the wallet binding is derived from — the entitlement check of `asserted-lookup`. Missing means every refusal.                                                     |
| `OID4VP_SUBJECT_CLAIM`              | Conditional       | _(unset)_      | The claim carrying the subject, for `issuer-scoped-claim`.                                                                                                                               |
| `OID4VP_SUBJECT_CLAIM_ISSUERS`      | Conditional       | _(unset)_      | Which issuers may assert `OID4VP_SUBJECT_CLAIM`.                                                                                                                                         |
| `OID4VP_ISSUER_ASSURANCE`           | No                | _(unset)_      | Per-issuer eIDAS level of assurance, mapped to the OIDC `acr` claim ([ADR-010](/reference/records/adr/010-acr-assurance-mapping/)). Listing an issuer here does **not** make it trusted. |
| `OID4VP_STATUS_LIST_TRUST_ANCHORS`  | No                | _(empty)_      | Trust anchors for Token Status List revocation checking (or `_PATH` to read them from a file).                                                                                           |
| `OID4VP_STATUS_LIST_URI_ALLOWLIST`  | No                | _(empty)_      | Permitted status-list URIs.                                                                                                                                                              |
| `OID4VP_WALLET_INVOCATION_ENDPOINT` | No                | `openid4vp://` | The wallet deep-link / QR target. Script-capable schemes (`javascript:`, `data:`) are refused at boot.                                                                                   |

### Post-quantum hybrid signing (ADR-005)

Also **off by default** — tokens are Ed25519-only and the JWKS is EdDSA-only
unless configured. See the [verifier guide](/operate/pqc-verifier-guide/).

| Variable                 | Required               | Default     | Description                                                                                                                                                                     |
| ------------------------ | ---------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SIGNING_ALGORITHM_MODE` | No                     | `ed25519`   | `ed25519` or `ed25519+ml-dsa-65`. Must be the latter for hybrid.                                                                                                                |
| `HYBRID_SIGNING_ENABLED` | No                     | `false`     | Turns on live hybrid token issuance. Enabling it without an ML-DSA key **throws at startup** — a half-configured deployment fails fast rather than degrading to classical-only. |
| `JWT_MLDSA_PRIVATE_KEY`  | Yes, when hybrid is on | _(unset)_   | ML-DSA-65 private key as a base64url 32-byte seed (or `JWT_MLDSA_PRIVATE_KEY_PATH`).                                                                                            |
| `JWT_MLDSA_KID`          | No                     | _(unset)_   | Stable `kid` for the ML-DSA key published in the `AKP` JWK.                                                                                                                     |
| `PQC_TOKEN_DELIVERY`     | No                     | `reference` | `reference` keeps the bearer a small Ed25519 JWS and serves the PQC signature via introspection. `self-contained` requires `PQC_SELF_CONTAINED_ACK`.                            |
| `PQC_SELF_CONTAINED_ACK` | Conditional            | `false`     | Explicit acknowledgement that `self-contained` ships a ~4.4 KB detached signature exceeding cookie and URL budgets.                                                             |

> Setting `JWT_MLDSA_PRIVATE_KEY` alone publishes the ML-DSA public key in the
> JWKS without issuing any hybrid token — deliberate, so verifiers can fetch the
> key before issuance is switched on.

> **Note:** `.env.docker.example` does not list the wallet-federation or
> post-quantum variables either. Both features are off by default, so the stack
> runs without them.

## Troubleshooting

### Port Conflicts

If ports 3000, 5432, or 6379 are in use:

```bash
# Check what's using the port
lsof -i :3000

# Modify port mappings in docker-compose.yml
ports:
  - '3001:3000'  # Map to different host port
```

### Migration Errors

```bash
# Check migration-runner logs
docker-compose logs migration-runner

# Check postgres is ready
docker-compose ps postgres

# Re-run migrations
docker-compose run --rm migration-runner
```

If migration-runner fails specifically on the ADR-002 migration (0011), that
is very likely a required backfill step you skipped — see the
[Upgrades runbook](/operate/upgrades/), not this section.

### JWT Key Errors

Ensure your JWT keys in `.env`:

- Include the `-----BEGIN/END-----` lines
- Are properly quoted with double quotes
- Have no extra whitespace
- Are **PKCS#8** for private keys (`-----BEGIN PRIVATE KEY-----`), not PKCS#1
  (`-----BEGIN RSA PRIVATE KEY-----`) — see the [Keys guide](/operate/keys/)
  if you generated an RS256 key with `openssl genrsa`.

### Build Failures

```bash
# Clean Docker build cache
docker builder prune

# Rebuild without cache
docker-compose build --no-cache
```

If the build fails on `Cannot find module '@tailwindcss/vite'` or a similar dev-portal-scoped import while building **auth-server** or **migration-runner**: `apps/developer-portal` is intentionally excluded from those build contexts via the root `.dockerignore`. The exclusion keeps Nx's project-graph processor from trying to parse the portal's configs (which import portal-scoped dev deps) during an auth-server build. This exclusion is load-bearing and should not be removed.

The **developer-portal** image needs its own source, so it ships a sibling `apps/developer-portal/Dockerfile.dockerignore`. BuildKit prefers a `<dockerfile>.dockerignore` over the root `.dockerignore`, so that file applies to the portal build only and deliberately does **not** exclude `apps/developer-portal`. Build the portal image with BuildKit enabled (default on Docker 23+) so this per-Dockerfile ignore is honored.

### Watch: "no space left on device"

When running `docker compose ... up --watch`, Compose uses inotify. The error often means **inotify limits** (not disk space):

1. **Close other watchers** (Nx graph, IDE, etc.):
   ```bash
   pkill -f 'nx graph.*watch'
   ```
2. **Increase inotify instance limit**:
   ```bash
   sudo sysctl fs.inotify.max_user_instances=4096
   echo "fs.inotify.max_user_instances=4096" | sudo tee -a /etc/sysctl.d/99-inotify.conf
   ```
3. **Use watch-free dev** if it still fails:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
   # After code changes:
   docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build auth-server
   ```

### Container Won't Start

```bash
# Check container logs
docker logs qauth-auth-server

# Check container status
docker inspect qauth-auth-server | jq '.[0].State'
```

## Production Considerations

This Docker setup is designed for **local development**. For production:

1. **Use secrets management** (Vault, AWS Secrets Manager) instead of `.env` files
2. **Use managed databases** (RDS, Cloud SQL) instead of containerized PostgreSQL
3. **Use managed Redis** (ElastiCache, Memorystore) for high availability
4. **Add reverse proxy** (nginx, Traefik) with TLS termination
5. **Configure resource limits** in Docker/Kubernetes
6. **Set up monitoring** (Prometheus, Grafana)
7. **Enable logging aggregation** (ELK, Loki)

See [ADR-001: JWT Key Management](/reference/records/adr/001-jwt-key-management/) for production key management strategy, and the [Keys guide](/operate/keys/) for how to generate each key type today.

## Testing the Setup

A comprehensive test script is available:

```bash
./scripts/test-docker.sh
```

This verifies:

- Environment configuration
- Docker image builds
- Service startup and health
- Database migrations
- API endpoint functionality
- Data persistence

## See also

- [Keys](/operate/keys/) — generating EdDSA, RS256, and ML-DSA key material, and the PKCS#8 pitfall.
- [Upgrades](/operate/upgrades/) — the ADR-002 destructive-migration runbook; read it before running `migration-runner` against an existing database.
- [Observability](/operate/observability/) — logging, metrics, and alerting once the stack is up.
- [Environment-Aware Authorization](/operate/environment-authorization/) — the `environment` policy dimension referenced throughout this stack.
