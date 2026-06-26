# Docker Guide

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

# Test the developer-portal liveness probe, then open it in a browser
curl http://localhost:3001/healthz   # -> ok
# http://localhost:3001
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

### Auth Server

The main authentication API server.

- **Port**: 3000 (mapped to host)
- **Health Check**: `GET /health`
- **Production**: `Dockerfile` → `docker-entrypoint.sh` runs `node main.js`.
- **Development**: `Dockerfile.dev` → `pnpm nx serve auth-server --watch`; use with `docker-compose.dev.yml` and `--watch`.

### Developer Portal

The TanStack Start web UI for user registration, email verification, login, and
OAuth consent management. It renders server-side and calls the auth-server only
from its server functions — tokens never reach the browser.

- **Port**: 3001 (mapped to host)
- **Health Check**: `GET /healthz` (a lightweight liveness probe served by the
  Node adapter; it does **not** depend on the auth-server being reachable)
- **Production**: `Dockerfile` → `docker-entrypoint.sh` runs `node server.mjs`.
- **Development**: `Dockerfile.dev` → `pnpm nx dev developer-portal` (Vite dev
  server); use with `docker-compose.dev.yml` and `--watch`.
- **Depends on**: `auth-server` (healthy).

TanStack Start's Vite build emits a framework-agnostic fetch handler
(`server/server.js`) plus static client assets (`client/`) rather than a
self-listening server, so the production image runs a tiny Node adapter
(`apps/developer-portal/server.mjs`) that pipes `node:http` requests into the
fetch handler and serves the client assets. The image is built with the same
`pnpm deploy --prod` strategy as the auth-server so the build output's bare
imports resolve at runtime.

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

CIMD is the recommended MCP client-registration mechanism (see [ADR-007](./adr/007-mcp-first-positioning.md)). When a `client_id` is an HTTPS URL, the auth-server fetches and validates the client's metadata document on demand instead of persisting a registration record. All settings have safe defaults — none are required to run.

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

### JWT Key Errors

Ensure your JWT keys in `.env`:

- Include the `-----BEGIN/END-----` lines
- Are properly quoted with double quotes
- Have no extra whitespace

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

See [ADR-001: JWT Key Management](./adr/001-jwt-key-management.md) for production key management strategy.

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
