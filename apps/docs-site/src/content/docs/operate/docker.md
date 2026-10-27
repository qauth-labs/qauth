---
title: Docker Guide
description: Running QAuth with Docker Compose — production and development, service details, and troubleshooting.
sidebar:
  order: 1
lastVerified: '2026-10-25'
---

This guide covers the Docker setup for QAuth: **production** (prod build, no watch) and **development** (dev image, Compose Watch + `nx serve --watch`).

## Overview

QAuth uses Docker Compose to orchestrate the following services:

| Service              | Image                | Purpose                                                  |
| -------------------- | -------------------- | -------------------------------------------------------- |
| **postgres**         | `postgres:18-alpine` | Primary database (PostgreSQL 18 with `uuidv7()` support) |
| **redis**            | `redis:7-alpine`     | Session cache and rate limiting                          |
| **migration-runner** | Custom               | Applies the pending database migrations, then exits      |
| **auth-server**      | Custom               | Main authentication API server                           |
| **developer-portal** | Custom               | TanStack Start web UI for registration/login/consents    |

Compose builds the three custom images from source. Each release also
publishes the `migration-runner` and `auth-server` images, signed and
attested, so a deployment can pin their digests instead of building them:
see [Published images](/operate/images/).

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
- Docker Compose **2.24.4+** for development (`docker-compose.dev.yml` uses the `!reset` merge tag; `--watch` needs 2.22+)
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

# The key-encryption key: openssl rand -base64 32. Keep a copy with your backups.
KEK=...
```

> **Set a KEK.** At its first boot the server imports the JWT keys and
> `SESSION_COOKIE_SECRET` into the realm's encrypted key store, wrapped with
> `KEK`, and refuses to start without one. See
> [the key store](/operate/keys/#the-key-store).

> **The JWT keys are optional.** Tokens are signed with the realm's keys in
> the key store. Set `JWT_PRIVATE_KEY` to keep the key a deployment already
> signs with; leave it unset and the first boot generates the keys.
> `JWT_PUBLIC_KEY` is derived from the private key when unset. See
> [the key store](/operate/keys/#the-key-store).

### 3. Start Services

**Production** (prod build, no watch):

```bash
docker compose up -d
docker compose logs -f
```

**Development** (dev image, Compose Watch, `nx serve --watch`; requires Docker Compose 2.24.4+):

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

A dedicated service that applies the pending database migrations before
auth-server starts.

- The image holds Node and one bundled program with the migrations beside it:
  no pnpm, nx or drizzle-kit. Only `DATABASE_URL` is read.
- It takes a Postgres advisory lock, so a second runner waits, then finds
  nothing to do. It logs each migration it applies with its duration.
- It exits `0` when the database is current, whether it applied migrations or
  found none pending, and non-zero with a message naming the failed migration
  otherwise; a failed run rolls back. The exit codes are on the
  [Upgrades](/operate/upgrades/) page.
- Exits after completion (restart: "no"); auth-server waits for it to complete
  successfully.

Run migrations manually, or only check what is pending:

```bash
docker-compose run --rm migration-runner
docker-compose run --rm migration-runner --check
```

The auth server also checks at boot: when the database lacks migrations of its
release, it waits up to `DB_MIGRATION_WAIT_MS` (60 seconds) for the runner,
then exits naming them.

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
  does **not** depend on the auth-server being reachable. The portal build has
  no dedicated `/healthz` route, so there is nothing to `curl`.
- **Production**: `Dockerfile` → runs `node server/index.mjs`, the
  self-contained server the build emits (see below).
- **Development**: `Dockerfile.dev` → `pnpm nx dev developer-portal` (Vite dev
  server); use with `docker-compose.dev.yml` and `--watch`.
- **Depends on**: `auth-server` (healthy).
- **Address**: fixed at `172.30.80.10` on the Compose network, so the
  auth-server's `TRUST_PROXY` can name it (see Production Considerations
  below). If Compose reports that an existing `qauth-network` must be
  recreated, run `docker compose down` once (named volumes are kept).

The portal is built by TanStack Start's Vite plugin alone, which emits a
**self-contained, self-listening** Node server at
`dist/apps/developer-portal/server/index.mjs` (a small srvx server,
`apps/developer-portal/src/node-entry.ts`, with every runtime dependency bundled
in) plus static assets under `public/`. The production image's runner
stage just copies `server/` and `public/` and runs `node server/index.mjs` — no
separate `pnpm deploy` step is needed (`apps/developer-portal/Dockerfile`).

> **Build context note:** the portal source is excluded from the auth-server /
> migration-runner build contexts by the root `.dockerignore` (see the build
> note below). The portal image lifts that exclusion for its own build via a
> sibling `apps/developer-portal/Dockerfile.dockerignore`, which BuildKit
> prefers over the root file when present. No action is needed — this is wired
> up already.

Open the portal at `http://localhost:3001` once the stack is up. Set a
`PORTAL_SESSION_SECRET` in `.env` first (see Environment Variables). A
developer who signs up there can log in only after confirming the address from
the emailed link, so the stack needs a mail provider that delivers (see the
note under Environment Variables).

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

> **The Compose `environment:` map is an allowlist.** The `auth-server` service
> in `docker-compose.yml` configures itself through an explicit `environment:`
> map. There is no `env_file:`, no bind mount of the repo into the container, and
> the root `.dockerignore` excludes `.env` from the build context — so the
> container never reads `.env` itself. Compose reads `.env` only to resolve the
> entries **the map already contains**. A variable the map does not name resolves
> to its schema default inside the container no matter what `.env` says,
> silently.
>
> Every variable documented on this page is on that map, so `.env` works for all
> of them. Entries take one of two forms: `VAR: ${VAR:-default}` restates a
> default in the file, while a bare `VAR:` is a null value that Compose resolves
> from `.env` (or the shell) and omits entirely when unset, letting the schema
> default apply without this file having to track it. Prefer the bare form when
> adding a variable — restating defaults in two places is what let them drift
> apart before.

See `.env.docker.example` for all available variables. Key variables:

| Variable                       | Required | Description                                                                                                                                                      |
| ------------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DB_PASSWORD`                  | Yes      | PostgreSQL password                                                                                                                                              |
| `JWT_PRIVATE_KEY`              | No       | EdDSA private key (PEM format), imported into the realm key store; unset, the first boot generates the signing keys                                              |
| `JWT_PUBLIC_KEY`               | No       | EdDSA public key (PEM format); derived from the private key when unset                                                                                           |
| `KEK`                          | Yes      | Key-encryption key, the base64 of 32 random bytes; wraps every key in the realm key store (or `KEK_PATH`, a file holding it, mounted into the container)         |
| `JWT_ISSUER`                   | No       | JWT issuer URL (default: http://localhost:3000). At first boot it becomes the default realm's permanent issuer; a later boot with another value refuses to start |
| `DEFAULT_REALM_ENDPOINT_HOSTS` | No       | Names server-side callers reach the auth-server by (default: `auth-server`, the developer portal's)                                                              |
| `EMAIL_PROVIDER`               | No       | Email provider: mock, resend, smtp (default: mock)                                                                                                               |
| `REQUIRE_VERIFIED_ACCOUNT`     | No       | Refuse password login until the address is verified (`true`)                                                                                                     |
| `NODE_ENV`                     | No       | `production` (default) or `development` for dev                                                                                                                  |
| `LOG_LEVEL`                    | No       | `info` (default); use `debug` for development                                                                                                                    |

> **The `mock` email provider delivers nothing, and a new account cannot sign in
> until its address is verified.** `REQUIRE_VERIFIED_ACCOUNT` defaults to `true`
> since 2026-10-19: with it off, registering an address and then logging in
> with the chosen password would tell a free address from a registered one. A
> stack on `EMAIL_PROVIDER=mock` therefore cannot complete a sign-up. Point
> `smtp` at a real server or a local mail catcher. For a throwaway local trial
> only, `REQUIRE_VERIFIED_ACCOUNT=false` in `.env` lets unverified accounts sign
> in, and gives that answer back.

#### Developer Portal

| Variable                 | Required | Default                   | Description                                                                           |
| ------------------------ | -------- | ------------------------- | ------------------------------------------------------------------------------------- |
| `PORTAL_SESSION_SECRET`  | Yes      | —                         | 32+ char secret signing the portal session cookie                                     |
| `PORTAL_SESSION_TTL`     | No       | `900`                     | Session cookie lifetime in seconds                                                    |
| `PORTAL_AUTH_SERVER_URL` | No       | `http://auth-server:3000` | Base URL the portal uses (server-side) to reach auth-server                           |
| `QAUTH_NETWORK_PREFIX`   | No       | `172.30.80`               | Compose network `/24` (first three octets); the portal is `<prefix>.10`               |
| `PORTAL_TRUST_PROXY`     | No       | _(unset)_                 | Address of a reverse proxy in front of the portal (single addresses, comma-separated) |

Generate a secret with `openssl rand -hex 32`. The portal will not start without
`PORTAL_SESSION_SECRET`.

For **development** with `docker-compose.dev.yml`, set `NODE_ENV=development` and `LOG_LEVEL=debug` in `.env`.

### Client ID Metadata Documents (CIMD)

CIMD is the recommended MCP client-registration mechanism (see [ADR-007](/reference/records/adr/007-mcp-first-positioning/)) — MCP Authorization 2026-07-28 says authorization servers and MCP clients **SHOULD** support it, and deprecates RFC 7591 dynamic registration in its favour. When a `client_id` is an HTTPS URL, the auth-server fetches and validates the client's metadata document on demand instead of persisting a registration record. All settings have safe defaults — none are required to run.

| Variable                  | Required | Default            | Description                                                                                               |
| ------------------------- | -------- | ------------------ | --------------------------------------------------------------------------------------------------------- |
| `CIMD_ENABLED`            | No       | `true`             | Master switch. When `false`, URL-formatted `client_id`s are rejected with `invalid_client`.               |
| `CIMD_TRUST_POLICY`       | No       | `accept-any-https` | `accept-any-https` (any validating HTTPS document) or `allowlist` (only hosts in `CIMD_TRUSTED_DOMAINS`). |
| `CIMD_TRUSTED_DOMAINS`    | No       | _(empty)_          | Comma/space-separated host allowlist for `allowlist` policy. A leading `*.` permits subdomains.           |
| `CIMD_CACHE_DEFAULT_TTL`  | No       | `300`              | Cache TTL (seconds) when the document carries no usable `Cache-Control`/`Expires`.                        |
| `CIMD_CACHE_MAX_TTL`      | No       | `3600`             | Hard upper bound (seconds) on any cached document, regardless of upstream `max-age`.                      |
| `CIMD_MAX_DOCUMENT_BYTES` | No       | `65536`            | Maximum document size in bytes.                                                                           |
| `CIMD_FETCH_TIMEOUT_MS`   | No       | `5000`             | Per-fetch timeout in milliseconds.                                                                        |

A metadata document and a client's `jwks_uri` are fetched through the egress client and never reach a private, loopback or link-local address, whatever the configuration: the client named them, and the [egress allowlist](#outbound-calls-and-the-egress-allowlist) applies only to destinations the operator or an admin set.

> **Note:** the `CIMD_*` variables are optional and default-safe, so the stack runs without them, and `.env.docker.example` does not list them. The `auth-server` `environment:` map does, so setting them in `.env` takes effect. Be deliberate about `CIMD_TRUST_POLICY`: it defaults to `accept-any-https`, which returns before `CIMD_TRUSTED_DOMAINS` is consulted — so populating the domain list alone changes nothing until you also set `CIMD_TRUST_POLICY=allowlist`.

#### Hostile document hosts

Under `accept-any-https`, anyone can make the server fetch a document from a host they choose, by
sending its URL as a `client_id`. The fetch includes a TLS handshake with that host, and a hostile
host can keep the TLS library busy for seconds per handshake, in one call nothing interrupts. QAuth
never runs that handshake on the thread that serves requests:

- The CIMD and `jwks_uri` fetches run on worker threads, at most 8 at a time and 2 per host name. A
  thread a host keeps busy holds its slot until the handshake ends, so a caller with many host names
  can fill all 8. Other documents that are not cached then fail to load, and their clients are
  refused, until the slots free.
- The SSRF-safe egress client, which these fetches move to (#481), runs each exchange in a fetch
  process of its own instead. A process is killed at its deadline and a fresh one takes its place,
  so a hostile host holds a slot for no longer than the deadline. At most 8 processes run, and the
  host names under one registrable domain (`a.example.com`, `b.example.com`) share 2 of them. A
  process starts with an empty environment and, on Linux, none of the server's open files (on
  other systems, a descriptor the server inherited without close-on-exec reaches it). Each takes about
  70 MB, so a full pool needs about 600 MB beside the server; Linux ends a fetch process first
  when memory runs out.

Neither makes a hostile host free: a caller who names enough domains still keeps fetches busy until
their deadlines. The mitigation is `CIMD_TRUST_POLICY=allowlist`: the server then fetches a Client
ID Metadata Document only from the hosts in `CIMD_TRUSTED_DOMAINS`, so an unauthenticated caller
can no longer pick the host.

#### Granting scopes to a CIMD client

A CIMD client starts with no scopes, so it is granted none of the scopes it asks for. Its document owns its name, redirect URIs and grant types; which scopes it may receive is the operator's decision, which a document cannot make. Grant them in the `cimd_clients` section of the seed manifest, and run `db:seed-oauth-clients` as for any other manifest:

```json
{
  "realm": "master",
  "cimd_clients": [
    {
      "client_id": "https://client.example.com/oauth/metadata.json",
      "scopes": ["mcp:read", "mcp:write", "offline_access"],
      "audience": ["https://mcp.example.com/mcp"]
    }
  ]
}
```

- Write `client_id` exactly as the client sends it: an `https` URL of at most 255 ASCII characters, with a path beyond `/` and no fragment.
- An entry sets only `scopes` and `audience`. `audience` is the token audience when the client names no `resource`. An empty `scopes` list withdraws the grant.
- `audience` cannot hold a value in the reserved `urn:qauth:aud:` namespace, such as the developer API's `urn:qauth:aud:developer:v1-rc.0`: a CIMD client never gets an API family audience ([API conventions](/reference/api-conventions/#issuing-a-family-audience)). A `clients` entry may list one, and the token endpoint then issues it to that client.
- An entry has no secret, so the seed prints none and `--rotate` does not apply. Every run sets the row to the entry's values and leaves the rest of it alone.
- Until the client's first authorization, its row has no redirect URI. That authorization reads the document and fills the row in, and later re-resolutions never change the grant.
- The grant is a ceiling: the user still consents, for each resource.
- The seed refuses an entry whose `client_id` belongs to a client that is not a CIMD client, and changes nothing for it.
- The client resolves only while `CIMD_ENABLED` is `true` and the trust policy accepts its host.

### Redirect URI schemes for native apps

A redirect URI must be `https`, `http` to a loopback host, or a private-use scheme written as a reverse domain name, such as `com.example.app:/callback` (RFC 8252 §7.1). Some native apps call back on a scheme without a period instead. Cursor's desktop app, for one, uses `cursor://anysphere.cursor-mcp/oauth/callback`. List each such scheme you accept in `REDIRECT_URI_CUSTOM_SCHEMES`:

```bash
# .env — accept the Cursor desktop app's callback
REDIRECT_URI_CUSTOM_SCHEMES=cursor
```

| Variable                      | Required | Default   | Description                                                                                                       |
| ----------------------------- | -------- | --------- | ----------------------------------------------------------------------------------------------------------------- |
| `REDIRECT_URI_CUSTOM_SCHEMES` | No       | _(empty)_ | Scheme names, separated by spaces or commas, that a redirect URI may use besides the three kinds above. No colon. |

- A listed scheme is accepted everywhere a redirect URI is: dynamic client registration, `POST /api/clients`, CIMD documents, a seeded client, `/oauth/authorize` and the consent screen. Matching stays exact.
- Without it, registration refuses such a URI with `invalid_redirect_uri: unsupported scheme`, and `/oauth/authorize` refuses one already stored with `redirect_uri not permitted for this environment`. The client's `https` and loopback callbacks keep working either way.
- The default is empty on purpose. The reverse-domain form only makes an accidental clash between two apps unlikely. Neither form stops a malicious app on the same device from claiming the scheme; PKCE, which QAuth requires of every client, is what protects the code (RFC 8252 §8.1). Which apps to trust on your users' devices is your choice, one scheme at a time.
- The server refuses to start when an entry is not a scheme name, or names a scheme a browser or the operating system acts on itself: `http`, `https`, `javascript`, `data`, `file`, `blob`, `intent`, `mailto` and the like. Such schemes are refused at authorization whatever the list holds.

### ID-JAG / enterprise-managed authorization (ADR-011)

**Off by default**, and doubly fail-closed: with `ID_JAG_ENABLED` off the
`jwt-bearer` grant is neither advertised nor accepted, and even with it on an
empty `ID_JAG_TRUSTED_ISSUERS` rejects every assertion and keeps the grant out
of the discovery metadata. See
[ID-JAG](/integrate/oauth-flow/#id-jag--enterprise-managed-authorization-adr-011).

| Variable                         | Required          | Default   | Description                                                                                                                                                                                                                                                                                                          |
| -------------------------------- | ----------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ID_JAG_ENABLED`                 | No                | `false`   | Master switch. Gates both the `jwt-bearer` grant and the discovery members that advertise it.                                                                                                                                                                                                                        |
| `ID_JAG_TRUSTED_ISSUERS`         | Yes, when enabled | _(empty)_ | Allowlist of enterprise IdP issuers whose assertions may be redeemed. Empty rejects everything — an assertion never nominates its own trust.                                                                                                                                                                         |
| `ID_JAG_MAX_ASSERTION_LIFETIME`  | No                | `300`     | Seconds. Bounds the replay window a `jti` is tracked for.                                                                                                                                                                                                                                                            |
| `ID_JAG_ISSUED_LIFETIME`         | No                | `300`     | Seconds. Lifetime stamped on assertions QAuth **mints**, capped at the subject token's remaining lifetime.                                                                                                                                                                                                           |
| `ID_JAG_CLOCK_SKEW_LEEWAY`       | No                | `60`      | Seconds of tolerance on `exp` / `nbf` / `iat`.                                                                                                                                                                                                                                                                       |
| `ID_JAG_JWKS_CACHE_TTL`          | No                | `300`     | Seconds to cache a trusted issuer's discovery document and JWKS. At most `3600`: a larger value stops the server at boot. `0` turns the cache off, and every assertion then costs the issuer two fetches.                                                                                                            |
| `ID_JAG_JWKS_REFRESH_COOLDOWN`   | No                | `30`      | Seconds between two refreshes that an assertion with an unknown `kid` may force for one issuer. Inside the cooldown such an assertion is refused without a fetch, so a rotated key is picked up at most this long after it is first presented, or after the negative cache below lapses if a fetch failed. 1 to 300. |
| `ID_JAG_JWKS_NEGATIVE_CACHE_TTL` | No                | `30`      | Seconds a failed discovery or JWKS fetch is remembered. Meanwhile nothing is fetched from that issuer, so an outage costs one attempt per window; keys already cached keep working. 1 to 300.                                                                                                                        |
| `ID_JAG_FETCH_TIMEOUT_MS`        | No                | `5000`    | Timeout for issuer discovery / JWKS fetches.                                                                                                                                                                                                                                                                         |
| `ID_JAG_MAX_DOCUMENT_BYTES`      | No                | `65536`   | Size cap on a fetched discovery or JWKS document.                                                                                                                                                                                                                                                                    |

> **Note:** the `auth-server` `environment:` map forwards every `ID_JAG_*`
> variable, so setting them in `.env` takes effect. A trusted issuer's
> discovery URL is an operator-set destination: an
> [egress allowlist](#outbound-calls-and-the-egress-allowlist) entry can open
> its private host for a realm. The `jwks_uri` its discovery document names
> never reaches a private address, so an issuer whose keys sit on a private
> network cannot be used from discovery alone yet.

#### Provisioning a client for ID-JAG

The switches above turn the feature on. Each client still needs its own list of
targets: the foreign authorization servers and MCP servers it may name when it
mints an ID-JAG, and the MCP servers it may redeem an assertion for. Set it with
`id_jag_targets` on the client's entry in the `db:seed-oauth-clients` manifest:

```json
{
  "realm": "master",
  "clients": [
    {
      "client_id": "partner-agent",
      "name": "Partner agent (mints ID-JAGs)",
      "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"],
      "scopes": ["chat.read"],
      "token_endpoint_auth_method": "client_secret_basic",
      "is_agent": true,
      "id_jag_targets": ["https://auth.partner.example", "https://mcp.partner.example/mcp"]
    },
    {
      "client_id": "enterprise-mcp-client",
      "name": "MCP client (redeems ID-JAGs)",
      "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
      "scopes": ["chat.read"],
      "token_endpoint_auth_method": "client_secret_basic",
      "id_jag_targets": ["https://mcp.example.com/mcp"]
    }
  ]
}
```

Two client columns hold resource identifiers, and each does one job:

| Manifest field   | Column                         | What it bounds                                                                                                                                                                                  |
| ---------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audience`       | `oauth_clients.audience`       | The tokens QAuth issues to the client: the `resource` values `client_credentials` accepts, the token `aud` when a grant names no `resource`, and the token audiences the client may introspect. |
| `id_jag_targets` | `oauth_clients.id_jag_targets` | ID-JAG only. Minting: the `audience` (the target authorization server's issuer) and the `resource` (the MCP server) must both be listed. Redeeming: the assertion's `resource` must be listed.  |

- Neither list falls back to the other. A server listed only in `audience` is not
  an ID-JAG target, and one listed only in `id_jag_targets` is not a
  `client_credentials` audience.
- An empty or missing `id_jag_targets` denies both minting and redeeming.
- Only the manifest's `clients` entries set it. Dynamic registration,
  `POST /api/clients`, a CIMD metadata document and the manifest's `cimd_clients`
  entries cannot, and a client created by one of them has an empty list.
- The seed skips a client that already exists. To change the list of an existing
  client, re-run its entry with `--rotate`, which also issues a new secret, or set
  `oauth_clients.id_jag_targets` with an `UPDATE` by hand.
- Before migration 0027 the targets were read from `audience`. The migration
  copies nothing, so a client set up that way mints and redeems nothing until its
  targets are listed here.

### Outbound calls and the egress allowlist

The outbound calls the server makes for a configuration value or a request (the
CIMD, client `jwks_uri` and ID-JAG issuer fetches, the SSF push) go through one
SSRF-safe egress client: `https` only, every address of the
host checked, the connection pinned to the checked addresses, redirects checked
the same way, time and size capped
([ADR-019 Decision 8](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)).
It never reaches a private, loopback or link-local address, unless the
deployment allowlist names the host or range **and** the destination was set by
the operator or a realm admin, for a realm the entry names. A destination that a
client, an end user or a fetched document supplies (a CIMD `client_id`, a
client's `jwks_uri`, the `jwks_uri` of an issuer's discovery document) never
uses the allowlist. The wallet status-list fetch keeps its own URI-prefix
allowlist for now, and the OpenTelemetry export and a KEK custody adapter
(`KEK_PROVIDER`) make their own connections: their destinations are
deployment-wide configuration, outside the egress client by ADR-019's
amendments of 2026-10-24 and 2026-10-27.

`EGRESS_ALLOWLIST_PATH` names the allowlist, a JSON file the operator writes:

```json
{
  "entries": [
    { "host": "idp.corp.example", "realms": ["master"] },
    { "cidr": "10.20.0.0/16", "realms": ["master", "acme"], "note": "partner VPN" }
  ]
}
```

- Each entry names one `host` (exact, no wildcard) or one `cidr` range, and the
  realms it applies to, by realm name.
- A `host` entry opens the private (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`), shared (`100.64.0.0/10`) and unique-local (`fc00::/7`)
  addresses its name resolves to. Loopback, link-local and other special
  ranges open only through a `cidr` entry that names them.
- A `cidr` entry is not tied to a host: any operator or admin destination of
  the realms it names that resolves into the range is allowed. It may be no
  wider than `/8` (IPv4) or `/32` (IPv6), and may not overlap a range that
  reaches other addresses only through translation (IPv4-mapped
  `::ffff:0:0/96`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4
  `2002::/16`, Teredo `2001::/32`).
- The server reads the file once, at boot. A file that cannot be read, does
  not validate or others can write stops the boot, naming the variable, the
  file and the mistake; a file its group can write, or that neither root nor
  the server's user owns, gives a warning.
- The list is not in the database, and no API reads or edits it, so a realm
  admin cannot widen it.
- No entry opens an unspecified (`0.0.0.0`) or multicast address, or a cloud
  metadata endpoint (`169.254.169.254`, `169.254.170.0/24`, `100.100.100.200`,
  `fd00:ec2::/32`), and a redirect to another host never uses the entry that
  let the first request through.

With Compose, mount the file read-only and name its path in `.env`:

```yaml
# docker-compose.override.yml
services:
  auth-server:
    volumes:
      - ./egress-allowlist.json:/etc/qauth/egress-allowlist.json:ro
```

```bash
# .env
EGRESS_ALLOWLIST_PATH=/etc/qauth/egress-allowlist.json
```

`CIMD_ALLOW_PRIVATE_ADDRESSES` and `ID_JAG_ALLOW_PRIVATE_ADDRESSES` are gone:
set to any value, they stop the boot with a message that names
`EGRESS_ALLOWLIST_PATH`. Tests reach a local fixture server through the
test-only `createTestEgressClient` instead.

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
| `OID4VP_EMAIL_VERIFYING_ISSUERS`    | No                | _(unset)_      | Issuers whose wallet `email` counts as verified without a disclosed `email_verified: true`. Unset means none. List only issuers that never issue unverified addresses.                   |
| `OID4VP_ISSUER_ASSURANCE`           | No                | _(unset)_      | Per-issuer eIDAS level of assurance, mapped to the OIDC `acr` claim ([ADR-010](/reference/records/adr/010-acr-assurance-mapping/)). Listing an issuer here does **not** make it trusted. |
| `OID4VP_STATUS_LIST_TRUST_ANCHORS`  | No                | _(empty)_      | Trust anchors for Token Status List revocation checking (or `_PATH` to read them from a file).                                                                                           |
| `OID4VP_STATUS_LIST_URI_ALLOWLIST`  | No                | _(empty)_      | Permitted status-list URIs.                                                                                                                                                              |
| `OID4VP_STATUS_LIST_SIGNERS`        | No                | _(unset)_      | Which status issuer may sign the lists under a URI prefix on another host (a CDN), as JSON. Unset: the signer's certificate must name the list host.                                     |
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
> post-quantum variables. Both features are off by default, so the stack runs
> without them. The `auth-server` `environment:` map does list them — every
> wallet variable above including the four `OID4VP_SUBJECT_*`, and every
> post-quantum one (`SIGNING_ALGORITHM_MODE`, `HYBRID_SIGNING_ENABLED`,
> `JWT_MLDSA_*`, `PQC_*`) — so all of them can be set from `.env`. Note that
> `OID4VP_SUBJECT_BINDING_CLAIMS` is required once the wallet flag is on: leaving
> it unset refuses every sign-in rather than falling back to a default.

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

# List the pending migrations without changing anything
docker-compose run --rm migration-runner --check

# Re-run migrations
docker-compose run --rm migration-runner
```

A failed run names the migration that failed and rolls the whole run back, so
running it again after fixing the cause is safe.

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
4. **Add reverse proxy** (nginx, Traefik) with TLS termination, and set
   `TRUST_PROXY` to the addresses allowed to report the client address. Every
   per-IP rate limit and the failed-login lockout key on the client address.
   Without `TRUST_PROXY`, the auth-server sees every request as coming from the
   proxy, so all users share one bucket and one caller can lock everyone out.
   The developer portal counts as a proxy too: it forwards one address, the
   client of the connection it is serving. List only the addresses of the
   proxies in front of the auth-server and of the developer portal, never a
   range that clients can connect from. A broad private range such as
   `uniquelocal`, or the whole Docker network, also covers the bridge gateway,
   which host-local and published-port clients appear from. In this Compose
   stack the portal has a fixed address, `172.30.80.10`, so
   `TRUST_PROXY=172.30.80.10` names the portal alone; add a reverse proxy's own
   address after a comma. `TRUST_PROXY=true` and hop counts are rejected,
   because they would let any caller choose its own address.
   With a TLS proxy in front of the portal, set `PORTAL_TRUST_PROXY` on the
   portal to that proxy's address, so the portal forwards each visitor's
   address rather than the proxy's, and set `TRUST_PROXY` on the auth-server to
   the portal's fixed address, plus the proxy's if the auth-server is behind it
   too. Every reverse proxy named in `PORTAL_TRUST_PROXY` or `TRUST_PROXY` must
   append the address it accepted the connection from to `X-Forwarded-For`
   (for example, nginx:
   `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`), so the
   last entry is always one it wrote; the portal sets the header itself. The
   first hop, the proxy clients connect to, may instead replace the header
   with that address, as the reference configuration does; a proxy behind
   another trusted hop must append. Use
   single addresses in both, never a client range; on the Compose network,
   give the proxy a fixed address below `<prefix>.128`, such as
   `172.30.80.20`. If `172.30.80.0/24` overlaps a network on your host, set
   `QAUTH_NETWORK_PREFIX` to the first three octets of a free `/24`; the
   portal is then `<prefix>.10`.
   The proxy must also pass the host the client asked for. The auth-server
   answers a request only on the realm host, the host of `JWT_ISSUER`, and on
   the names in `DEFAULT_REALM_ENDPOINT_HOSTS`; any other host gets
   `421 Misdirected Request`, and only `/health` answers on every host. Keep
   the client's `Host` header (nginx: `proxy_set_header Host $host;`), or send
   it as `X-Forwarded-Host` from an address listed in `TRUST_PROXY`; from any
   other address that header is ignored. A proxy listed in `TRUST_PROXY` must
   set `X-Forwarded-Host` itself or remove it (nginx:
   `proxy_set_header X-Forwarded-Host $host;`), because the auth-server
   believes the value it forwards, and one passed through from the client
   would let the client pick the realm. An endpoint host answers the API
   routes only: the sign-in pages, `/oauth/authorize` and `/consents` answer
   421 there. [Reverse Proxy](/operate/reverse-proxy/) lists every rule the
   proxy follows, and the reference nginx configuration that implements them.
5. **Configure resource limits** in Docker/Kubernetes. `docker-compose.yml`
   caps the auth-server at 1 GiB and the developer portal at 512 MiB and
   restarts both after a crash (`restart: unless-stopped`); size the limits to
   your load. The portal also reads at most 1 MiB of any request body.
6. **Size the Argon2 thread pool to the host.** Every presented
   `client_secret`, password and API key is checked with Argon2id on Node's
   libuv thread pool, which also verifies and signs every JWT (through
   WebCrypto) and runs the database's SCRAM handshake. The pool has
   `UV_THREADPOOL_SIZE` threads, 4 unless set, and QAuth lets Argon2 use at
   most half of them, so that token checks keep threads during a burst of
   logins or client secrets. With the default, two Argon2 checks run at once
   whatever the host has. **On a host with four or more cores, raise
   `UV_THREADPOOL_SIZE`**, for example to the core count, so that more checks
   run at once. It is Node's setting, not QAuth's: set it in the process
   environment (`docker-compose.yml` forwards it from `.env`). Each
   concurrent check holds `PASSWORD_MEMORY_COST` (64 MiB by default), so raise
   the memory limit with it.

   Checks beyond the running ones wait in a queue. A client-secret check
   (`/oauth/token`, `/oauth/introspect`, `/oauth/revoke`) that would wait
   behind `PASSWORD_HASH_QUEUE_LIMIT` others (32 by default) is refused at
   once, before any hash, with `503 Service Unavailable`,
   `"error": "temporarily_unavailable"` and `Retry-After: 1`, rather than
   waiting until its caller times out. Each refusal is logged at `warn` with
   the client and the queue length, and counted in
   `qauth_client_secret_checks_shed_total` (see
   [Observability](/operate/observability/#metrics-get-metrics)). Sign-ins and
   registrations are not refused: they wait their turn, and count toward the
   queue while they wait. Raise the limit if legitimate clients see these
   refusals while the host has CPU to spare; lower it to fail faster.

7. **Set up monitoring** (Prometheus, Grafana)
8. **Enable logging aggregation** (ELK, Loki)

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
- [Upgrades](/operate/upgrades/) — the upgrade procedure (back up, run `migration-runner`, start the new version) and the runbook of the destructive ADR-002 migration 0011.
- [Observability](/operate/observability/) — logging, metrics, and alerting once the stack is up.
- [Environment-Aware Authorization](/operate/environment-authorization/) — the `environment` policy dimension referenced throughout this stack.
