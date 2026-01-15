# Docker Development Guide

This guide covers the Docker setup for local development of QAuth.

## Overview

QAuth uses Docker Compose to orchestrate the following services:

| Service              | Image                | Purpose                                                  |
| -------------------- | -------------------- | -------------------------------------------------------- |
| **postgres**         | `postgres:18-alpine` | Primary database (PostgreSQL 18 with `uuidv7()` support) |
| **redis**            | `redis:7-alpine`     | Session cache and rate limiting                          |
| **migration-runner** | Custom               | Runs database migrations via Nx                          |
| **auth-server**      | Custom               | Main authentication API server                           |

## Prerequisites

- Docker 20.10+ and Docker Compose 2.0+
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

```bash
# Start all services (builds images on first run)
docker-compose up -d

# Watch logs
docker-compose logs -f
```

### 4. Verify Setup

```bash
# Check all services are healthy
docker-compose ps

# Test health endpoint
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

- **Image**: `redis:7-alpine`
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
- **Entrypoint**: `/app/docker-entrypoint.sh`

## Common Operations

### Rebuild Images

After code changes:

```bash
# Rebuild and restart
docker-compose up -d --build

# Or rebuild specific service
docker-compose build auth-server
docker-compose up -d auth-server
```

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
