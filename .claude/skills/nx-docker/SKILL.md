---
name: nx-docker
description: Docker and containerization for Nx projects. Use when building images, managing containers, or working with docker-compose.
---

# Docker & Containerization

## Development Stack

```bash
# Start services
docker compose up -d
docker compose up -d postgres redis

# Logs
docker compose logs -f

# Stop
docker compose down
docker compose down -v  # Remove volumes
```

## Services

| Service    | Port | Purpose       |
| ---------- | ---- | ------------- |
| `postgres` | 5432 | PostgreSQL 18 |
| `redis`    | 6379 | Redis 7 cache |

## Building Images

```bash
# Build with Nx
pnpm nx build auth-server --configuration=production

# Build Docker image
docker build -t qauth/auth-server:latest -f apps/auth-server/Dockerfile .

# Prune for minimal image
pnpm nx run auth-server:prune
```

## Multi-Stage Build Pattern

```dockerfile
# Stage 1: Build
FROM node:24-alpine AS builder
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm nx build auth-server --configuration=production
RUN pnpm nx run auth-server:prune

# Stage 2: Run
FROM node:24-alpine AS runner
WORKDIR /app
COPY --from=builder /app/dist/apps/auth-server .
RUN pnpm install --prod --frozen-lockfile
CMD ["node", "main.js"]
```

## Fresh Dev Setup

```bash
docker compose up -d postgres redis
docker compose exec postgres pg_isready -U postgres
pnpm nx run infra-db:db:migrate
pnpm nx run infra-db:db:seed
pnpm nx serve auth-server
```

## Debugging

```bash
docker compose exec postgres bash
docker compose exec postgres psql -U postgres -d qauth
docker compose exec redis redis-cli
```

## Cleanup

```bash
docker compose down           # Stop containers
docker compose down -v        # Remove volumes
docker compose down --rmi local  # Remove images
```

## Testcontainers

```typescript
import { PostgreSqlContainer } from '@testcontainers/postgresql';

const container = await new PostgreSqlContainer().withDatabase('qauth_test').start();
```
