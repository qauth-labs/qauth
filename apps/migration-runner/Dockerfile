# Migration Runner Dockerfile (#474, ADR-018 §5).
#
# Every upgrade ends by running this image. It holds Node and one bundled
# program, `main.js`, with the generated migrations in `drizzle/` beside it:
# no pnpm, nx, tsx or drizzle-kit, and no workspace. The program applies the
# pending migrations to DATABASE_URL under a Postgres advisory lock, so a
# second runner waits and then finds nothing to do; `--check` reports the
# pending migrations and changes nothing. See apps/migration-runner/src/main.ts.
#
# Requires BuildKit (default on Docker 23+) for the `--mount=type=cache`
# pnpm-store mount.
#
# syntax=docker/dockerfile:1.7

# Stage 1: build the bundle with the workspace's own tools.
FROM node:26-alpine AS builder
WORKDIR /app
# pnpm comes from npm at the exact version CI uses. Node 26 no longer ships
# corepack. It stays in this stage.
ARG PNPM_VERSION=12.14.0
RUN npm install --global pnpm@${PNPM_VERSION}
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY nx.json tsconfig.base.json ./
COPY vitest.config.mts ./
COPY libs ./libs
COPY apps ./apps

# Install with a cache mount for pnpm's package store — see the auth-server
# Dockerfile for the full rationale.
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --store-dir /pnpm/store

# dist/apps/migration-runner: main.js (the program, pg and drizzle-orm in one
# file) and drizzle/ (a copy of libs/infra/db/drizzle).
RUN NX_DAEMON=false NX_NO_CLOUD=true \
    pnpm nx run migration-runner:build --skip-nx-cache

# Stage 2: Node and the bundle, nothing else.
FROM node:26-alpine AS runner
WORKDIR /app

RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Owned by root and only readable by the runtime user: the program cannot
# change itself or the migrations it applies.
COPY --from=builder /app/dist/apps/migration-runner/main.js ./main.js
COPY --from=builder /app/dist/apps/migration-runner/drizzle ./drizzle

# The image must stay free of development tools (#474). This fails the build
# when one of them reaches it, by command or as an installed package.
RUN set -eu; \
    for tool in pnpm nx tsx drizzle-kit; do \
      if command -v "$tool" >/dev/null 2>&1; then \
        echo "The migration runner image must not contain $tool" >&2; exit 1; \
      fi; \
    done; \
    found="$(find / -xdev -type d \( -name pnpm -o -name nx -o -name tsx -o -name drizzle-kit \) \
      -path '*/node_modules/*' 2>/dev/null)"; \
    if [ -n "$found" ]; then \
      echo "The migration runner image must not contain these packages:" >&2; \
      echo "$found" >&2; exit 1; \
    fi; \
    test -f /app/drizzle/meta/_journal.json

USER nodejs

ENTRYPOINT ["node", "/app/main.js"]
