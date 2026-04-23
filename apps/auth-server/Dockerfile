# Auth Server Dockerfile
# Multi-stage build for production. Requires BuildKit (default on Docker
# 23+) for the `--mount=type=cache` pnpm-store mount.
#
# syntax=docker/dockerfile:1.7

# Stage 1: Base image with corepack + root workspace manifests.
#
# We intentionally do NOT run `pnpm install` here. pnpm-workspace.yaml points
# at apps/** and libs/**; without those directories on disk, the install
# only resolves root-manifest deps and leaves every workspace-scoped dep
# (fastify, @fastify/*, etc.) out of node_modules. The install happens in
# the builder stage, once workspace sources are in place.
FROM node:24-alpine AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY nx.json tsconfig.base.json ./

# Stage 2: Builder
FROM deps AS builder
# Copy root vitest.config.ts (needed for Nx project-graph processing)
COPY vitest.config.ts ./
COPY libs ./libs
COPY apps ./apps

# Install with a cache mount for pnpm's package store — lockfile changes
# or source changes invalidate the layer, but downloaded/extracted packages
# persist across builds, so only the workspace symlink graph is rebuilt.
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --store-dir /pnpm/store

# Build auth-server and all its dependencies
RUN pnpm nx build auth-server --prod

# Stage 3: Runner (minimal production image)
FROM node:24-alpine AS runner
WORKDIR /app

# Enable corepack to use correct pnpm version
RUN corepack enable

# Copy built application bundle. Nx's build output already embeds the
# compiled workspace libs at `./libs/` inside this directory and main.js
# contains a resolver that points `@qauth-labs/*` at them.
COPY --from=builder /app/dist/apps/auth-server ./

# Copy package files for dependency resolution
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/pnpm-lock.yaml ./pnpm-lock.yaml
COPY --from=builder /app/pnpm-workspace.yaml ./pnpm-workspace.yaml

# Copy node_modules (includes workspace dependencies)
# This is the simplest approach for monorepo - can be optimized later
COPY --from=builder /app/node_modules ./node_modules

# Copy entrypoint script
COPY apps/auth-server/docker-entrypoint.sh ./docker-entrypoint.sh
# Fix Windows line endings (CRLF) and permissions
RUN sed -i 's/\r$//' ./docker-entrypoint.sh && \
    chmod +x ./docker-entrypoint.sh

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]
