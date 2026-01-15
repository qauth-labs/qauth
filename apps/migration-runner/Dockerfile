# Migration Runner Dockerfile
# Runs database migrations using Nx targets from infra-db
# This maintains separation of concerns: infra-db owns migrations

# Stage 1: Dependencies
FROM node:24-alpine AS deps
WORKDIR /app

# Copy only package files first (layer caching)
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY nx.json tsconfig.base.json ./

# Enable corepack to use correct pnpm version from package.json
RUN corepack enable && \
    pnpm install --frozen-lockfile

# Stage 2: Full workspace (needed for Nx to work)
FROM deps AS workspace
# Copy root vitest.config.ts (needed for Nx project graph processing)
COPY vitest.config.ts ./
COPY libs ./libs
COPY apps ./apps

# Copy entrypoint script
COPY apps/migration-runner/docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /app

USER nodejs

ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]
