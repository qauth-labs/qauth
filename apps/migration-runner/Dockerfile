# Migration Runner Dockerfile
# Runs database migrations using Nx targets from infra-db. Requires
# BuildKit (default on Docker 23+) for the `--mount=type=cache` pnpm-store
# mount.
#
# syntax=docker/dockerfile:1.7

# Stage 1: Base image with corepack + root workspace manifests.
# No install here — see the auth-server Dockerfile for the reason.
FROM node:24-alpine AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY nx.json tsconfig.base.json ./

# Stage 2: Full workspace (needed for Nx to resolve the project graph).
FROM deps AS workspace
COPY vitest.config.ts ./
COPY libs ./libs
COPY apps ./apps

# Install with a cache mount for pnpm's package store — see auth-server
# Dockerfile for the full rationale.
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --store-dir /pnpm/store

# Copy entrypoint script
COPY apps/migration-runner/docker-entrypoint.sh ./docker-entrypoint.sh
# Fix Windows line endings (CRLF) and permissions
RUN sed -i 's/\r$//' ./docker-entrypoint.sh && \
    chmod +x ./docker-entrypoint.sh

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /app

USER nodejs

ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]
