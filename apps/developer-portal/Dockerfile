# Developer Portal Dockerfile — production image.
#
# The portal is a TanStack Start app. Its Vite build emits a
# framework-agnostic fetch handler (`server/server.js`, default export
# `{ fetch }`) plus static client assets (`client/`) — it does NOT ship a
# self-listening server. We therefore:
#   1. build the app with Nx (`vite build`), and
#   2. run it behind a tiny Node adapter (`server.mjs`) that pipes
#      `node:http` requests into the fetch handler and serves the client
#      assets.
#
# Dependency strategy mirrors the auth-server prod image: `pnpm deploy`
# produces a self-contained tree whose node_modules contains real copies of
# the workspace + external prod deps, so the build output's bare imports
# (react, @tanstack/*) resolve at runtime without a custom resolver.
#
# Requires BuildKit (default on Docker 23+) for the `--mount=type=cache`
# pnpm-store mount. A sibling `Dockerfile.dockerignore` lifts the root
# `.dockerignore`'s exclusion of `apps/developer-portal` for this build only.
#
# syntax=docker/dockerfile:1.7

# Stage 1: Workspace install + Nx build + pnpm deploy.
FROM node:24-alpine AS builder
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY nx.json tsconfig.base.json ./
COPY vitest.config.ts ./
COPY libs ./libs
COPY apps ./apps

# Install with a cache mount for pnpm's package store.
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --store-dir /pnpm/store

# Build the TanStack Start app -> dist/apps/developer-portal/{server,client}.
RUN pnpm nx build developer-portal

# Produce a self-contained deploy bundle at /deploy containing the portal's
# prod node_modules (real copies, not symlinks across the store).
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm --filter @qauth-labs/developer-portal deploy --prod --legacy \
    --store-dir /pnpm/store /deploy

# Stage 2: Runner.
FROM node:24-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Non-root user, created before COPY --chown so layers land owned correctly.
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Self-contained prod node_modules from the deploy bundle.
COPY --from=builder --chown=nodejs:nodejs /deploy/node_modules ./node_modules

# Built app output: SSR fetch handler + static client assets.
COPY --from=builder --chown=nodejs:nodejs /app/dist/apps/developer-portal/server ./server
COPY --from=builder --chown=nodejs:nodejs /app/dist/apps/developer-portal/client ./client

# Node adapter (container entrypoint) + entrypoint script.
COPY --chown=nodejs:nodejs apps/developer-portal/server.mjs ./server.mjs
COPY --chown=nodejs:nodejs apps/developer-portal/docker-entrypoint.sh ./docker-entrypoint.sh
# BusyBox `sed -i` rewrites + re-owns to root; re-chown the single file so
# USER nodejs can exec it. (Per-file chown, not -R — cheap.)
RUN sed -i 's/\r$//' ./docker-entrypoint.sh && \
    chmod +x ./docker-entrypoint.sh && \
    chown nodejs:nodejs ./docker-entrypoint.sh

USER nodejs

ENV PORT=3001
ENV HOST=0.0.0.0
EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/healthz', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)}).on('error', () => process.exit(1))"

ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]
