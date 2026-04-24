# Auth Server Dockerfile — production image.
#
# Strategy: `pnpm deploy` for a self-contained tree, then run TypeScript
# sources under tsx at startup.
#
# An earlier iteration of this Dockerfile tried to ship the Nx esbuild
# prod bundle. That path hit a chain of mismatches — pnpm's no-hoist
# layout scattered deps, Nx emitted `package.js` where Node expected
# `package.json`, the custom main.js resolver's manifest was empty, and
# transitive workspace deps couldn't be resolved via file-system lookups.
# pnpm-deploy-plus-tsx is substantially simpler and idiomatic for pnpm
# workspaces. If we later want a bundled image, the right fix is in
# qauth's Nx config (populating the main.js manifest), not here.
#
# Requires BuildKit (default on Docker 23+) for the `--mount=type=cache`
# pnpm-store mount.
#
# syntax=docker/dockerfile:1.7

# Stage 1: Workspace + install.
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

# Produce a self-contained deploy bundle at /deploy containing:
#   - apps/auth-server's full source
#   - all workspace deps (real copies, not symlinks) under node_modules/@qauth-labs/
#   - all external prod deps under node_modules/
# We keep devDeps out via --prod.
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm --filter @qauth-labs/auth-server deploy --prod --legacy \
    --store-dir /pnpm/store /deploy

# Stage 2: Runner.
FROM node:24-alpine AS runner
WORKDIR /app

# tsx is a lightweight TypeScript runner (zero config) that we use as
# the production entrypoint. Kept global so the deployed bundle's
# node_modules stays tight to the app's own runtime deps.
RUN npm install --global tsx@4

# Create the non-root user up-front so the subsequent COPY --chown can
# reference it. Chowning at COPY time avoids a trailing `chown -R /app`
# pass, which would otherwise rewrite the entire ~450MB deploy layer.
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy the self-contained deploy.
COPY --from=builder --chown=nodejs:nodejs /deploy ./

# Entrypoint: tsx on auth-server's TS entry. Since this is a deploy bundle,
# workspace packages live as real copies under ./node_modules/@qauth-labs/
# and external deps under ./node_modules/ — Node's normal resolution finds
# both without any custom resolver or generated manifest.
COPY --chown=nodejs:nodejs apps/auth-server/docker-entrypoint.sh ./docker-entrypoint.sh
# BusyBox `sed -i` writes a temp file and renames it, which resets the
# file's ownership to root; re-chown the single file back to nodejs so
# USER nodejs can exec it cleanly. (Per-file chown, not -R — cheap.)
RUN sed -i 's/\r$//' ./docker-entrypoint.sh && \
    chmod +x ./docker-entrypoint.sh && \
    chown nodejs:nodejs ./docker-entrypoint.sh

USER nodejs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]
