# Developer Portal Dockerfile — production image.
#
# The portal is a TanStack Start app built with the Nitro v2 Vite plugin.
# `nx build` emits a self-contained, self-listening Node server at
# `dist/apps/developer-portal/server/index.mjs` (Nitro bundles its runtime
# deps into `server/node_modules`) plus static assets under `public/`. So the
# runner just copies that output and runs `node server/index.mjs` — no custom
# adapter and no separate `pnpm deploy` step are needed.
#
# Requires BuildKit (default on Docker 23+) for the `--mount=type=cache`
# pnpm-store mount. A sibling `Dockerfile.dockerignore` lifts the root
# `.dockerignore`'s exclusion of `apps/developer-portal` for this build only.
#
# syntax=docker/dockerfile:1.7

# Stage 1: Workspace install + Nx build.
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

# Build the TanStack Start + Nitro app. Output (server/ with bundled
# node_modules, public/) lands in dist/apps/developer-portal.
RUN pnpm nx build developer-portal

# Stage 2: Runner.
FROM node:24-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Non-root user, created before COPY --chown so layers land owned correctly.
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Self-contained Nitro output: the Node server (with its bundled deps) plus
# the static assets it serves. Nothing else is required at runtime.
COPY --from=builder --chown=nodejs:nodejs /app/dist/apps/developer-portal/server ./server
COPY --from=builder --chown=nodejs:nodejs /app/dist/apps/developer-portal/public ./public

USER nodejs

# Nitro's Node server listens on PORT (default 3000); pin it for the image.
ENV PORT=3001
EXPOSE 3001

# Liveness only: confirm the process is up and accepting connections, without
# depending on SSR rendering or the upstream auth-server being reachable.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD node -e "require('net').connect(3001, 'localhost').on('connect', function () { process.exit(0); }).on('error', function () { process.exit(1); })"

CMD ["node", "server/index.mjs"]
