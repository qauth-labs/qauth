# Auth Server Dockerfile
# Multi-stage build for production

# Stage 1: Dependencies
FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY nx.json tsconfig.base.json ./
RUN corepack enable && \
    pnpm install --frozen-lockfile

# Stage 2: Builder
FROM deps AS builder
# Copy root vitest.config.ts (needed for Nx project graph processing)
COPY vitest.config.ts ./
COPY libs ./libs
COPY apps ./apps

# Build auth-server and all its dependencies
RUN pnpm nx build auth-server --prod

# Stage 3: Runner (minimal production image)
FROM node:24-alpine AS runner
WORKDIR /app

# Enable corepack to use correct pnpm version
RUN corepack enable

# Copy built application
COPY --from=builder /app/dist/apps/auth-server ./

# Copy compiled workspace libraries (referenced by @qauth/* imports)
COPY --from=builder /app/dist/libs ./dist/libs

# Copy package files for dependency resolution
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/pnpm-lock.yaml ./pnpm-lock.yaml
COPY --from=builder /app/pnpm-workspace.yaml ./pnpm-workspace.yaml

# Copy node_modules (includes workspace dependencies)
# This is the simplest approach for monorepo - can be optimized later
COPY --from=builder /app/node_modules ./node_modules

# Copy entrypoint script
COPY apps/auth-server/docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh

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
