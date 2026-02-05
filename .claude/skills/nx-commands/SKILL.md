---
name: nx-commands
description: Nx command reference for common tasks. Use when running builds, tests, linting, or any Nx workspace operations.
---

# Nx Commands Reference

**Always use `pnpm nx` instead of bare `nx`**

## Development

```bash
pnpm nx serve auth-server
pnpm nx serve auth-server --configuration=development
```

## Building

```bash
pnpm nx build auth-server
pnpm nx run-many -t build --all
pnpm nx affected -t build
```

## Testing

```bash
pnpm nx test {project-name}
pnpm nx test {project-name} --watch
pnpm nx run-many -t test --all
pnpm nx affected -t test
pnpm nx run-many -t test --all --coverage
```

## Linting

```bash
pnpm nx lint {project-name}
pnpm nx run-many -t lint --all
pnpm nx affected -t lint
```

## Type Checking

```bash
pnpm nx typecheck {project-name}
pnpm nx run-many -t typecheck --all
```

## Database (infra-db)

```bash
pnpm nx run infra-db:db:generate   # Generate migrations
pnpm nx run infra-db:db:migrate    # Run migrations
pnpm nx run infra-db:db:studio     # Drizzle Studio GUI
pnpm nx run infra-db:db:push       # Push schema (dev only)
pnpm nx run infra-db:db:seed       # Seed dev data
pnpm nx run infra-db:db:drop       # Drop tables (DANGER)
```

## Workspace

```bash
pnpm nx graph                      # Project graph
pnpm nx affected:graph             # Affected graph
pnpm nx show projects              # List projects
pnpm nx show project {name}        # Project config
pnpm nx reset                      # Clear cache
```

## CI/CD

```bash
pnpm nx affected -t lint test build
pnpm nx run-many -t test --parallel=3
pnpm nx affected -t test --base=origin/main --head=HEAD
```

## Troubleshooting

```bash
pnpm nx reset                              # Clear cache
pnpm nx test {project} --skip-nx-cache     # Bypass cache
NX_VERBOSE_LOGGING=true pnpm nx test {project}
```
