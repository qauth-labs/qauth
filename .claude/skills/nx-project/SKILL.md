---
name: nx-project
description: Create and manage Nx projects (libraries and applications). Use when creating new libs, organizing projects, or setting up project tags and dependencies.
---

# Nx Project Management

## Project Naming Convention

- **Applications**: Direct name (e.g., `auth-server`, `migration-runner`)
- **Libraries**: `{domain}-{name}` format (e.g., `server-jwt`, `infra-db`, `shared-errors`)

## Library Domains

| Domain            | Path                          | Tag                    |
| ----------------- | ----------------------------- | ---------------------- |
| `fastify/plugins` | `libs/fastify/plugins/{name}` | `scope:fastify-plugin` |
| `infra`           | `libs/infra/{name}`           | `scope:infra`          |
| `server`          | `libs/server/{name}`          | `scope:server`         |
| `shared`          | `libs/shared/{name}`          | `scope:shared`         |

## Module Boundaries

| Source Tag      | Only Depend On                                                 |
| --------------- | -------------------------------------------------------------- |
| `scope:shared`  | `scope:shared`                                                 |
| `type:testing`  | `scope:shared`, `scope:infra`, `scope:server`, `scope:fastify` |
| `scope:infra`   | `scope:infra`, `scope:shared`                                  |
| `scope:server`  | `scope:server`, `scope:shared`                                 |
| `scope:fastify` | `scope:fastify`, `scope:server`, `scope:infra`, `scope:shared` |
| `scope:app`     | `scope:fastify`, `scope:shared`, `scope:server-config`         |

## Creating New Libraries

**ALWAYS use Nx generators. NEVER create libraries manually.**

```bash
pnpm nx generate @nx/js:library \
  --name={name} \
  --directory=libs/{domain}/{name} \
  --projectNameAndRootFormat=as-provided \
  --bundler=none \
  --linter=none \
  --unitTestRunner=vitest \
  --no-interactive
```

### Examples

```bash
# Server library
pnpm nx generate @nx/js:library \
  --name=auth \
  --directory=libs/server/auth \
  --projectNameAndRootFormat=as-provided \
  --bundler=none \
  --linter=none \
  --unitTestRunner=vitest \
  --no-interactive

# Fastify plugin
pnpm nx generate @nx/js:library \
  --name=auth \
  --directory=libs/fastify/plugins/auth \
  --projectNameAndRootFormat=as-provided \
  --bundler=none \
  --linter=none \
  --unitTestRunner=vitest \
  --no-interactive
```

## After Generation

1. Add tags to `project.json`:

   ```json
   "tags": ["scope:{domain}", "type:{type}"]
   ```

2. Update `index.ts` exports

3. Verify path alias in `tsconfig.base.json`

## Project Tags

- `scope:app` - Application projects
- `scope:fastify-plugin` - Fastify plugins
- `scope:infra` - Infrastructure libraries
- `scope:server` - Server-side libraries
- `scope:shared` - Shared utilities
- `type:db` - Database-related
- `type:cache` - Cache-related

## Viewing Projects

```bash
pnpm nx show project {project-name}
pnpm nx graph
pnpm nx show projects
```
