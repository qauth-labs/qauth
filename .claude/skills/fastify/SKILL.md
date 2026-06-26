---
name: fastify
description: Fastify usage for QAuth — plugin authoring (encapsulation, decorators, lifecycle), route schemas with the Zod type provider, production/reverse-proxy setup, and the Fastify version/CVE requirement. Use when adding or modifying @qauth-labs/fastify-plugin-* libraries, auth-server routes, or deployment config.
---

# Fastify (QAuth)

Standards-aligned Fastify usage for QAuth: plugin authoring, route validation,
and production deployment. Use this skill when creating plugins, wiring routes,
reviewing Fastify code, or configuring the server for production.

## When to Use This Skill

- Adding a new `@qauth-labs/fastify-plugin-*` library
- Wrapping a shared utility (DB, cache, JWT, PKCE, etc.) as a Fastify plugin
- Defining or reviewing routes (schemas, type provider, validation)
- Configuring the server for production (reverse proxy, listen address, CVE/version)
- Reviewing or refactoring plugin registration order or decorator availability
- Questions about encapsulation, `fastify-plugin`, or lifecycle hooks

## Production

- **Use a reverse proxy** (e.g. Nginx, HAProxy). Do not expose the Fastify app
  directly to the internet. Handle TLS, HTTP→HTTPS redirects, and static assets
  at the proxy.
- **Listen on `0.0.0.0`** in containers/Kubernetes so readiness/liveness probes
  can reach the app (the default `127.0.0.1` is unreachable from the pod network).
- **Trust proxy**: behind a reverse proxy, configure `trustProxy` so
  `request.ip` and `X-Forwarded-*` headers are correct.

## Routes and Validation

- **Schema**: register `schema.body`, `schema.querystring`, `schema.params`, and
  `schema.response` (e.g. `response: { 200: responseSchema }`). Fastify v5 uses
  schemas for both validation and types.
- **Type provider**: call `fastify.withTypeProvider<ZodTypeProvider>()` before
  defining routes when using Zod schemas.
- See the `validation` skill for schema organization and Zod v4 validators.

```typescript
fastify.withTypeProvider<ZodTypeProvider>().post(
  '/login',
  {
    schema: {
      body: loginSchema,
      response: { 200: loginResponseSchema },
    },
    config: { rateLimit: { max: env.LOGIN_RATE_LIMIT, timeWindow: env.LOGIN_RATE_WINDOW * 1000 } },
  },
  async (request, reply) => {
    /* ... */
  }
);
```

## Security and Dependencies

- **Fastify version**: keep Fastify **≥ 5.3.2** to avoid **CVE-2025-32442**
  (content-type parsing bypass in 5.0.0–5.3.0). Do not rely on
  content-type-specific validation without normalizing the header.
- **Audit**: run `pnpm audit` regularly; fix or document high/critical
  vulnerabilities (see the `security` skill).
- **Node**: Fastify v5 requires Node.js v20+; this project uses `>=24.7.0`.

## Quick Reference

| Concern          | QAuth pattern                                                                   |
| ---------------- | ------------------------------------------------------------------------------- |
| **Distribution** | Wrap with `fastify-plugin` so decorators are available to parent/children       |
| **Name**         | `name: '@qauth-labs/fastify-plugin-<feature>'` in fp options                    |
| **Types**        | `declare module 'fastify' { interface FastifyInstance { ... } }` in plugin file |
| **Options**      | Typed via `fp<OptionsType>(async (fastify, options) => {...}, { name })`        |
| **Lifecycle**    | Use `onReady` for post-boot checks, `onClose` for cleanup (e.g. DB/cache)       |
| **Logging**      | `fastify.log.debug/info/warn` after registration or in hooks                    |

## Plugin Structure (QAuth)

1. **Wrap with `fp`**  
   All plugins that add decorators used outside their own context must use `fastify-plugin`. Otherwise decorators are encapsulated and not visible to the root app or sibling plugins.

2. **Name and TypeScript**
   - Pass `{ name: '@qauth-labs/fastify-plugin-<feature>' }` as second argument to `fp()`.
   - In the same file, extend `FastifyInstance` via `declare module 'fastify'` so routes and other plugins get correct types for your decorators.

3. **Options**
   - Define an options type in `src/types.ts` (or next to the plugin).
   - Use `fp<YourOptions>(async (fastify, options) => {...}, { name })`.
   - Options can be optional for stateless plugins (e.g. PKCE).

4. **Decorators**
   - Use `fastify.decorate('name', value)` for utilities shared across the app.
   - Decorate once; do not re-decorate in nested registers.
   - For async setup (e.g. DB connection), perform it inside the plugin and then `decorate`; do not use synchronous `decorate` with uninitialized resources.

5. **Lifecycle**
   - **onReady**: Run after the server is ready (e.g. test DB/Redis connection, log success).
   - **onClose**: Clean up resources (close pool, disconnect Redis).
   - Register hooks with `fastify.addHook('onReady', ...)` and `fastify.addHook('onClose', ...)`.

6. **Errors**
   - Let async errors propagate from the plugin so Fastify/avvio can handle them.
   - Use `fastify.after()` in the app when you need to run logic after a specific plugin and handle its errors.

## Encapsulation Rules

- **register** creates a new context: decorators and routes registered inside are not visible to ancestors or siblings.
- **Children** inherit from their parent: routes and plugins registered inside a plugin see that plugin’s decorators plus all parent decorators.
- **fastify-plugin** breaks encapsulation for that plugin: its decorators (and hooks) are visible to the parent, so the whole app can use them. Use it for shared utilities (db, cache, jwtUtils, pkceUtils, etc.).

## Project Layout

- Plugins live under `libs/fastify/plugins/<feature>/`.
- Main implementation: `src/lib/fastify-plugin-<feature>.ts` or `<feature>-plugin.ts`.
- Public API: `src/index.ts` re-exports plugin and types.
- Options and shared types: `src/types.ts`.
- Nx tags: e.g. `scope:fastify`, `type:<feature>`.

## Checklist for New Plugins

- [ ] Plugin wrapped with `fp(..., { name: '@qauth-labs/fastify-plugin-<feature>' })`
- [ ] `declare module 'fastify'` extends `FastifyInstance` with new decorators
- [ ] Options type defined and used as `fp<Options>(...)` when plugin is configurable
- [ ] Resources (DB, Redis, etc.) cleaned up in `onClose`
- [ ] Optional: `onReady` used for connection or sanity checks
- [ ] Exported from `src/index.ts`; app registers with `fastify.register(plugin, options)`

## Additional Resources

- Official encapsulation and plugin model: [reference.md](reference.md)
- Existing plugins: `libs/fastify/plugins/db`, `libs/fastify/plugins/cache`, `libs/fastify/plugins/jwt`, `libs/fastify/plugins/pkce`
- App registration order: `apps/auth-server/src/app/app.ts`
