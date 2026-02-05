---
name: fastify-plugins
description: Create and review Fastify plugins with correct encapsulation, decorators, and lifecycle. Use when adding or modifying @qauth/fastify-plugin-* libraries, wrapping utilities for the auth server, or when the user asks about Fastify plugin patterns.
---

# Fastify Plugins (QAuth)

Standards-aligned Fastify plugin authoring for QAuth. Plugins extend the server with decorators and hooks while respecting encapsulation. Use this skill when creating new plugins, reviewing plugin code, or debugging encapsulation/order issues.

## When to Use This Skill

- Adding a new `@qauth/fastify-plugin-*` library
- Wrapping a shared utility (DB, cache, JWT, PKCE, etc.) as a Fastify plugin
- Reviewing or refactoring plugin registration order or decorator availability
- Questions about encapsulation, `fastify-plugin`, or lifecycle hooks

## Quick Reference

| Concern          | QAuth pattern                                                                   |
| ---------------- | ------------------------------------------------------------------------------- |
| **Distribution** | Wrap with `fastify-plugin` so decorators are available to parent/children       |
| **Name**         | `name: '@qauth/fastify-plugin-<feature>'` in fp options                         |
| **Types**        | `declare module 'fastify' { interface FastifyInstance { ... } }` in plugin file |
| **Options**      | Typed via `fp<OptionsType>(async (fastify, options) => {...}, { name })`        |
| **Lifecycle**    | Use `onReady` for post-boot checks, `onClose` for cleanup (e.g. DB/cache)       |
| **Logging**      | `fastify.log.debug/info/warn` after registration or in hooks                    |

## Plugin Structure (QAuth)

1. **Wrap with `fp`**  
   All plugins that add decorators used outside their own context must use `fastify-plugin`. Otherwise decorators are encapsulated and not visible to the root app or sibling plugins.

2. **Name and TypeScript**
   - Pass `{ name: '@qauth/fastify-plugin-<feature>' }` as second argument to `fp()`.
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

- [ ] Plugin wrapped with `fp(..., { name: '@qauth/fastify-plugin-<feature>' })`
- [ ] `declare module 'fastify'` extends `FastifyInstance` with new decorators
- [ ] Options type defined and used as `fp<Options>(...)` when plugin is configurable
- [ ] Resources (DB, Redis, etc.) cleaned up in `onClose`
- [ ] Optional: `onReady` used for connection or sanity checks
- [ ] Exported from `src/index.ts`; app registers with `fastify.register(plugin, options)`

## Additional Resources

- Official encapsulation and plugin model: [reference.md](reference.md)
- Existing plugins: `libs/fastify/plugins/db`, `libs/fastify/plugins/cache`, `libs/fastify/plugins/jwt`, `libs/fastify/plugins/pkce`
- App registration order: `apps/auth-server/src/app/app.ts`
