# Fastify Plugins — Official Standards & Reference

Summary of Fastify plugin behavior (v5.x) and how QAuth applies it. Source: [Plugins Guide](https://fastify.dev/docs/latest/Guides/Plugins-Guide), [Encapsulation](https://fastify.dev/docs/latest/Reference/Encapsulation).

---

## 1. Register and encapsulation

- **Everything is a plugin**: routes, utilities, and nested servers are plugins.
- **`fastify.register(plugin, options)`** creates a new **encapsulation context**. Changes (decorators, hooks, routes) inside that context are **not** visible to:
  - Ancestors (parent or root)
  - Sibling contexts (other plugins registered at the same level)
- **Children** of a context **do** see that context’s decorators, hooks, and routes.
- Plugin must signal completion: **async function** (return Promise) or **callback** `done()`.

Takeaway: to expose decorators to the whole app (or to other plugins at the root), use **fastify-plugin** so that plugin’s context is not encapsulated.

---

## 2. Plugin signature

- One function: `(fastify, options, done?) => void | Promise<void>`.
- **fastify**: encapsulated instance for that plugin.
- **options**: config passed as second argument to `register(plugin, options)`.
- **done**: required in callback style; omit when using async/await.

Async (preferred):

```ts
async function myPlugin(fastify: FastifyInstance, options: MyOptions) {
  fastify.decorate('foo', createFoo(options));
}
```

Callback:

```ts
function myPlugin(fastify, options, done) {
  fastify.decorate('foo', createFoo(options));
  done();
}
```

---

## 3. Decorators

- **fastify.decorate(name, value)**: add property to the Fastify instance. Synchronous; value must be ready.
- **fastify.decorateRequest(name, value)** / **fastify.decorateReply(name, value)**: add to request/reply. For reply/request use `function` (not arrow) if you need `this`.
- Decorators are **scoped to the encapsulation context** where they are defined. Siblings and parents do not see them unless the plugin is wrapped with **fastify-plugin**.

For async setup (e.g. DB connection): do the async work inside the plugin, then call `decorate` with the result. Do not call `decorate` with a promise that the rest of the app must await.

---

## 4. Hooks

- **fastify.addHook(hookName, handler)**: run logic at lifecycle or request lifecycle.
- **Lifecycle**: `onReady` (after all plugins loaded), `onClose` (during shutdown). Use for health checks and cleanup.
- **Request**: `onRequest`, `preParsing`, `preValidation`, `preHandler`, `onResponse`, etc.
- Hooks are also encapsulated; only routes in the same (or child) context run that context’s hooks.

QAuth usage: `onReady` for DB/Redis connection checks, `onClose` for closing pools and connections.

---

## 5. Distribution and fastify-plugin

- **Problem**: A plugin that only uses `register` runs in an encapsulated context, so its decorators are not visible to the parent (e.g. root app).
- **Solution**: Wrap the plugin with **fastify-plugin** so it “breaks” encapsulation and its decorators/hooks are registered on the parent instance.

```ts
import fp from 'fastify-plugin';

export const myPlugin = fp(
  async (fastify, options) => {
    fastify.decorate('util', createUtil(options));
  },
  { name: '@scope/plugin-name' }
);
```

- Use **name** for debugging and for Fastify’s dependency/metadata. QAuth uses `@qauth/fastify-plugin-<feature>`.
- Plugins are loaded after `.listen()`, `.inject()`, or `.ready()`; decorators are not available before that.

---

## 6. Options from parent (functions)

If a plugin needs something from a previously registered plugin (e.g. `parent.db`), pass a **function** as options; Fastify will call it with the parent instance:

```ts
fastify.register(dbPlugin, { url: '...' });
fastify.register(otherPlugin, (parent) => ({
  connection: parent.db,
  otherOption: 'foo',
}));
```

---

## 7. Errors and after()

- Let plugin errors propagate so Fastify/avvio can handle startup failure.
- **fastify.after(callback)** runs when the previous `register` completes. Use to depend on a plugin and handle its errors:

```ts
fastify.register(databasePlugin, config).after((err) => {
  if (err) throw err;
});
```

---

## 8. Custom errors and warnings

- **@fastify/error**: create consistent error classes for your plugin.
- **process-warning**: emit deprecations or warnings (e.g. `warning.emit('CODE')`).

---

## 9. ESM

- ESM is supported: export default async function; no `done`. Same encapsulation and decorator rules apply.

---

## 10. QAuth conventions (summary)

| Item         | Convention                                                                      |
| ------------ | ------------------------------------------------------------------------------- |
| Package name | `@qauth/fastify-plugin-<feature>`                                               |
| fp name      | `name: '@qauth/fastify-plugin-<feature>'`                                       |
| Types        | `declare module 'fastify' { interface FastifyInstance { ... } }` in plugin file |
| Options      | Typed in `src/types.ts`, use `fp<Options>(...)`                                 |
| Lifecycle    | `onReady` for checks, `onClose` for cleanup                                     |
| Location     | `libs/fastify/plugins/<feature>/src/lib/`                                       |
| Export       | Plugin and types from `src/index.ts`                                            |

These align with Fastify v5 plugin and encapsulation behavior and current best practice (explicit naming, typing, and lifecycle cleanup).
