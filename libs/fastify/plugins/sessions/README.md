# @qauth-labs/fastify-plugin-sessions

Fastify plugin for the browser session service of
[`@qauth-labs/server-sessions`](../../../server/sessions/README.md) (ADR-019 Decision 3). It builds
the service's Postgres port over the database plugin's repositories and its Redis port over the cache
plugin's client, and decorates the instance with `fastify.sessionService`.

> **Status:** the auth-server registers it. Since #488 the browser sign-in and the session lookup
> run on it (`apps/auth-server/src/app/helpers/browser-session.ts`), and since #550 the
> `session-expiry` and `session-purge` jobs on the `web` role (`apps/auth-server/src/app/jobs/`).

## Usage

Register it after the database and cache plugins; it refuses to boot without them.

```typescript
import { sessionServicePlugin } from '@qauth-labs/fastify-plugin-sessions';

await fastify.register(sessionServicePlugin, {
  settings: {
    defaultMaxLifespanSeconds: env.SESSION_COOKIE_TTL,
    lastSeenIntervalSeconds: env.SESSION_LAST_SEEN_INTERVAL,
  },
  metrics: {
    cacheLookups: fastify.metrics.sessionCacheLookups,
    storeReads: fastify.metrics.sessionPostgresReads,
    lastSeenWrites: fastify.metrics.sessionLastSeenWrites,
  },
});

const session = await fastify.sessionService.get({ realmId: request.realm.id, sid });
```

The plugin only builds the service: nothing reaches Postgres or Redis until a session is created or
read, so a boot with no reachable database still boots.

`repositorySessionStore(fastify.repositories)` is the Postgres port on its own. On a cache miss it
reads the session and its realm's row (`sso_max_lifespan`, `sso_idle_timeout`) together. Its
revocations pass on the clients each ended session served, with their `client_id` and name, which
the repository deleted from `session_clients` in the same transaction; a list reads the realm's row
beside the page, to judge each session's state.

The auth-server may not import `@qauth-labs/server-sessions` itself, so this package re-exports the
types it works with (`SessionService`, `BrowserSession`, …) and the Redis key helpers.
