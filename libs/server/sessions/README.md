# @qauth-labs/server-sessions

The browser session service: it creates, reads, touches and ends browser sessions
([ADR-019 Decision 3](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md)). Postgres
holds the truth, Redis caches reads, and last-seen writes are throttled.

> **Status:** the auth-server decorates it as `fastify.sessionService`. The password and wallet
> sign-ins create sessions through it, and every route that reads the session cookie resolves the
> session through it (#488).

## Usage

```typescript
import { createRedisSessionCache, createSessionService } from '@qauth-labs/server-sessions';

const sessions = createSessionService({
  store, // the Postgres port: the auth-server builds it over its repositories
  cache: createRedisSessionCache(fastify.redis),
  settings: {
    defaultMaxLifespanSeconds: env.SESSION_COOKIE_TTL,
    lastSeenIntervalSeconds: env.SESSION_LAST_SEEN_INTERVAL,
  },
  metrics, // three prom-client counters, optional
  logger: fastify.log,
});

const session = await sessions.create({ realmId, userId, authTime: Date.now(), amr: ['pwd'] });
const same = await sessions.get({ realmId, sid: session.sid }); // null when absent
await sessions.revoke({ realmId, sid: session.sid, reason: 'sign_out' });
```

## Ports

The service talks to Postgres and Redis through two small ports, so its unit tests need neither.

| Port           | What it does                                                                                                    | Implemented by                                        |
| -------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `SessionStore` | The realm's lifetimes; insert, find, the conditional last-seen `UPDATE` and revoke on `sessions`.               | the auth-server, over `@qauth-labs/infra-db`          |
| `SessionCache` | Read an entry and its tombstone together; write an entry with a time to live; write a tombstone over the entry. | `createRedisSessionCache` (any `ioredis`-like client) |

`createMemorySessionStore`, `createMemorySessionCache` and `createManualClock` are in-memory ports
for tests. The real service runs on them as it runs on Postgres and Redis, and each can be switched
`down` to act as a stopped server.

## Rules

- **Create.** Always a new row and a new id. Postgres first, then the cache. The absolute end is the
  realm's `sso_max_lifespan` from now, or `SESSION_COOKIE_TTL` when the realm sets none.
- **Read.** The cache first, Postgres on a miss. A read from Postgres fills the cache for 60 seconds,
  never past the session's end. The service never serves an entry past that time, whatever expiry
  the cache gave it.
- **Absent.** A session is absent when it is revoked, past its absolute end, past the realm's idle
  limit (`sso_idle_timeout`, judged from the stored `last_seen_at`), or in another realm. The
  absolute end is applied again at every read: a realm that shortens `sso_max_lifespan` shortens its
  live sessions too.
- **Last seen.** `last_seen_at` is written at most once per `SESSION_LAST_SEEN_INTERVAL` (60 seconds
  by default) per session, by one conditional `UPDATE`: of several nodes, only the first writes. A
  realm whose idle limit is shorter than twice the interval gets half its idle limit as the interval,
  so a session in use never idles out.
- **Outages.** When Redis is down, reads go to Postgres. A cache call that has not answered after 250 ms
  (`cacheTimeoutMs`) is given up, so a Redis that hangs does not hold reads for its client's retries. When Postgres is down and a read needs it (a
  miss, or a last-seen write that falls due), the session is absent; a cached session is served for
  no longer than the cache time. `get` never throws for either; `create` and `revoke` throw when
  Postgres cannot store the change.
- **Revoke.** Postgres first, then a tombstone is written over the cache entry for twice the cache
  time. A read that sees the tombstone answers "absent", so a fill that raced the revocation cannot
  bring the session back, even one that reached Redis late. Reads on the node that were already
  waiting on Postgres do not answer the reads that start after the revocation.
- **Not stored.** The CSRF values and the consent scopes are volatile per-flow values. They are not
  part of a session here and never reach Postgres; the session record keeps only its own columns,
  and the cache entry leaves out the address and the user agent too.

## Metrics

The service counts through three counters it is given, each labelled `result`:

| Counter          | `result` values                   | Meaning                                                |
| ---------------- | --------------------------------- | ------------------------------------------------------ |
| `cacheLookups`   | `hit`, `miss`, `revoked`, `error` | One per cache read; `hit` over all gives the hit rate. |
| `storeReads`     | `ok`, `error`                     | One per Postgres read of a session.                    |
| `lastSeenWrites` | `written`, `skipped`, `error`     | One per conditional `last_seen_at` update sent.        |

The auth-server registers them as `qauth_session_cache_lookups_total`,
`qauth_session_postgres_reads_total` and `qauth_session_last_seen_writes_total`.
