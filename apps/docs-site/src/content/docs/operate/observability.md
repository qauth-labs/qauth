---
title: Observability Guide
description: QAuth's observability surface — structured logging, request-id tracking, auth-event logging, failed-login lockout, Prometheus metrics, events as OpenTelemetry logs, and alerting.
sidebar:
  order: 3
lastVerified: '2026-10-24'
---

This guide covers QAuth's observability surface: structured logging, request-id
tracking, auth-event logging, failed-login tracking/lockout, Prometheus metrics,
events exported as OpenTelemetry logs, and recommended alerting.

## Overview

| Capability                | Mechanism                                                        |
| ------------------------- | ---------------------------------------------------------------- |
| **Structured logging**    | pino (built into Fastify) with secret redaction                  |
| **Request-id tracking**   | `genReqId` + `REQUEST_ID_HEADER`, echoed on responses            |
| **Auth-event logging**    | Structured `authEvent` log lines for login/register/logout/token |
| **Failed-login tracking** | Redis-backed per-identifier counters with temporary lockout      |
| **Metrics**               | `GET /metrics` in Prometheus text format via `prom-client`       |
| **Event export**          | Every event as an OpenTelemetry log record, off by default       |
| **Background jobs**       | Periodic jobs, one node at a time under a Postgres advisory lock |
| **Event delivery**        | Each event to each delivery destination, at least once           |
| **Alerting**              | Prometheus Alertmanager rules (see below)                        |

## Structured Logging

QAuth logs through Fastify's built-in [pino](https://getpino.io) logger. Output
is JSON by default — suitable for log shippers (Loki, Elasticsearch, Datadog,
CloudWatch, ...).

- `LOG_LEVEL` — `fatal | error | warn | info | debug | trace` (default `info`).
- `LOG_PRETTY` — when `true` **and** `NODE_ENV != production`, output is routed
  through [`pino-pretty`](https://github.com/pinojs/pino-pretty) for colourised,
  human-readable local development. Production always emits JSON.

### Secret redaction

The logger is configured with a pino `redact` allowlist that replaces sensitive
values with `[Redacted]`. The paths are `LOG_REDACT_PATHS` in
`apps/auth-server/src/config/logger.ts`, and they fall into three groups:

- **Credential-bearing headers** — `req.headers.authorization`,
  `req.headers.cookie`, `res.headers["set-cookie"]`.
- **Top-level plus one level of nesting** (each field also has a `*.field`
  twin) — `password`, `token`, `access_token`, `refresh_token`, `id_token`,
  `client_secret`, `secret`.
- **Top-level only** (no `*.` twin) — `newPassword`, `currentPassword`,
  `subject_token`, `actor_token`, `code`, `code_verifier`, `authorization`.

Two limits follow from that shape. A field in the last group is redacted only at
the root of a logged object: `log.info({ code_verifier })` is redacted,
`log.info({ body: { code_verifier } })` is not. And pino's `*` matches exactly
**one** level, so even a field with a `*.` twin is missed deeper down
(`{ a: { b: { password } } }`). No route logs a request body, so nothing reaches
a log sink today — read the list as the shape of the backstop, not as
full-depth coverage. A regression test (`logger.test.ts`) drives the real pino
config end to end and asserts that a payload carrying these fields (including
one nested level) is serialised with `[Redacted]` in their place.

> Callers must still avoid passing secrets into log payloads; redaction is a
> defence-in-depth backstop, not a license to log credentials.

## Request-ID Tracking

Every request gets a request id, surfaced as `reqId` on all of its log lines:

- An inbound `REQUEST_ID_HEADER` (default `x-request-id`) is honoured for
  distributed tracing/propagation.
- When absent, a UUID is generated (`genReqId`).
- The id is **echoed back** on the response's `REQUEST_ID_HEADER` by the
  request-id plugin (`apps/auth-server/src/app/plugins/request-id.ts`), so a
  caller can correlate a response — and its server logs — with the request.

## Auth-Event Logging

Login, logout and registration emit structured log lines via `logAuthEvent`
(`apps/auth-server/src/app/helpers/auth-events.ts`) on both success and
failure. A registration of an address that already has an account logs
`user.register.failure` with `reason` `address_in_use`, or
`address_in_use_mail_capped` when the per-address mail caps held back the
notice. The caller got the same `202` either way; only this line tells them
apart.

> ⚠️ **Token-exchange events are not log lines.** `logAuthEvent` is called only
> from `routes/auth/login.ts`, `routes/auth/logout.ts` and
> `routes/auth/register.ts`. The `oauth.token.exchange.*` names exist as members
> of the event type union, but the token endpoint records them **only as events**
> (`token.issued`, `token.request_failed`) in the event store, never through the
> logger. An alert built on an `oauth.token.exchange.success` log line will never
> fire — read the event store for those instead. Since 0.2.0 nothing writes the
> `audit_logs` table; it stays read-only until a later release drops it.

Each emitted line carries:

- `authEvent` — e.g. `user.login.success`, `user.login.failure`.
- `success`, `userId`/`clientId` (when known), `ip`, ISO `timestamp`, and
  `reqId`.
- On **failure** paths, the email is logged as a SHA-256 `emailHash` rather than
  the raw address, to avoid account enumeration. Passwords/tokens are never
  logged.

These structured logs complement the durable `audit_logs` database trail.

## Failed-Login Tracking & Lockout

Failed logins are tracked per realm and identifier (email **hash** and source IP)
in Redis (`apps/auth-server/src/app/helpers/failed-login.ts`). Each realm counts
its own: the same address in two realms is two accounts, and a source address
locked out in one realm is not locked out in another. The rate limits keep a
bucket per realm and address the same way. After
`FAILED_LOGIN_MAX_ATTEMPTS` failures inside `FAILED_LOGIN_WINDOW`, the identifier
is locked out for `FAILED_LOGIN_LOCKOUT_DURATION` seconds; further login attempts
return `429 Too Many Requests` with a `Retry-After` header before any credential
verification.

- An attempt is counted **before** its password is verified, so guesses sent
  concurrently cannot outrun the counter. A login that ends in a server error
  therefore stays counted too. While the attempt that reaches the limit is
  being verified, other attempts for the same identifier are refused.
- The attempt counter has a TTL equal to the window, so it **decays** naturally.
- A **successful** login clears both the counter and any lockout of its email.
  The source address's counter keeps the failures other attempts left on it
  until they decay; the success gives back only its own count. Users behind
  one shared address (an office NAT, or one IPv6 `/64`) therefore share its
  `FAILED_LOGIN_MAX_ATTEMPTS` failures per window, and signing in does not
  clear them.
- All cache operations are **best-effort / fail-open**: if Redis is unavailable,
  logins are never blocked by the tracker — though an instance-wide Redis outage
  still fails the request earlier, at the app-wide rate-limiter's `onRequest`
  hook (see
  [Hosted UI](/integrate/hosted-ui/#what-the-stash-adds-to-the-pre-authentication-path)),
  so "the tracker never blocks" is not the same as "a Redis outage is invisible
  on `POST /auth/login`".

### Configuration

| Variable                        | Default | Description                            |
| ------------------------------- | ------- | -------------------------------------- |
| `FAILED_LOGIN_TRACKING_ENABLED` | `true`  | Master switch for throttling/lockout.  |
| `FAILED_LOGIN_MAX_ATTEMPTS`     | `5`     | Failures in the window before lockout. |
| `FAILED_LOGIN_WINDOW`           | `900`   | Sliding window in seconds (15 min).    |
| `FAILED_LOGIN_LOCKOUT_DURATION` | `900`   | Lockout duration in seconds (15 min).  |

None of these reach the container under Docker Compose — see the Compose caveat
below.

## Metrics (`GET /metrics`)

QAuth exposes Prometheus metrics in text exposition format at `GET /metrics`
(`apps/auth-server/src/app/routes/metrics.ts`). The endpoint includes default
process/runtime metrics plus QAuth counters and gauges:

| Metric                                   | Type    | Labels               | Meaning                                                             |
| ---------------------------------------- | ------- | -------------------- | ------------------------------------------------------------------- |
| `qauth_login_attempts_total`             | counter | `result`, `reason`   | Login outcomes (success/failure).                                   |
| `qauth_tokens_issued_total`              | counter | `type`, `grant_type` | Tokens issued by type and grant.                                    |
| `qauth_job_runs_total`                   | counter | `job`, `result`      | Background job runs by outcome.                                     |
| `qauth_events_oldest_unread_age_seconds` | gauge   | none                 | Seconds the oldest committed event has been held back from readers. |
| `qauth_events_telemetry_dropped_total`   | counter | `reason`             | Event log records not exported; present only when the export is on. |
| `qauth_events_pending`                   | gauge   | `kind`               | Event deliveries not finished yet, by delivery route.               |
| `qauth_events_delivery_lag_seconds`      | gauge   | none                 | Seconds the oldest event that waits for a delivery has waited.      |
| `qauth_events_delivery_attempts_total`   | counter | `kind`, `result`     | Event delivery attempts by route and result.                        |
| `qauth_events_retention_deleted_total`   | counter | `category`           | Events the retention job deleted, by category.                      |
| `qauth_events_oldest_age_seconds`        | gauge   | `category`           | Seconds since each category's oldest stored event was written.      |
| `qauth_session_cache_lookups_total`      | counter | `result`             | Browser session cache reads; `hit` over all is the cache hit rate.  |
| `qauth_session_postgres_reads_total`     | counter | `result`             | Postgres reads of a browser session.                                |
| `qauth_session_last_seen_writes_total`   | counter | `result`             | Conditional writes of a browser session's last-seen time.           |

Label values, as emitted today. The plugin
(`apps/auth-server/src/app/plugins/metrics.ts`) does not constrain them, so treat
each list as **open** — a new call site can add a value without a schema change.

- `result` is `success` or `failure`. `reason` is set on failures only, e.g.
  `invalid_credentials`, `locked_out`, `error`. A login refused because the
  account is not verified yet counts as `invalid_credentials`: this endpoint is
  unauthenticated, and a label of its own would tell a caller who just
  registered an address whether it was free. The `user.login.failure` log line
  and the audit row keep the reason `email_not_verified`.
- `type` is e.g. `access`, `refresh`, or `id_jag` (the ID-JAG assertion minted by
  the token-exchange grant). `grant_type` is e.g. `password`,
  `authorization_code`, `refresh_token`, `client_credentials`, `token-exchange`,
  or `jwt-bearer`.
- `job` is a job's name, e.g. `purge-expired`. `result` is `success`, `failure`
  or `timeout`; see [Background jobs](#background-jobs).
- `reason` on `qauth_events_telemetry_dropped_total` is `queue_full` or
  `export_failed`; see
  [Events as OpenTelemetry logs](#events-as-opentelemetry-logs).
- `kind` is a delivery route, such as `webhook` or `ssf`. `result` on
  `qauth_events_delivery_attempts_total` is `delivered`, `retry` (failed, tried
  again later) or `failed` (failed for good); see
  [Event delivery](#event-delivery).
- `result` on `qauth_session_cache_lookups_total` is `hit`, `miss`, `revoked`
  (a recently ended session's tombstone) or `error` (Redis did not answer, and
  Postgres was read instead). On `qauth_session_postgres_reads_total` it is `ok`
  or `error`; with Postgres not answering, the session counts as absent. On
  `qauth_session_last_seen_writes_total` it is `written`, `skipped` (the stored
  time was recent, usually because another node wrote it first) or `error`.
  `last_seen_at` is written at most once per `SESSION_LAST_SEEN_INTERVAL`
  (60 seconds by default) per session. The session service that counts these
  is in place, but the hosted pages do not use it yet, so they stay at zero for
  now.

The endpoint is **unauthenticated and rate-limit-exempt** (so a scraper can poll
it frequently). Restrict access at the reverse proxy / network layer (e.g. to a
metrics subnet), or disable it entirely with `METRICS_ENABLED=false`.

> ℹ️ **Under Docker Compose these reach the container, but only because they are
> listed.** The `auth-server` service in `docker-compose.yml` declares an
> explicit `environment:` map and no `env_file:`, so that map is an
> **allowlist**: only the variables named in it are forwarded. Every variable on
> this page is on it — `METRICS_ENABLED`, `LOG_PRETTY`, `LOG_REDACT_PATHS`,
> `REQUEST_ID_HEADER` and the four `FAILED_LOGIN_*` settings are forwarded as
> bare `VAR:` entries, a null value that Compose resolves from `.env` (or the
> shell) and omits entirely when unset, so an unset variable still falls through
> to its schema default. `METRICS_ENABLED=false` in `.env` therefore does
> unregister `GET /metrics`.
>
> The allowlist itself is the thing to remember: a variable you add to `.env`
> later is **not** reachable from Compose until you also add it to that map.
> See [Docker](/operate/docker/#environment-variables).

### Event store lag

The event store hands an event to its readers only once every transaction
older than the event has ended, so a reader never skips an event that commits
late. The price is lag: a transaction left open holds back every event written
after it began, until it ends. That holds for any transaction that has written
something, on any database of the same Postgres server.

`qauth_events_oldest_unread_age_seconds` is how long the oldest event held back
this way has waited. It is read from the database at each scrape and is 0 in
normal operation. If the read fails, the gauge shows `NaN` and the auth server
logs a warning. A value that keeps growing points at a long-running
transaction; this query lists the open ones that hold readers back, oldest
first:

```sql
SELECT pid, datname, xact_start, state, query
FROM pg_stat_activity
WHERE backend_xid IS NOT NULL
ORDER BY xact_start;
```

### Event delivery

The delivery role hands every event to every destination of a delivery route,
such as a webhook subscription, at least once and with the event's own id. It
runs in the auth server, beside the other roles. No route is built yet, so
today it only publishes its metrics.

A delivery that fails is tried again after 30 seconds, then after twice as long
each time, at most 6 hours, less up to 20% at random. After the last of its 12
attempts it ends `failed` and stays in the delivery history.
`EVENT_DELIVERY_MAX_ATTEMPTS`, `EVENT_DELIVERY_RETRY_INITIAL_DELAY` and
`EVENT_DELIVERY_RETRY_MAX_DELAY` change the schedule (see
[Configuration](/operate/configuration/)). A destination that is down holds
only its own deliveries: the others go on.

- `qauth_events_pending{kind}` counts the deliveries not finished yet. It grows
  while a destination fails and falls as the retries succeed or run out.
- `qauth_events_delivery_lag_seconds` is how long the oldest event that waits
  for a delivery has waited, the time before the role picked it up included.
  It is 0 while no route has a destination, and about a second in normal
  operation.
- `qauth_events_delivery_attempts_total{kind,result}` counts the attempts. A
  rising `result="failed"` rate means destinations that stay down past the last
  retry.

Both gauges are read from the database at each scrape; a failed read shows
`NaN` and logs a warning. To see which destinations fail and why:

```sql
SELECT destination_kind, destination_id, status, count(*),
       max(attempt_count) AS attempts, max(last_status_code) AS last_status,
       max(last_error_class) AS last_error
FROM event_deliveries
WHERE status <> 'delivered'
GROUP BY 1, 2, 3
ORDER BY 4 DESC;
```

### Event retention

A realm keeps its user events 90 days and its admin events 365 days by
default. Admin events are never kept fewer than 90 days. Both values are realm
policy, stored on the realm row (`realms.user_event_retention_days`,
`realms.admin_event_retention_days`). `EVENT_RETENTION_USER_DAYS` and
`EVENT_RETENTION_ADMIN_DAYS` only seed a new realm's values: changing them
later leaves existing realms as they are (see
[Configuration](/operate/configuration/)). Until the admin API exists, change
an existing realm's retention with SQL; the row refuses an admin retention
below 90 days.

The `event-retention` job runs every hour, on one node at a time. It deletes a
realm's events once they are older than the realm's retention and every
enabled delivery destination has finished them, as `delivered` or `failed`. A
destination that is down holds its events back only until its retries run out.
A disabled destination holds nothing back. Readers of the event API are not
waited for: one that falls behind retention has to start again. The job
deletes the oldest events first, at most 1000 per transaction.

Admin events go only from the start of a realm's chain, and the newest one
always stays. Before the job deletes admin events, it checks each one against
the one before it. In the same transaction, it stores the last one it deletes
as the realm's chain anchor (`event_chain_anchors`). The chain check then
starts from the anchor. If an old admin event was changed, the job keeps it and
every admin event after it, and logs an error. The chain check reports the
change.

- `qauth_events_retention_deleted_total{category}` counts the events deleted.
- `qauth_events_oldest_age_seconds{category}` is how old each category's
  oldest event is. With the default retention it stays near 90 days for `user`
  and 365 days for `admin`. A value well past the retention means the job does
  not run, or a destination holds events back:
  `qauth_job_runs_total{job="event-retention"}` and the delivery metrics above
  tell which. It is read from the database at each scrape. A failed read shows
  `NaN` and logs a warning.

Only the retention role may delete from `events`.
`eventRetentionGrantStatements()` in `@qauth-labs/infra-db` gives the database
user that runs the job that grant, and the reads it needs. While a deployment
runs every role as one database user, that user owns the tables and holds
every grant.

### Admin event chain

An admin event records a change made by an administrator, a service account or
an operator on the server host: what changed, as a diff with every secret value
`***`, and the approvals the change ran on (see
[Admin events](/reference/events/#admin-events)). Admin events are always on; no
environment key and no realm setting turns them off. The admin API, which will
write most of them, is not built yet.

A realm's admin events form a hash chain: each stores the hash of the one
before it. Check a realm's chain from a host that holds the database
credentials:

```bash
DATABASE_URL=postgresql://qauth:pw@db:5432/qauth \
  pnpm --dir libs/infra/db exec tsx src/scripts/verify-event-chain.ts --realm=<realm name>
```

`pnpm nx run infra-db:events:verify-chain -- --realm=<realm name>` runs the same
check, but Nx reports every failure as exit code `1` and prints lines of its
own, so a monitor uses the command above.

The command only reads, so run it as a database role that may read the
`events` and `event_chain_anchors` tables, such as their owner; a role given
only the event writer's grants cannot. Once the retention job has deleted a
realm's oldest admin events, a full check starts from the realm's chain anchor
and prints it as the point it verified from. A kept head that retention has
since deleted is replaced by the anchor in the same way. `--realm-id=<uuid>` names a realm that no longer exists, and `--json`
prints the report as JSON. Its exit code tells a broken chain from a check
that could not run, so a monitor does not report a database outage as
tampering:

| Exit code | Meaning                                                                                                        |
| --------- | -------------------------------------------------------------------------------------------------------------- |
| `0`       | Every admin event verifies. It prints the chain's head.                                                        |
| `1`       | The chain breaks. It prints the first event that was changed, or that follows one that was removed.            |
| `2`       | A usage error: an unknown flag, a missing realm, or no `DATABASE_URL`. Nothing was read.                       |
| `3`       | The check could not run: the database is unreachable or failing, or no realm and no event has the realm given. |

With exit code `3` the reason is on standard error and nothing is on standard
output. The command waits 10 seconds for a connection.

The chain shows a changed or removed event, but not a chain rewritten from
some event to the end, or the newest events cut, by someone who can write the
database. Keep the head it prints somewhere outside the database, and run the
next check from it with `--from-seq=<seq> --from-hash=<hex>`. That run first
checks that the kept head is still there with the same hash, so it fails when
the chain was cut back to before the kept head or rewritten up to it. Then it
checks the events after the kept head, as a full check does. It does not read
the events before the kept head: one event changed there shows only in a full
check, without `--from-…`, so run both. And as in a full check, events after
the kept head that were rewritten to the end, or cut, leave no break: keep each
new head it prints.

### Example Prometheus scrape config

```yaml
scrape_configs:
  - job_name: qauth-auth-server
    metrics_path: /metrics
    static_configs:
      - targets: ['auth-server:3000']
```

`/metrics` answers only on a realm's host or endpoint host, like every route
but `/health`; any other host gets `421 Misdirected Request`. The target above
works because the Compose file lists `auth-server` in
`DEFAULT_REALM_ENDPOINT_HOSTS`. A scraper that reaches the server by another
name, or by a pod address, needs that name or address in the list.

## Events as OpenTelemetry Logs

QAuth can send every event it records to your own OpenTelemetry collector, as
one log record per event, over OTLP/HTTP. The
[event reference](/reference/events/) lists the event types. The export is off
by default.

It is telemetry, with no delivery guarantee. A record can be dropped, and a
crash between the moment an event commits and the moment it is sent loses that
record. The event itself is never lost: it stays in the event store either way.
Build anything that must see every event on the event store, not on this
export.

### Turning it on

Set the switch and point the exporter at your collector's OTLP/HTTP port:

```sh
OTEL_EVENTS_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
# Optional:
OTEL_SERVICE_NAME=qauth-auth-server
OTEL_EXPORTER_OTLP_HEADERS=x-api-key=<URL-encoded key>
```

The export reads the standard OpenTelemetry exporter variables, with their
standard meaning. The
[configuration reference](/operate/configuration/#advanced-keys) lists each
one.

- `OTEL_EXPORTER_OTLP_ENDPOINT` is the collector's base URL, and the export
  appends `/v1/logs` to it. `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` is a full URL,
  used as it is. With neither set, the export sends to
  `http://localhost:4318/v1/logs`.
- `OTEL_EXPORTER_OTLP_HEADERS` holds headers such as a collector API key, as
  URL-encoded `name=value` pairs separated by commas. The configuration page
  treats it as a secret.
- `OTEL_EXPORTER_OTLP_TIMEOUT` is how long one export may take, its retries
  included: 10000 ms by default, an hour at most. `OTEL_EXPORTER_OTLP_COMPRESSION`
  is `gzip` or `none`.
- `OTEL_EXPORTER_OTLP_CERTIFICATE` names a PEM file of CA certificates for a
  collector behind TLS with a private CA. `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`
  and `OTEL_EXPORTER_OTLP_CLIENT_KEY` name the client certificate and key for
  mutual TLS.
- Each of these has a `LOGS_` form (`OTEL_EXPORTER_OTLP_LOGS_HEADERS` and so on)
  that wins over the general one. The two header lists are merged.
- `OTEL_SERVICE_NAME` sets the records' `service.name` (`qauth-auth-server` by
  default). `OTEL_RESOURCE_ATTRIBUTES` is not read.

When the export is on, the server checks these values at boot: a malformed
URL, header list, timeout or compression refuses to start, with the variable's
name in the error, and so does a TLS file the process cannot read, or a client
certificate set without its key or a key without its certificate. The
exporter would otherwise drop an unreadable CA file without a word and trust
the public CAs instead. The error never repeats a header value. When the
export is off, the server leaves them alone. They are process-wide, and another
OpenTelemetry component of yours may read them.

The records are JSON-encoded OTLP (`http/json`). `OTEL_EXPORTER_OTLP_PROTOCOL`
is not read, and gRPC is not supported. The OpenTelemetry Collector's `otlp`
receiver accepts JSON on its HTTP port:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  debug: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
```

The collector is your own, and it often sits on a private network. So the export
does not go through QAuth's SSRF-safe egress client, which guards the
destinations that clients and users register; ADR-019 Decision 8 records this
as its one exception. Its destination comes only from these variables, never
from a realm admin, a client or a user. Point the endpoint only at a collector
you run.

Under Docker Compose every variable above is forwarded to the `auth-server`
container. A certificate or key variable names a path inside the container, so
mount the file too.

### What a record holds

| Part of the record | Value                                                                                              |
| ------------------ | -------------------------------------------------------------------------------------------------- |
| Body               | The event envelope as a JSON string, the same document the event store holds.                      |
| Event name         | The event type, such as `urn:qauth:event:user.signed_in:v1-rc.0`.                                  |
| Timestamp          | The event's `time`.                                                                                |
| Severity           | The type's severity: `info` is INFO (9), `warning` is WARN (13), `critical` is ERROR2 (18).        |
| Severity text      | The type's severity as written in the registry: `info`, `warning` or `critical`.                   |
| Trace and span id  | Those of the span active when the event committed, when the process has one.                       |
| Resource           | `service.name` from `OTEL_SERVICE_NAME`, and the OpenTelemetry SDK's `telemetry.sdk.*` attributes. |
| Scope              | `qauth.events`.                                                                                    |

Every record carries these attributes:

| Attribute              | Value                                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------------------- |
| `qauth.event.id`       | The event id, a UUIDv7. It is the same id on every route an event takes.                          |
| `qauth.event.type`     | The event type.                                                                                   |
| `qauth.event.category` | `user` or `admin`.                                                                                |
| `qauth.realm`          | The id of the realm the event happened in.                                                        |
| `qauth.subject.id`     | The subject's id, when the event has a subject.                                                   |
| `qauth.client.id`      | The `client_id` of the client the request came through, when there was one.                       |
| `qauth.request.id`     | The request id echoed on `REQUEST_ID_HEADER`, when no span is active and the event has a request. |

QAuth starts no traces itself. A record carries a trace id only when the
process runs an OpenTelemetry tracing setup of yours, such as the Node.js
auto-instrumentation loaded with `--require`, that made a span active for the
request. Otherwise `qauth.request.id` links the record to the request's log
lines (`reqId`) and to the `trace_id` of an error response.

A record holds what the event holds and nothing more. The event store refuses
an event that carries a password, a token, a key or a value shaped like one,
and the export checks every event against the same rules before it queues the
record. The export adds no masking of its own. On events that a person's own
request caused, the body includes the request's IP address and `User-Agent`,
as the event store does. An admin event's `diff` carries the before and after
values an admin changed, a contact address included, and a field an event type
declares as personal data goes out as it is stored. Your collector and the
storage behind it then hold that personal data, and how long they keep it is
yours to set: the event store's retention does not reach the exported copy.

### Queue, drops and limits

Export never fails a request, and a request never waits for the collector.
When an event commits, the request builds its record and puts it in a queue
in memory. The server sends the queue's records later, on its own:

- The queue holds up to 2048 records. When it is full, each new record pushes
  out the oldest one, so a collector that comes back receives the latest
  events.
- Records go out in batches of up to 512, one batch at a time. A batch leaves
  once 512 records wait, or a second after the first of them arrived. Records
  that arrive while a batch is out wait for it to end.
- A batch the collector refuses, or that cannot be sent before
  `OTEL_EXPORTER_OTLP_TIMEOUT`, is dropped after the exporter's own retries.
  It is not sent again. If an export has not reported 5 seconds after that
  timeout, its batch is given up and the next one goes out.
- When the server stops, it spends up to 5 seconds sending what is queued. It
  logs how many records were left unsent, and drops them.

`qauth_events_telemetry_dropped_total` counts the records the queue gives up.
`reason="queue_full"` counts records pushed out of a full queue, and
`reason="export_failed"` counts records in batches that failed or were given
up. The server logs two other losses instead of counting them: the records
left at shutdown (a warning), and an event that fails the event contract,
which the event store's own check already keeps out (an error). The counter
is on `/metrics` only while the export is on. A rule like this one tells you
when records keep being dropped for 15 minutes, as they are when the collector
falls behind or cannot be reached; a single burst, such as a collector
restart, does not fire it:

```yaml
- alert: QAuthEventExportDropping
  expr: increase(qauth_events_telemetry_dropped_total[5m]) > 0
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: 'QAuth is dropping event log records'
    description: 'The OpenTelemetry collector refuses or does not answer QAuth exports.'
```

## Background Jobs

The auth server runs periodic jobs in its own process
(`apps/auth-server/src/app/jobs/`). Every node of a deployment runs the same
jobs, and each job runs on one node at a time. The exception is a run that keeps
going past its time limit (below): it can overlap the next node's run, which is
why every job must be safe to repeat.

| Job             | Interval | Time limit | What it does                                                                                                                                     |
| --------------- | -------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `purge-expired` | 1 hour   | 5 minutes  | Deletes expired authorization codes, email verification tokens and OID4VP requests, and each refresh-token family whose every token has expired. |

How a run is placed:

- Runs are aligned to the interval on the wall clock: `purge-expired` runs once
  per clock hour. Each node wakes at a random point in the first 10% of the
  interval, at most 5 minutes in, so the nodes do not query the database
  together.
- The first node to wake takes a Postgres advisory lock named after the job, on
  a connection of its own, and runs the job. It keeps the lock until twice that
  wake window has passed (10 minutes past the hour for `purge-expired`), so the
  nodes that wake after it skip that interval. The second window allows for
  clock skew between nodes: keep their clocks synchronised (NTP). A node that
  only gets the lock after that time skips the interval too.
- The lock's connection comes from the server's pool (`DB_POOL_MAX`, 20 by
  default). Each job holds one from the moment it takes the lock until it
  releases it, and the job's own queries use others. A node that finds the lock
  held gives its connection back at once. The server refuses to start with
  `DB_POOL_MAX` below 2, where the lock would leave no connection for requests.
- The lock is a session-level lock, so a connection pooler in transaction mode
  between QAuth and Postgres (for example PgBouncer with
  `pool_mode = transaction`) cannot hold it.

What happens when a run goes wrong:

- A run that fails or reaches its time limit is logged and counted, and runs
  again at the next interval. There is no retry queue: every job is safe to
  repeat. A run is told to stop at its limit; a database statement it has
  already sent still runs to its end in Postgres.
- When a node dies or loses its database connection during a run, Postgres
  drops the lock, and another node takes the job at its next interval. Postgres
  notices at once when the node's process exits. A host that vanishes without
  closing its connection keeps the lock until the database server's TCP
  keepalive (`tcp_keepalives_idle` and the settings next to it) gives up on the
  connection.
- On `SIGTERM` or `SIGINT` the server tells running jobs to stop and waits up to
  5 seconds for them. Then it closes the database pool, which waits for a
  statement a job has already sent, so shutdown can take longer than that.

Each log line carries the job's name as `job`: `job run started`,
`job run finished` with `durationMs`, `job run failed` with `err`, and
`job run exceeded its time limit and was stopped`. A node that skips a run
because another node holds the lock logs `job run skipped: another node holds
its lock` at `debug`. `qauth_job_runs_total` counts the runs; a skipped run is
not counted, and a lock that cannot be taken, for example because the database
is unreachable, counts as a `failure`.

## Alerting (Optional)

QAuth does not ship an alerting stack. The following Prometheus Alertmanager
rules are recommended starting points; tune thresholds to your traffic. They
assume the `auth-server` is also instrumented for HTTP status codes (e.g. via a
proxy exporter or `http_requests_total`-style metric); the auth-failure rule uses
the built-in `qauth_login_attempts_total` counter.

```yaml
groups:
  - name: qauth-auth-server
    rules:
      # Spike in authentication failures — possible credential-stuffing/brute force.
      - alert: QAuthHighLoginFailureRate
        expr: |
          sum(rate(qauth_login_attempts_total{result="failure"}[5m]))
            /
          clamp_min(sum(rate(qauth_login_attempts_total[5m])), 1) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: 'High login-failure ratio on QAuth'
          description: 'Over 50% of login attempts have failed for 10 minutes.'

      # Elevated server errors (requires an HTTP status metric at the proxy/app).
      - alert: QAuthHigh5xxRate
        expr: |
          sum(rate(http_requests_total{job="qauth-auth-server",status=~"5.."}[5m]))
            /
          clamp_min(sum(rate(http_requests_total{job="qauth-auth-server"}[5m])), 1) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: 'High 5xx error rate on QAuth'
          description: 'More than 5% of requests are returning 5xx for 5 minutes.'

      # The scrape target is down.
      - alert: QAuthInstanceDown
        expr: up{job="qauth-auth-server"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: 'QAuth auth-server is down'
          description: 'Prometheus cannot scrape {{ $labels.instance }}.'
```

### Wiring Alertmanager

1. Add the rules above to a file referenced by `rule_files:` in `prometheus.yml`.
2. Point Prometheus at Alertmanager under `alerting.alertmanagers:`.
3. Configure Alertmanager receivers (email, Slack, PagerDuty, ...) and routing.
4. Reload Prometheus (`SIGHUP` or `POST /-/reload`) and verify under
   **Status → Rules** and **Alerts**.

## See also

- [Docker](/operate/docker/) — running the stack this endpoint is served from.
- [Environment-Aware Authorization](/operate/environment-authorization/) — how `environment` affects rate limits referenced above.
