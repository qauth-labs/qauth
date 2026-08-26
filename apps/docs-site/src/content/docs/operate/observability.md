---
title: Observability Guide
description: QAuth's observability surface — structured logging, request-id tracking, auth-event logging, failed-login lockout, Prometheus metrics, and alerting.
sidebar:
  order: 3
lastVerified: '2026-08-10'
---

This guide covers QAuth's observability surface: structured logging, request-id
tracking, auth-event logging, failed-login tracking/lockout, Prometheus metrics,
and recommended alerting.

## Overview

| Capability                | Mechanism                                                        |
| ------------------------- | ---------------------------------------------------------------- |
| **Structured logging**    | pino (built into Fastify) with secret redaction                  |
| **Request-id tracking**   | `genReqId` + `REQUEST_ID_HEADER`, echoed on responses            |
| **Auth-event logging**    | Structured `authEvent` log lines for login/register/logout/token |
| **Failed-login tracking** | Redis-backed per-identifier counters with temporary lockout      |
| **Metrics**               | `GET /metrics` in Prometheus text format via `prom-client`       |
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
(`apps/auth-server/src/app/helpers/auth-events.ts`) — login and logout on both
success and failure, registration on success.

> ⚠️ **Token-exchange events are not log lines.** `logAuthEvent` is called only
> from `routes/auth/login.ts`, `routes/auth/logout.ts` and
> `routes/auth/register.ts`. The `oauth.token.exchange.*` names exist as members
> of the event type union, but the token endpoint records them **only as rows in
> the `audit_logs` table**, never through the logger. An alert built on an
> `oauth.token.exchange.success` log line will never fire — query the audit table
> for those instead.

Each emitted line carries:

- `authEvent` — e.g. `user.login.success`, `user.login.failure`.
- `success`, `userId`/`clientId` (when known), `ip`, ISO `timestamp`, and
  `reqId`.
- On **failure** paths, the email is logged as a SHA-256 `emailHash` rather than
  the raw address, to avoid account enumeration. Passwords/tokens are never
  logged.

These structured logs complement the durable `audit_logs` database trail.

## Failed-Login Tracking & Lockout

Failed logins are tracked per identifier (email **hash** and source IP) in Redis
(`apps/auth-server/src/app/helpers/failed-login.ts`). After
`FAILED_LOGIN_MAX_ATTEMPTS` failures inside `FAILED_LOGIN_WINDOW`, the identifier
is locked out for `FAILED_LOGIN_LOCKOUT_DURATION` seconds; further login attempts
return `429 Too Many Requests` with a `Retry-After` header before any credential
verification.

- The attempt counter has a TTL equal to the window, so it **decays** naturally.
- A **successful** login clears both the counter and any lockout.
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
process/runtime metrics plus QAuth auth counters:

| Metric                       | Type    | Labels               | Meaning                           |
| ---------------------------- | ------- | -------------------- | --------------------------------- |
| `qauth_login_attempts_total` | counter | `result`, `reason`   | Login outcomes (success/failure). |
| `qauth_tokens_issued_total`  | counter | `type`, `grant_type` | Tokens issued by type and grant.  |

Label values, as emitted today. The plugin
(`apps/auth-server/src/app/plugins/metrics.ts`) does not constrain them, so treat
each list as **open** — a new call site can add a value without a schema change.

- `result` is `success` or `failure`. `reason` is set on failures only, e.g.
  `invalid_credentials`, `locked_out`, `email_not_verified` (emitted only when
  `REQUIRE_EMAIL_VERIFIED=true`), `error`.
- `type` is e.g. `access`, `refresh`, or `id_jag` (the ID-JAG assertion minted by
  the token-exchange grant). `grant_type` is e.g. `password`,
  `authorization_code`, `refresh_token`, `client_credentials`, `token-exchange`,
  or `jwt-bearer`.

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

### Example Prometheus scrape config

```yaml
scrape_configs:
  - job_name: qauth-auth-server
    metrics_path: /metrics
    static_configs:
      - targets: ['auth-server:3000']
```

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
