# Observability Guide

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
values with `[Redacted]`. Covered fields include passwords, access/refresh/ID
tokens, client secrets, OAuth codes, PKCE verifiers, `Authorization` headers,
and cookies — at both top-level and nested (`*.field`) positions. See
`apps/auth-server/src/config/logger.ts` (`LOG_REDACT_PATHS`). A regression test
(`logger.test.ts`) asserts that none of these values reach the log output.

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

Login, registration, logout, and token exchange emit structured log lines via
`logAuthEvent` (`apps/auth-server/src/app/helpers/auth-events.ts`), on both
success and failure. Each line carries:

- `authEvent` — e.g. `user.login.success`, `user.login.failure`,
  `oauth.token.exchange.success`.
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
  logins are never blocked by the tracker.

### Configuration

| Variable                        | Default | Description                            |
| ------------------------------- | ------- | -------------------------------------- |
| `FAILED_LOGIN_TRACKING_ENABLED` | `true`  | Master switch for throttling/lockout.  |
| `FAILED_LOGIN_MAX_ATTEMPTS`     | `5`     | Failures in the window before lockout. |
| `FAILED_LOGIN_WINDOW`           | `900`   | Sliding window in seconds (15 min).    |
| `FAILED_LOGIN_LOCKOUT_DURATION` | `900`   | Lockout duration in seconds (15 min).  |

## Metrics (`GET /metrics`)

QAuth exposes Prometheus metrics in text exposition format at `GET /metrics`
(`apps/auth-server/src/app/routes/metrics.ts`). The endpoint includes default
process/runtime metrics plus QAuth auth counters:

| Metric                       | Type    | Labels               | Meaning                           |
| ---------------------------- | ------- | -------------------- | --------------------------------- |
| `qauth_login_attempts_total` | counter | `result`, `reason`   | Login outcomes (success/failure). |
| `qauth_tokens_issued_total`  | counter | `type`, `grant_type` | Tokens issued by type and grant.  |

- `result` is `success` or `failure`; `reason` annotates failures
  (`invalid_credentials`, `locked_out`, `error`).
- `type` is `access` or `refresh`; `grant_type` is `password`,
  `authorization_code`, `refresh_token`, `client_credentials`, or
  `token-exchange`.

The endpoint is **unauthenticated and rate-limit-exempt** (so a scraper can poll
it frequently). Restrict access at the reverse proxy / network layer (e.g. to a
metrics subnet), or disable it entirely with `METRICS_ENABLED=false`.

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
