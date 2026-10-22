# @qauth-labs/server-egress

The one client for every outbound call that configuration or user input causes: webhooks,
back-channel logout, SSF push, upstream discovery, CIMD and `jwks_uri` fetches, and every call a
plugin makes ([ADR-019 Decisions 8 and 12](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md)).
It is SSRF-safe by construction and has no switch that lets it reach a private address.

> **Status:** the library is complete, but nothing calls it yet. #481 moves the CIMD, client JWKS
> and ID-JAG fetches onto it and adds the deployment-level allowlist for operator-set private
> destinations. #749 moves its TLS work into a pool of child processes.

## Usage

```typescript
import { createEgressClient, isEgressError } from '@qauth-labs/server-egress';

const egress = createEgressClient({ logger: fastify.log });

// At registration: resolve and check, send nothing.
await egress.validateDestination(webhookUrl, { purpose: 'webhook' });

// At every delivery: the same checks again, then the call.
try {
  const res = await egress.request({
    method: 'POST',
    url: webhookUrl,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(event),
    purpose: 'webhook',
    limits: { maxRedirects: 0 },
  });
  // res.status, res.headers, res.body (a Buffer), res.url, res.redirects
} catch (err) {
  if (isEgressError(err)) {
    // err.reason, err.outcome ('blocked' | 'failed'), err.host
  }
  throw err;
}
```

`request` resolves with the final response whatever its status; a 4xx or 5xx is the caller's to
judge. It rejects with an `EgressError` when a check refuses the call or the call fails, and with a
`TypeError` for a caller's mistake: an unknown method, a bad `purpose`, a body on `GET` or `HEAD`, a
header the client sets itself, or an invalid limit.

`purpose` is a fixed label of the caller, such as `webhook` or `cimd`, not data. It names the call
in counts and logs, so it is limited to lower-case letters, digits and `_ . : -`, 64 characters at
most.

## What the client checks

- **Scheme and credentials.** `https` only. A URL with a user name or password is refused.
- **Addresses.** The host is resolved once per request, A and AAAA, with c-ares (never
  getaddrinfo, never `/etc/hosts`). When any address is not public the whole name is refused. An IP
  literal in the URL is checked the same way. The WHATWG URL parser has already turned the other
  IPv4 spellings (`0x7f.1`, `2130706433`) into dotted quads.
- **The connection.** The client dials only the addresses it checked, so a name that answers
  differently a moment later (DNS rebinding) changes nothing. TLS names the URL's host in SNI and
  checks the certificate against it. `rejectUnauthorized` is set explicitly, so
  `NODE_TLS_REJECT_UNAUTHORIZED=0` cannot turn it off.
- **Redirects.** A `301`, `302`, `303`, `307` or `308` with a `Location` is followed only after its
  target passes every check above. At most 3 by default; a caller sets `maxRedirects: 0` to follow
  none. `Authorization` and `Cookie` are dropped when a redirect leaves the origin (host and port).
  `303`, and `301` or `302` after a `POST`, turn the request into a `GET` without its body, as
  `fetch` does.
- **Proxies.** None. The client opens its own connection and uses no agent, so `HTTP_PROXY`,
  `HTTPS_PROXY` and a proxy-aware global agent (`NODE_USE_ENV_PROXY`) have no effect. A proxy would
  hide the real destination from the address checks.

Refused addresses (`isPublicUnicastAddress`, `addressKind`):

| Kind            | IPv4                                                                                    | IPv6                                       |
| --------------- | --------------------------------------------------------------------------------------- | ------------------------------------------ |
| `unspecified`   | `0.0.0.0/8`                                                                             | `::`                                       |
| `loopback`      | `127.0.0.0/8`                                                                           | `::1`                                      |
| `private`       | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`                                         |                                            |
| `shared`        | `100.64.0.0/10` (carrier-grade NAT)                                                     |                                            |
| `link-local`    | `169.254.0.0/16`, with the metadata address `169.254.169.254`                           | `fe80::/10`                                |
| `unique-local`  |                                                                                         | `fc00::/7`, with `fd00:ec2::254`           |
| `multicast`     | `224.0.0.0/4`                                                                           | `ff00::/8`                                 |
| `documentation` | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`                                     | `2001:db8::/32`, `3fff::/20`               |
| `reserved`      | `192.0.0.0/24`, `192.88.99.0/24`, `198.18.0.0/15`, `240.0.0.0/4` with `255.255.255.255` | `2001::/23`, everything outside `2000::/3` |

An IPv6 address that carries an IPv4 address is judged by that address: IPv4-mapped
(`::ffff:0:0/96`), NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`), in hex or dotted form. The
deprecated IPv4-compatible form (`::/96`) is outside `2000::/3` and refused. A literal with a zone
id is refused.

## Limits

| Limit              | Default | Meaning                                                               |
| ------------------ | ------- | --------------------------------------------------------------------- |
| `connectTimeoutMs` | 5 000   | TCP connect plus the TLS handshake, per connection (so per redirect). |
| `totalTimeoutMs`   | 10 000  | The whole call: resolution, every redirect, the last body byte.       |
| `maxRequestBytes`  | 1 MiB   | The request body. A larger one is refused before anything is sent.    |
| `maxResponseBytes` | 1 MiB   | The response body. Reading stops at the cap.                          |
| `maxRedirects`     | 3       | Redirects followed. `0` follows none.                                 |

`createEgressClient({ limits })` sets the client's limits; `request({ limits })` and
`validateDestination(url, { limits })` override them for one call. The client also caps the
response head at 16 KiB and tolerates at most three `1xx` interim responses.

## Errors, counts and logs

`EgressError.reason` is one of:

| Reason        | When                                                                          |
| ------------- | ----------------------------------------------------------------------------- |
| `scheme`      | The URL, or a redirect target, is not `https` (or not a URL).                 |
| `credentials` | The URL, or a redirect target, carries a user name or password.               |
| `address`     | The host is, or resolves to, an address that is not public.                   |
| `redirect`    | A redirect past `maxRedirects`, or one whose `Location` is not a URL.         |
| `size`        | The request body or the response body is above its cap.                       |
| `timeout`     | The connect time or the total time ran out.                                   |
| `network`     | The name did not resolve, or the connection, TLS or the HTTP exchange failed. |

`EgressError.outcome` is `blocked` when a check refused the call (nothing more was sent to the
refused destination) and `failed` otherwise. The message names the host and never the path, the
query string or a header.

Every blocked or failed call is counted by purpose, outcome and reason. `egress.counts()` returns
the counts. A `counter` option receives them too; a prom-client
`Counter<'purpose' | 'outcome' | 'reason'>` fits. A `logger` option (pino-style `warn(fields,
message)`) gets one line per call with `purpose`, `host`, `reason` and `outcome`.

## Tests

`src/lib/egress-client.test.ts` runs the production path against local HTTPS servers.
`src/testing/fixture-network.ts` replaces only the two network edges: a resolver that answers from a
table, and a dialler that routes the public addresses the test hands out to local servers. The
resolver (`resolveWithCares`) and the dialler (`dialPinned`) the client uses outside tests have
their own tests in `src/lib/transport.test.ts`. Run them with:

```console
pnpm nx test server-egress
```
