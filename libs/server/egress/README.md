# @qauth-labs/server-egress

The one client for every outbound call that configuration or user input causes: webhooks,
back-channel logout, SSF push, upstream discovery, CIMD and `jwks_uri` fetches, and every call a
plugin makes ([ADR-019 Decisions 8 and 12](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md)).
It is SSRF-safe by construction. It has no switch that lets it reach a private address; only the
deployment allowlist can, for a destination the operator or an admin set, in a realm the entry
names.

> **Status:** the CIMD, client JWKS and ID-JAG issuer fetches of the auth server (through
> `@qauth-labs/fastify-plugin-egress`, as `fastify.egress`) and the SSF push use it (#410, #481).
> The back-channel logout, webhook and upstream provider callers move onto it as they land.

## Usage

```typescript
import { createEgressClient, isEgressError, loadEgressAllowlist } from '@qauth-labs/server-egress';

const egress = createEgressClient({
  logger: fastify.log,
  allowlist: loadEgressAllowlist(process.env.EGRESS_ALLOWLIST_PATH), // when it is set
});

// At registration: resolve and check, send nothing.
await egress.validateDestination(webhookUrl, {
  purpose: 'webhook',
  source: 'admin',
  realm: 'acme',
});

// At every delivery: the same checks again, then the call.
try {
  const res = await egress.request({
    method: 'POST',
    url: webhookUrl,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(event),
    purpose: 'webhook',
    source: 'admin', // an admin set this webhook
    realm: 'acme', // the allowlist entries naming this realm apply
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

`source` says who set the destination, and every call names it:

| Source            | Destinations                                                                   |
| ----------------- | ------------------------------------------------------------------------------ |
| `operator`        | The deployment's configuration: a trusted ID-JAG issuer's discovery URL.       |
| `admin`           | A realm admin: a back-channel logout URI or webhook an admin sets.             |
| `client`          | An OAuth client: a CIMD `client_id`, a registered `jwks_uri`, an SSF endpoint. |
| `end_user`        | An end user.                                                                   |
| `remote_document` | A fetched document: the `jwks_uri` an issuer's discovery document names.       |

`realm` names the realm the destination belongs to, by name. Only an `operator` or `admin`
destination with a `realm` can use the [allowlist](#the-deployment-allowlist).

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
- **Where the connection is made.** Not in the server's process: see
  [Fetch processes](#fetch-processes).

## The deployment allowlist

ADR-019 Decision 8 lets a non-public address be reached only when a deployment-level allowlist
names its host or range, the destination's `source` is `operator` or `admin`, and the call's
`realm` is one the entry names. A `client`, `end_user` or `remote_document` destination never uses
it. `EGRESS_ALLOWLIST_PATH` names the file; `loadEgressAllowlist(path)` reads and validates it, and
`parseEgressAllowlist(json)` validates a value already in hand. The client accepts only a list
those two made.

```json
{
  "entries": [
    { "host": "idp.corp.example", "realms": ["master"] },
    { "cidr": "10.20.0.0/16", "realms": ["master", "acme"], "note": "partner VPN" }
  ]
}
```

- `host` is matched exactly and case-insensitively against the URL's host, never with a wildcard.
  Every address the host resolves to may then be dialled. An IP address is written as a `cidr`.
- `cidr` is an IPv4 or IPv6 range in its first-address form (`10.20.0.0/16`, not `10.20.0.7/16`).
  Every address of the URL's host must lie in a listed range or be public. An IPv4-mapped IPv6
  address (`::ffff:10.20.0.7`) is judged by its IPv4 address; a NAT64 or 6to4 address is not.
- `realms` lists realm names, compared exactly. `note` is the operator's and is not read.
- An unknown member, an entry with both or neither of `host` and `cidr`, or an entry without realms
  refuses the whole file, naming where the mistake is.
- No entry opens an unspecified (`0.0.0.0/8`, `::`), multicast or cloud metadata
  (`169.254.169.254`, `fd00:ec2::254`, in any IPv6 form that carries it) address.
- A redirect to another host never uses the entry that let the first request through: its target is
  the remote side's choice, not the operator's. A redirect on the same host does.

The list is not in the database and no API edits it; the auth server reads the file once at boot
(`@qauth-labs/fastify-plugin-egress`).

## The test-only client

`createTestEgressClient(options)` is the production client with two changes: it may also reach
loopback addresses (`localhost`, `127.0.0.1`, `::1`) for any source, and its names resolve with the
operating system's resolver (so `localhost` resolves) and its exchanges run in the test's process.
Every other check stays. It exists only while `NODE_ENV` is `test`: creating one, and every call
through one, throws otherwise. TLS trusts the process's default CA certificates;
`src/testing/loopback-fixture.ts` starts an HTTPS server on localhost whose CA it adds. It replaces
the removed `CIMD_ALLOW_PRIVATE_ADDRESSES` and `ID_JAG_ALLOW_PRIVATE_ADDRESSES` switches.

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
response head at 16 KiB and tolerates at most three `1xx` interim responses. Chunk-size lines, chunk
extensions and trailers are not body bytes, so it also caps everything it reads from the connection
at twice `maxResponseBytes` plus room for the heads; a host cannot stream framing until the total
timeout.

## Fetch processes

The client resolves names and runs every check in the server's process. The exchange itself — the
TCP connection to a checked address, the TLS handshake, the HTTP request and the byte caps — runs in
a fetch process, a Node process of its own (`src/lib/process-pool.ts`, program
`src/lib/exchange.ts`). OpenSSL works through a handshake message in one synchronous call that
nothing interrupts, and a host can make that call last seconds (a Certificate message of
certificates whose EC keys use an explicit curve). On the server's own thread that would stop every
route and timer; on a worker thread it would hold the thread, and its slot, until OpenSSL returned.
A process can be killed.

- **Deadlines stay in the server's process.** The connect time runs until the process reports the
  end of the TLS handshake; the total time runs for the whole call. A process that passes either is
  killed with `SIGKILL`, the call fails with `timeout`, and a fresh process starts when a call next
  needs one. A process holds its slot until it has exited.
- **Nothing of the server's.** A process starts with an empty environment (Node adds the two
  variables of its IPC channel and removes them at start), `/dev/null` for its standard streams, no
  file descriptor of the server's but that channel, none of the server's Node flags, a 64 MiB heap,
  the lowest CPU priority and, on Linux, the highest OOM score, so that the kernel ends a fetch
  process before the server when memory runs out.
- **The descriptors, in detail.** Node opens its own descriptors close-on-exec and marks a low few
  it inherits, but a supervisor (a CI runner, an init system, a shell) can hand the server higher
  ones without close-on-exec, and libuv's spawn closes none. On Linux the pool lists those
  (`/proc/self/fdinfo`, as `fd:dev:ino`) and passes the list to the process, which closes each
  that is still the same file before it reads its first message (`inheritedDescriptors`,
  `closeInheritedDescriptors`). Elsewhere the list is empty, so a descriptor the server inherited
  without close-on-exec reaches the fetch process.
- **The server's TLS setup.** A process trusts the certificates the server's process trusts —
  Node's bundled roots, `NODE_EXTRA_CA_CERTS`, the system store when Node uses it — and takes its
  TLS defaults (`--tls-min-v1.3`, `--tls-cipher-list`), both sent over the channel when it starts.
  The OpenSSL flags of the server's command line and `NODE_OPTIONS` (`--use-openssl-ca`,
  `--use-system-ca`, `--openssl-config`, `--openssl-legacy-provider`, `--enable-fips`, …) are
  passed on, `OPENSSL_CONF` as `--openssl-config`, and with `--use-openssl-ca` the process reads
  OpenSSL's store from the server's `SSL_CERT_FILE` and `SSL_CERT_DIR`, sent over the channel.
- **Bounds.** At most 8 processes run at once, and the calls to one host family hold at most 2 of
  them. A host name counts under its registrable domain, by the Public Suffix List with its private
  section: `a.example.com` and `b.example.com` share a family, `alice.eu.org` and `bob.eu.org` do
  not. An IPv4 literal is its own family, an IPv6 literal counts under its /64. At most 64 calls
  wait for a process, 8 per family; any more fail at once with `busy`. A waiting call's time counts
  against its total time.
- **One exchange at a time.** A process runs one exchange, sends back the status, the headers and
  the body, and waits for the next; it keeps nothing between them. An idle process exits after a
  minute. The pool checks every answer — its shape, the body against `maxResponseBytes`, a failure
  message kept to one line that names the host — and kills a process that answers out of turn.
- **Loaded from source.** Node does not strip the types of a file under `node_modules`, where a
  deployment keeps this library, so the pool reads `exchange.ts` and hands it to Node with
  `--input-type=module-typescript --eval`. That file therefore imports `node:` builtins only, and
  the library runs from its TypeScript sources only, as the server does.
- **Memory.** An idle fetch process takes about 70 MB, so a full pool adds about 600 MB to the
  server's memory; allow for it in a container limit. Processes start only for concurrent calls and
  exit after a minute without one.
- **Killability, not confidentiality.** A fetch process runs as the server's user. The pool keeps a
  host from holding the server's CPU or its slots past a deadline; it does not keep the server's
  secrets from a fetch process that a host has taken over, which can read
  `/proc/<server pid>/environ`, or end the server through the channel.

`egressPoolStats()` returns what the pool is doing, for `/metrics`:

| Field           | Meaning                                                                |
| --------------- | ---------------------------------------------------------------------- |
| `processes`     | Fetch processes alive, busy or idle; a killed one until it has exited. |
| `busy`          | Processes running an exchange.                                         |
| `waiting`       | Calls waiting for a process.                                           |
| `deadlineKills` | Processes killed because their exchange passed a deadline (a counter). |
| `maxProcesses`  | The most processes that run at once.                                   |

With prom-client, read it at each scrape:

```typescript
import { egressPoolStats } from '@qauth-labs/server-egress';

new Gauge({
  name: 'qauth_egress_processes',
  help: 'Egress fetch processes alive.',
  registers: [registry],
  collect() {
    this.set(egressPoolStats().processes);
  },
});
```

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
| `busy`        | The fetch processes had no room for the call (see Fetch processes).           |

`EgressError.outcome` is `blocked` when a check refused the call (nothing more was sent to the
refused destination) and `failed` otherwise, `busy` included. The message names the host and never the path, the
query string or a header.

Every blocked or failed call is counted by purpose, outcome and reason. `egress.counts()` returns
the counts. A `counter` option receives them too; a prom-client
`Counter<'purpose' | 'outcome' | 'reason'>` fits. A `logger` option (pino-style `warn(fields,
message)`) gets one line per call with `purpose`, `source`, `host`, `reason` and `outcome`.

## Tests

`src/lib/egress-client.test.ts` runs the production path against local HTTPS servers.
`src/testing/fixture-network.ts` replaces only the two network edges: a resolver that answers from a
table, and a dialler that routes the public addresses the test hands out to local servers. The
dialler cannot cross to a fetch process, so there the exchanges run in the test's process. The
library exports no way to hand the client another network, so the test swaps them in by mocking
the transport module (`vi.mock('./transport')`). The resolver (`resolveWithCares`) and the dialler
(`dialPinned`) the client uses outside tests have their own tests in `src/lib/transport.test.ts`.

`src/lib/process-pool.test.ts` starts real fetch processes against local TLS servers: a server that
stalls mid-handshake and one that keeps OpenSSL busy for seconds (`src/testing/hostile-handshake.ts`)
are killed at the deadline while another host is served; many host names of one server hold no
more than the family's share; and on Linux `/proc` shows what a process inherits: its environment
and its file descriptors, also when the server holds a descriptor without close-on-exec (the test
starts a vitest that holds one at descriptor 200, as a CI runner does).
Run them with:

```console
pnpm nx test server-egress
```
