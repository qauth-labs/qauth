---
title: Request lifecycle
description: A walk through apps/auth-server's bootstrap in execution order — which registration orders are load-bearing and which only look it, what the fail-closed boot checks refuse, and the two security invariants a contributor can silently undo.
sidebar:
  order: 2
lastVerified: '2026-07-27'
---

The auth server is assembled in two files, and reading them in the order they execute is the
fastest way to understand what a request meets on its way in:

- `apps/auth-server/src/main.ts` builds the Fastify instance, installs the Zod compilers,
  registers OpenAPI, then registers the app and listens.
- `apps/auth-server/src/app/app.ts` — one plugin function — registers everything else, in
  source order.

Both files carry unusually precise comments, and this page quotes them rather than paraphrasing
wherever they are exact. Where a comment states an ordering **requirement**, this page says
whether Fastify actually enforces it — because two of them do not, and one requirement that
nothing documents does.

## Part 1 — `main.ts`: the instance, before any route exists

`main.ts` does four things that `app.ts` cannot do, because they are properties of the root
Fastify instance rather than of a plugin.

### 1. The instance options (`apps/auth-server/src/main.ts:29`)

`logger` (pino with secret redaction), `requestIdHeader` / `requestIdLogLabel` / `genReqId`
(an inbound request id is honoured when present and generated otherwise, then attached to the
request-scoped logger as `reqId`), and `routerOptions.ignoreTrailingSlash`.

What is **not** in that options object is the point — see
[HTTP/1.1 only](#security-invariant-1--http11-only) below.

### 2. The global Zod validator and serializer compilers (`apps/auth-server/src/main.ts:53`)

`setValidatorCompiler(validatorCompiler)` and `setSerializerCompiler(serializerCompiler)` from
`fastify-type-provider-zod`, applied to the root instance so they are inherited by every route
in every plugin below. This is what makes `schema: { body: someZodSchema }` work, and it is also
a security control — see
[the global Zod compiler](#security-invariant-2--the-global-zod-validator-compiler) below.

### 3. OpenAPI, before the app (`apps/auth-server/src/main.ts:80`)

`@fastify/swagger` is registered **before** `server.register(app)` at
`apps/auth-server/src/main.ts:89`, and the comment there says why: routes must be added after
swagger so they are collected into the generated spec. The Swagger **UI** at `/docs` is gated on
`ENABLE_SWAGGER`, which defaults to `true` outside production and `false` in production
(resolved at the bottom of `apps/auth-server/src/config/env.ts`). The spec itself is registered
either way; the flag only suppresses the `/docs` route.

If you add a route and it does not appear in `openapi.json`, check that it is reachable from
`app()` rather than registered directly on the server after `listen`.

### 4. Signal handling and `listen`

`SIGTERM` / `SIGINT` both call `shutdown`, which awaits `server.close()` before
`process.exit(0)`. Anything you add that holds a resource open should be closed by a Fastify
`onClose` hook rather than by extending this function.

## Part 2 — `app.ts` in execution order

Every line below is `await`ed except where noted, so the order in the file is the order at boot.

| #   | Registration                                                        | What it contributes                                   |
| --- | ------------------------------------------------------------------- | ----------------------------------------------------- |
| 1   | `databasePlugin`, `apps/auth-server/src/app/app.ts:53`              | Postgres pool + the `repositories` decorator          |
| 2   | `cachePlugin`, `apps/auth-server/src/app/app.ts:65`                 | Redis (`lazyConnect: true`) as `fastify.redis`        |
| 3   | `passwordPlugin`, `apps/auth-server/src/app/app.ts:79`              | argon2id hasher + strength scoring                    |
| 4   | `pkcePlugin`, `apps/auth-server/src/app/app.ts:90`                  | PKCE challenge verification helpers                   |
| 5   | `assertTrustedIssuersUsable`, `apps/auth-server/src/app/app.ts:122` | **Boot check** — not a plugin                         |
| 6   | `federationPlugin`, `apps/auth-server/src/app/app.ts:124`           | The ADR-003 `providerRegistry` decorator              |
| 7   | `emailPlugin`, `apps/auth-server/src/app/app.ts:169`                | Resend / SMTP / mock provider                         |
| 8   | `jwtPlugin`, `apps/auth-server/src/app/app.ts:181`                  | Signing keys, JWKS, revocation callback               |
| 9   | `rateLimitPlugin`, `apps/auth-server/src/app/app.ts:226`            | `@fastify/rate-limit` wiring                          |
| 10  | `securityHeadersPlugin`, `apps/auth-server/src/app/app.ts:231`      | Helmet: CSP, HSTS, frame options                      |
| 11  | `requestIdPlugin`, `apps/auth-server/src/app/app.ts:235`            | Echoes the request id back on the response            |
| 12  | `metricsPlugin`, `apps/auth-server/src/app/app.ts:236`              | Prometheus registry                                   |
| 13  | `cors`, `apps/auth-server/src/app/app.ts:254`                       | Fail-closed in production when `CORS_ORIGIN` is unset |
| 14  | `formbody`, `apps/auth-server/src/app/app.ts:263`                   | Form-encoded body parsing                             |
| 15  | `AutoLoad` over `plugins/`, `apps/auth-server/src/app/app.ts:265`   | Not `await`ed; see below                              |
| 16  | `AutoLoad` over `routes/`, `apps/auth-server/src/app/app.ts:272`    | Not `await`ed; every route in the app                 |
| 17  | `errorHandler`, `apps/auth-server/src/app/app.ts:279`               | The global error handler                              |

## Which orders are load-bearing, and why they differ

There is no single rule here, and "register it before the routes" is not one. Fastify binds
different extension points at different moments, and that is what decides whether a line's
position matters:

| Extension point                                | Bound when                                                                | Position relative to routes                                  |
| ---------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Content-type parsers (`formbody`)              | Per encapsulation context, as each child plugin is created                | **Must precede routes**                                      |
| `onRoute` hooks (`@fastify/rate-limit`)        | Fire only for routes registered after the hook exists                     | **Must precede routes**                                      |
| The error handler                              | Captured into each route's context when that route's plugin finishes load | **Must precede routes** — and currently does not; see below  |
| Request/response hooks (`onRequest`, `onSend`) | Collected at Fastify's `preReady`, after every plugin has loaded          | Position does not change behaviour                           |
| Decorators (`fastify.repositories`)            | Resolved through the prototype chain at request time                      | Matters only for code that reads them at _registration_ time |

Steps 1–8 are ordinary dependency ordering of the last kind: `rateLimitPlugin` reads
`fastify.redis` while it is registering, so the cache plugin must already have decorated the
instance — and that specific dependency is enforced rather than assumed, by
`dependencies: [CACHE_PLUGIN_NAME]` in the plugin's own `fastify-plugin` options
(`apps/auth-server/src/app/plugins/rate-limit.ts`). Reach for that mechanism when you add a
plugin with a hard prerequisite; it turns a silent misordering into a boot failure that names
the missing plugin.

### `formbody` must precede routes — verified

`@fastify/formbody` at `apps/auth-server/src/app/app.ts:263`, with its own comment:

> RFC 6749 §3.2 (token endpoint) and RFC 7662 §2.1 (introspection) both mandate
> `application/x-www-form-urlencoded` for request bodies. Fastify ships with a JSON parser by
> default — without formbody, every OAuth-spec-compliant client gets 415 Unsupported Media Type.
> Register before routes so /oauth/\* receives decoded form bodies.

This is real, and it is the ordering mistake with the widest blast radius in the file. Content-type
parsers belong to an encapsulation context: an encapsulated child plugin gets the parser set that
existed when it was created, so a parser registered on the parent afterwards never reaches that
child's routes. Move this line below step 16 and the symptom is not a test failure — it is
`415 Unsupported Media Type` for every client that follows the spec, while any client that happens
to send JSON keeps working.

One wrinkle worth knowing, because it makes the failure partial rather than total: a route file
wrapped in `fastify-plugin` is _not_ encapsulated, so it shares the parent's parser set and would
keep working. Most route files under `apps/auth-server/src/app/routes/` export a plain plugin
function and would break; a handful (`apps/auth-server/src/app/routes/oauth/token.ts` among them)
are `fp`-wrapped and would not. A half-broken token endpoint whose introspection sibling returns
415 is a much worse debugging experience than a uniformly broken one.

The registration has a dedicated test at `apps/auth-server/src/app/plugins/formbody.test.ts` — but
note it is a test of the _plugin's behaviour_, deliberately built on a bare `Fastify()` instance,
not a test that `app.ts` still registers it in the right place. Nothing tests the ordering.

### `rateLimitPlugin` must precede routes — verified, and undocumented

Nothing in `app.ts` flags this one, so it is the easiest to break by tidying.

`@fastify/rate-limit` reads each route's `config.rateLimit` through an **`onRoute` hook**, and
`onRoute` is the one Fastify hook that is not retroactive: it fires as routes are added, so a
route registered before the hook exists is never seen. Routes across the app set per-route limits
this way — `apps/auth-server/src/app/routes/auth/login.ts:43` is the one that matters most — and
`apps/auth-server/src/app/routes/metrics.ts:31` opts out with `config: { rateLimit: false }`.

Move step 9 below step 16 and rate limiting stops applying to any of them. There is no error, no
warning, and no failing test: the endpoints simply answer every request. Treat this line as being
under the same "do not move" rule as `formbody`, even though it carries no comment saying so.

### Security headers, request-id, metrics, CORS — the comments overstate this

`securityHeadersPlugin` at `apps/auth-server/src/app/app.ts:231` carries a comment saying to
register before routes

> so every response — including the server-rendered login/consent pages and error responses —
> carries the CSP, HSTS, frame-options and related hardening headers.

and `apps/auth-server/src/app/app.ts:234` says request-id propagation and the metrics registry
"must be available before routes are loaded".

**Fastify does not require this.** `onRequest` / `onSend` hooks are collected at `preReady`, after
every plugin in the boot has loaded, so a hook added to the parent instance applies to routes that
were registered before it. All four of these plugins are `fastify-plugin`-wrapped — meaning they
install their hooks on the app instance rather than in a private child scope — so moving any of
them after step 16 changes nothing observable: the CSP header is still set, `reply.cspNonce` is
still populated on the login and consent pages, the request id is still echoed, and CORS still
applies.

The intent behind the comments is sound and the current order is the right convention — a reader
should not have to reason about hook collection to be confident the headers are global. But the
comments describe a guarantee stronger than the framework gives, so **do not infer the converse**:
"it is before the routes" is not evidence that something is safe to move, and it is not evidence
that a plugin registered after routes is broken. Decide per extension point, using the table above.

What genuinely matters about the security headers plugin is inside it, not around it:

- **The nonce.** The login and consent pages ship inline `<style>` blocks and stamp
  `reply.cspNonce.style` onto each one rather than weakening the policy with `'unsafe-inline'`.
  Add an inline `<style>` without the nonce and the browser refuses it.
- **The `/docs` exception.** Swagger UI bundles its own inline scripts and cannot use the nonce,
  so that one prefix is served a relaxed policy. The exception is scoped to the prefix; every
  other route keeps the strict policy (`apps/auth-server/src/app/plugins/security-headers.ts`).

## The two `AutoLoad` calls

```ts
// apps/auth-server/src/app/app.ts:265
fastify.register(AutoLoad, {
  dir: path.join(__dirname, 'plugins'),
  options: { ...opts },
  ignorePattern:
    /(error-handler|rate-limit|security-headers|metrics|request-id)\.(ts|js)$|\.(test|spec)\.(ts|js)$/,
});
```

Note what the `ignorePattern` names: every plugin `app.ts` registers **explicitly** above. That is
the design — those five need a chosen position in the order, so they are registered by hand and
excluded from the sweep to avoid being registered twice. As of `HEAD` the `plugins/` directory
contains nothing else, so this first `AutoLoad` call registers zero plugins. It is the escape
hatch for a future plugin whose position does not matter, not a place to read the current plugin
set from.

The routes sweep at `apps/auth-server/src/app/app.ts:272` is the one that matters day to day.
`@fastify/autoload` derives each plugin's URL prefix from its **directory**, not its filename —
`routes/auth/login.ts` registering `'/login'` serves `/auth/login` — with one override: a
directory whose entry file exports `autoPrefix` uses that string instead of the directory name,
and every file in that directory shares it (see
`apps/auth-server/src/app/routes/clients/index.ts`). If you add a route file and it 404s, that
mapping is the first thing to check.

Neither `AutoLoad` call is `await`ed. That is harmless — `fastify.register` enqueues, and the
`await` on the next registration flushes the queue in order — but it means the two sweeps and
everything after them share one boot phase rather than completing one at a time.

## The error handler

`apps/auth-server/src/app/app.ts:278` reads:

```ts
// Register error handler last to catch all unhandled errors
await fastify.register(errorHandler);
```

`apps/auth-server/src/app/plugins/error-handler.ts` is what turns the domain errors from
`@qauth-labs/shared-errors` into the wire shapes the rest of the docs describe: OAuth error codes,
RFC 6750 `WWW-Authenticate` challenges with a sanitized `error_description`, a `feedback` array for
weak passwords, `retryAfter` for rate limits, and — importantly — suppression of the message and
stack for unknown errors when `env.NODE_ENV === 'production'`. Routes throw
(`throw new InvalidGrantError(...)` and friends) and never build these bodies themselves.

> **⚠️ Registering last does not do what the comment says.** In Fastify 5 each route's context
> captures the error handler of its enclosing instance in an `after()` callback that runs when
> that route's plugin finishes loading (`errorHandler` in `node_modules/fastify/lib/route.js`),
> and `context.errorHandler` is what `node_modules/fastify/lib/error-handler.js` reads at request
> time. A `setErrorHandler` that runs _after_ a route plugin has loaded therefore does not reach
> that plugin's routes — they keep whatever handler was in effect when they loaded. The comment
> states an intent, not a mechanism Fastify provides. **This has been reported to the maintainers
> and is deliberately not changed here.** Do not move this line in either direction without
> reading that report first, and if you are adding a route whose contract includes a specific
> error body, assert that body end-to-end rather than assuming this plugin shaped it.

Note also that every test which exercises the handler's mapping —
`apps/auth-server/src/app/plugins/error-handler.test.ts`,
`apps/auth-server/src/app/routes/oauth/userinfo.test.ts`,
`apps/auth-server/src/app/routes/oauth/signature-verification.test.ts` — registers `errorHandler`
**before** the routes under test. Those tests prove the mapping logic; none of them reproduces the
production composition — see [Testing](/extend/testing/#the-honest-limitation) for why that whole
tier is blind to this class of problem.

## The fail-closed boot checks

Three things in the bootstrap answer configuration questions at startup rather than at request
time. They are not symmetrical, and the difference is worth getting right.

### `assertTrustedIssuersUsable` — refuses the boot, ungated

`assertTrustedIssuersUsable(env.OID4VP_TRUSTED_ISSUERS)` at
`apps/auth-server/src/app/app.ts:122`, implemented at
`libs/server/federation/src/trust/assert-trusted-issuers.ts:63`, throws
`InvalidConfigurationError` on an `OID4VP_TRUSTED_ISSUERS` map the runtime could not use.

**What it refuses, and why refusing is right.** The variable is validated twice by two different
rule sets that did not agree: `server-config`'s schema checks each entry is a syntactically valid
HTTPS URL and caps its length, while the runtime additionally reduces the same entry with
`canonicalizeIssuerIdentifier`, which refuses userinfo, a query string, and a fragment. Because
per-realm trust resolution is deliberately **all-or-nothing**, a single entry the canonicalizer
refuses collapsed that realm's entire allowlist to deny-all. The module's own comment names the
consequence precisely:

> The result was the worst shape a security control can take: no boot failure, no log, no signal
> of any kind, and every Verifiable Presentation to that realm rejected — indistinguishable, by
> design, from an untrusted issuer.

So the check runs the runtime's own reduction at startup — the same function, not a second
implementation that could drift. It is **not** gated on `WALLET_FEDERATION_ENABLED`: a typo is a
typo whether or not those flows are on today. An absent or empty map is not a fault; it means no
realm trusts any issuer, which is the intended fail-closed default, and it starts.

### `createConfiguredProviders` — refuses the boot, but only when the flag is on

`createConfiguredProviders`, `apps/auth-server/src/app/app.ts:125`, implemented at
`libs/fastify/plugins/federation/src/lib/configured-providers.ts:302`, is a **pure function of
config** — no I/O, no Fastify, no database — that returns the provider list the registry is seeded
with. `PasswordProvider` is unconditional
(`libs/fastify/plugins/federation/src/lib/configured-providers.ts:305`). Everything else is gated.

With `WALLET_FEDERATION_ENABLED` at its default of `false`, this function **cannot throw** — the
entire gate sits inside `if (options.walletFederationEnabled === true)` at
`libs/fastify/plugins/federation/src/lib/configured-providers.ts:317`. (Strict `=== true`, not
truthiness, because the string `'false'` — what an unparsed `process.env` value would hand it — is
truthy in JavaScript.) When the flag _is_ on, three questions must all be answered before a wallet
provider may exist:

1. **Is a `VerifierProfile` selected?** `resolveVerifierProfile` returns `undefined` when none
   usable is. The refusal that follows is built by probing every shipped profile with the real
   guards rather than describing them in prose, so the values it advertises as settable are
   exactly the ones that would actually start in this deployment.
2. **Is that profile's verifier identity provisionable here?** The same `resolveVerifierProfile`
   call throws for this case; the assertion is folded into the resolver, so there is no path that
   obtains a profile without it having been checked.
3. **Can this deployment's crypto layer honour the profile's mandates?** —
   `libs/fastify/plugins/federation/src/lib/configured-providers.ts:169`, the only one the
   resolver cannot make, because it is a property of this build rather than of the profile.

No profile is named in that third check by design: adding one must mean editing the profile table
and nothing else.

### `deriveCryptoCapabilities` — a descriptor, not an assertion

This is the subtle one, and the most common place to get the mental model wrong.

`CRYPTO_CAPABILITIES` is a module-level constant at `apps/auth-server/src/app/app.ts:48`, computed
when `app.ts` is first imported, before `app()` runs. `deriveCryptoCapabilities`,
`apps/auth-server/src/app/crypto-capabilities.ts:61`, **never throws**. It answers a question; the
answer is then read by the gate in step 3 above. Calling it a boot assertion is shorthand — the
refusal lives in `configured-providers.ts`, and this function is what makes that refusal correct.

The question it answers is deliberately narrower than the obvious one. From the module's own
JSDoc:

> - `@qauth-labs/core-crypto` EXPORTING an algorithm means the code to compute it exists.
> - This deployment being able to SIGN WITH it means a key for it has been provisioned and there
>   is a code path that uses it.

`deriveCryptoCapabilities` answers the second. Concretely, at `HEAD`:

| Entry                | Value   | Why                                                                                                                                                                                                                      |
| -------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `EdDSA`              | `true`  | The env schema requires an EdDSA key and refuses to parse without one, so any deployment reaching this function has one                                                                                                  |
| `RS256`              | derived | `true` only when a non-blank `JWT_RS256_PRIVATE_KEY` is configured — optional, and absent by default (`apps/auth-server/src/app/crypto-capabilities.ts:70`)                                                              |
| `ES256`              | `false` | The crypto layer _can_ compute an ES256 signature. What is missing is provisioning: no env var, no schema field, no JWKS entry, no code path (`apps/auth-server/src/app/crypto-capabilities.ts:79`)                      |
| `responseEncryption` | `false` | The JWE primitives exist and nothing in the workspace calls them — no `direct_post.jwt` response mode, no published encryption JWK, no intake route to decrypt at (`apps/auth-server/src/app/crypto-capabilities.ts:95`) |

Two `false` entries for algorithms the crypto library implements is the whole point. Deriving them
from "does the library export it" would lift the gate: a profile mandating ES256 would boot on a
deployment that cannot produce an ES256 signature, and the misconfiguration would surface as every
wallet rejecting every request in production — the worst possible place to find it.

**If you are the contributor who provisions P-256 key material**, the corresponding entry flips to
a real predicate over that configuration in the same change. The inner record is pinned with
`satisfies Record<JwsAlgorithm, boolean>` at
`apps/auth-server/src/app/crypto-capabilities.ts:80`, so widening the crypto layer's algorithm
union stops the literal compiling until the new algorithm is given an answer. The descriptor
cannot go stale by silence.

## Security invariant 1 — HTTP/1.1 only

`apps/auth-server/src/main.ts:23`, immediately above the `Fastify({...})` call:

> **SECURITY INVARIANT — HTTP/1.1 only.** Do NOT add `http2: true` (or `http2SessionTimeout`, or
> an HTTP/2 `serverFactory`) here without first clearing the `find-my-way` advisory. Fastify's
> router is `find-my-way`, and CVE-2026-47219 (DoS) is HTTP/2-specific; serving HTTP/1.1 is the
> only reason it is inert.

The mitigation is a property of the _protocol this process serves_, not of a version constraint or
a configuration flag — which is exactly why it is easy to undo. Enabling HTTP/2 on this instance
reactivates the advisory.

There is a second, independent line of defence: `pnpm-workspace.yaml:56` pins
`find-my-way: '>=9.7.0'` under `overrides`, and the comment there is explicit that this is "a
floor against a future http2 switch, not a live fix". So an HTTP/2 switch is safe only as long as
that floor — or a later fixed version — is what actually resolves. Verify with:

```bash
pnpm why find-my-way
```

A reverse proxy that terminates HTTP/2 in front of the server and forwards HTTP/1.1 does not
reactivate anything; the router only ever sees HTTP/1.1 requests. The invariant is about what this
process serves.

## Security invariant 2 — the global Zod validator compiler

`apps/auth-server/src/main.ts:41`, immediately above the two `set*Compiler` calls:

> **SECURITY INVARIANT — this global Zod validator compiler is load-bearing beyond typing.** It
> replaces Fastify's default `ajv` compiler for _every_ route, and `ajv` is what pulls `fast-uri`,
> which carries two unfixed-in-tree host-confusion advisories (CVE-2026-13676, CVE-2026-16221).
> Because no request is ever parsed by ajv, those advisories are inert.

State the mitigation carefully, because its shape is what tells you how to avoid breaking it. The
defence is **not** that `fast-uri` has been removed from the dependency tree — it is still there,
reachable through `ajv`. The defence is that **no request is ever parsed by ajv**, so no
attacker-controlled string reaches `fast-uri`'s URI parser. That property holds because the
compiler is set once, on the root instance, and inherited by every route below it.

Three ways to break it, all named in the comment:

- **Removing the line.** Every route falls back to ajv.
- **Scoping it to a subset of routes** — for example calling `setValidatorCompiler` on a child
  instance instead of the root, leaving sibling contexts on the default.
- **Adding a route that opts back into ajv validation**, e.g. a raw JSON Schema `schema` on an
  instance without this compiler.

Each silently reactivates host confusion inside an OAuth server. Nothing fails; nothing logs.

**The version floors exist so this is not the only mitigation.** `pnpm-workspace.yaml:53` pins
`fast-uri: '>=3.1.4 <4'`, and its comment says so directly — the advisories are

> Inert today — main.ts sets a global Zod validator compiler so ajv never parses a request, and
> redirect_uri matching is an exact string comparison with no URI parser in the decision — but
> floored so that stops being load-bearing.

The upper bound is deliberate: a bare `>=3.1.4` resolves to 4.x, turning a security floor into an
unreviewed major bump. Treat the floor as defence in depth, not as permission to remove the
compiler.

`apps/auth-server/src/main.ts:50` names **the second leg of the same invariant**, and it lives
somewhere a contributor would not think to look: `redirect_uri` matching is an exact string
comparison (`client.redirectUris.includes(...)`, per RFC 9700) with **no URI parser in the
security decision** — see `apps/auth-server/src/app/helpers/oauth-redirect.ts`. Introducing a
parse-then-compare there would put a URI parser back into the one decision the invariant protects,
even with the Zod compiler intact.

## Before you change the bootstrap

- **Adding a plugin routes depend on:** register it before step 15, `await` it, and if the
  dependency is hard, declare it with `dependencies:` in the plugin's `fastify-plugin` options
  rather than relying on line order.
- **Adding a plugin whose position genuinely does not matter:** drop it in
  `apps/auth-server/src/app/plugins/` and let the first `AutoLoad` sweep pick it up.
- **Adding a route:** nothing in `app.ts` changes. The directory determines the prefix.
- **Adding a credential provider:** nothing in `app.ts` changes either — see
  [Adding a credential provider](/extend/adding-a-credential-provider/).
- **Moving anything:** check the binding-time table above first. Two of this file's comments claim
  an ordering requirement Fastify does not enforce, and the one plugin with a real, undocumented
  requirement (`rateLimitPlugin`) fails silently.
- **Touching `main.ts`:** re-read both `SECURITY INVARIANT` comments in full first. They are there
  because the code they protect looks removable.

## See also

- [Repository map](/extend/repo-map/) — where new code belongs, and the tag constraints that decide
  it.
- [Testing](/extend/testing/) — what each tier can and cannot catch, including why the route tests
  would not notice a bootstrap-ordering regression.
- [Adding a credential provider](/extend/adding-a-credential-provider/) — the ADR-003 extension
  point that `createConfiguredProviders` gates.
- [Frontmatter contract](/extend/frontmatter/) — the fields every page in this site sets.
- [Status](/reference/status/) — what has shipped and what is flag-gated, rendered from the single
  status source.
