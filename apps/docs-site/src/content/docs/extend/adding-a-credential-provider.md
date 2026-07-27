---
title: Adding a credential provider
description: The ADR-003 extension point — the CredentialProvider interface, the registry, and createConfiguredProviders as the single registration point, with PasswordProvider as the complete example and WalletProvider as the fail-closed one.
sidebar:
  order: 5
lastVerified: '2026-07-27'
---

A **credential provider** is how QAuth learns that a user is who they say they are. Password
today; a wallet-backed presentation and upstream OIDC federation are the next two. ADR-003's
promise is that adding one is a **registration**, not a change to the authentication engine — no
new branch in a route, no `if (providerType === …)` anywhere.

This page is the practical version of
[ADR-003](/docs/adr/003-credential-provider-interface.md). Read the ADR for the decision and its
alternatives; read this for what the code actually does at `HEAD`.

## The contract

`libs/server/federation/src/providers/credential-provider.interface.ts:63`:

```ts
export interface CredentialProvider {
  readonly type: string;
  verify(input: unknown): Promise<VerifiedIdentity>;
  extractAttributes(result: VerifiedIdentity): UserAttribute[];
}
```

Three members, and each carries more meaning than its signature suggests.

### `type`

The discriminator. It is simultaneously the registry key and the value written to
`user_credentials.provider_type`, so it is a **database value**, not just an in-process label.
Changing it after rows exist orphans them.

### `verify(input: unknown): Promise<VerifiedIdentity>`

Takes provider-specific input and returns a normalized identity
(`libs/server/federation/src/providers/credential-provider.interface.ts:26`):

| Field            | Meaning                                                                                                        |
| ---------------- | -------------------------------------------------------------------------------------------------------------- |
| `externalSub`    | The subject as the **upstream** knows it. Never used as the token `sub` — the engine maps it to `users.id`.    |
| `assuranceLevel` | `'low'` \| `'substantial'` \| `'high'`, aligned to eIDAS LoA / ISO 29115. Propagated downstream as OIDC `acr`. |
| `rawClaims`      | Whatever the provider observed, before normalization.                                                          |

`input` is typed `unknown` on purpose: each provider owns its own input schema and parses it
itself. `'low'` carries no `acr` claim per ADR-003.

Implementations **reject** on verification failure. Returning a placeholder is not an option —
see [fail closed](#the-fail-closed-pattern) below.

### `extractAttributes(result): UserAttribute[]`

Turns a successful verification into rows for `user_attributes`
(`libs/server/federation/src/providers/credential-provider.interface.ts:44`): a `source`, an
`attrKey`, an `attrValue`, a `verified` flag, and an optional `expiresAt`. `source` is what claim
resolution ranks by, so it decides which value wins when two providers assert the same attribute.

## The registry

`libs/server/federation/src/providers/provider-registry.ts:14` is a `type → provider` map with
three methods and two deliberate throws:

- `register()` throws `ProviderAlreadyRegisteredError` when a `type` is already taken
  (`libs/server/federation/src/providers/provider-registry.ts:51`). That is a fail-fast against
  provider-confusion shadowing: two providers sharing a `type` must not silently resolve to
  whichever registered last.
- `resolve()` throws `ProviderNotRegisteredError` for an unknown `type`
  (`libs/server/federation/src/providers/provider-registry.ts:58`).

Seeding is not a separate code path: `createProviderRegistry` loops the initial providers through
that same `register()` method
(`libs/server/federation/src/providers/provider-registry.ts:68`), so a duplicate in the configured
list fails the boot rather than being silently deduplicated.

`federationPlugin` builds the registry from its `providers` option
(`libs/fastify/plugins/federation/src/lib/federation-plugin.ts:37`) and decorates the instance with
it (`libs/fastify/plugins/federation/src/lib/federation-plugin.ts:39`), which is why routes can
write `fastify.providerRegistry.resolve('password')`.

## The single registration point

`createConfiguredProviders`
(`libs/fastify/plugins/federation/src/lib/configured-providers.ts:302`) is where "which upstreams
exist" is decided, and `apps/auth-server/src/app/app.ts:125` is the only place that calls it.

Two properties make it worth understanding before you extend it:

- **It is a pure function of config.** No I/O, no Fastify, no database. That is what makes the
  flag-to-registry contract unit-testable without booting the auth-server, which would need
  Postgres and Redis.
- **Its option fields are required, not optional.**
  `libs/fastify/plugins/federation/src/lib/configured-providers.ts:78` explains why: a bootstrap
  that gains a new upstream must make a deliberate decision about it rather than inheriting a
  default from the library, and **typecheck** — not code review — is what enforces that. The single
  exception is `provisionedVerifierMaterial`, and only because omitting it _is_ the fail-closed
  answer.

`PasswordProvider` is unconditional
(`libs/fastify/plugins/federation/src/lib/configured-providers.ts:305`) — the authentication method
every deployment depends on, never flag-gated. Everything after it sits behind a flag.

> **How strong is "single registration point"?** It is a convention held up by two things, not by
> the registry API. First, the export allowlist: `libs/fastify/plugins/federation/src/index.ts:16`
> notes that `createPasswordProvider` is re-exported and `createWalletProvider` deliberately is
> **not**, so no bootstrap can construct a wallet provider at all, let alone register one. Second,
> the layering — `apps/auth-server` is `scope:app` and cannot import `libs/server/federation`
> directly (see [Repository map](/extend/repo-map/)). But
> `libs/fastify/plugins/federation/src/types.ts:11` does document
> `fastify.providerRegistry.register()` as an imperative alternative, and that method is public on
> the decorator. Treat imperative registration as an escape hatch that bypasses the config gate,
> and prefer extending `createConfiguredProviders`.

## Why routes never change

The engine resolves a provider by `type` and delegates. Both production call sites look the same:

- **Login** — `apps/auth-server/src/app/helpers/credential-auth.ts:80` resolves the provider and
  `apps/auth-server/src/app/helpers/credential-auth.ts:81` calls `verify()`. It does not call
  `extractAttributes()`; login reads the attributes that already exist.
- **Registration** — `apps/auth-server/src/app/routes/auth/register.ts:74` resolves,
  `apps/auth-server/src/app/routes/auth/register.ts:75` verifies, and
  `apps/auth-server/src/app/routes/auth/register.ts:80` extracts the attributes, which are then
  upserted inside the same transaction as the user and credential rows
  (`apps/auth-server/src/app/routes/auth/register.ts:117`).

Neither site names a provider implementation. Both name a `type` constant. That is the whole
property: a new upstream adds a file and one line in `createConfiguredProviders`, and the routes
above are untouched.

## Worked example — `PasswordProvider`

`libs/server/federation/src/providers/password.provider.ts:93`. Stateless, dependency-free, safe
to construct once at bootstrap.

### The precondition that surprises everyone

**`verify()` does not check the password.** For `type='password'` the secret comparison happens in
the route layer — the caller must have already argon2-verified the presented plaintext against
`credential_data.password_hash` and may only call `verify()` after that succeeded. The module
JSDoc states it, and the input schema enforces it structurally: the contract is
`verify({ email, passwordHash, emailVerified })`
(`libs/server/federation/src/providers/password.provider.ts:51`), which **carries no plaintext at
all**, so there is nothing for the provider to compare even if it wanted to.

This is deliberate — it keeps `libs/server/federation` framework-free — and password is the one
type whose secret check already had a home in the route layer. A wallet or upstream-OIDC provider
verifies its own cryptography inside `verify()`.

If you are writing a caller: `apps/auth-server/src/app/helpers/credential-auth.ts` is the pattern
to copy. It parses `credential_data`, calls `verifyPassword`, and only then resolves the provider.

### What it actually does

```ts
// libs/server/federation/src/providers/password.provider.ts:107
async verify(input: unknown): Promise<VerifiedIdentity> {
  const parsed = passwordVerifyInputSchema.safeParse(input);
  // …
}
```

- **Parses its input strictly.** `.strict()`, because callers construct this object in-process — an
  unknown key is a programming error, not forward-compatible data. A shape violation throws a plain
  `Error`; it is an internal invariant breach and is never mapped to a wire error.
- **Normalizes `externalSub` itself**
  (`libs/server/federation/src/providers/password.provider.ts:118`). `normalizeEmail` is
  idempotent, which guarantees `externalSub === user_credentials.external_sub` regardless of caller
  discipline. Login asserts that equality and fails closed if it ever diverges.
- **Returns `assuranceLevel: 'low'`**
  (`libs/server/federation/src/providers/password.provider.ts:121`) — self-asserted email and
  password is the lowest eIDAS LoA, and `'low'` emits no `acr`.
- **`extractAttributes` throws rather than returning `[]`** when `rawClaims.email` is missing
  (`libs/server/federation/src/providers/password.provider.ts:132`). An empty array would be
  indistinguishable from a credential that legitimately carries no claims.

### Shape ownership

The module is the **single owner** of the `credential_data` JSONB shape for
`provider_type='password'`: `passwordCredentialDataSchema`
(`libs/server/federation/src/providers/password.provider.ts:66`) and
`buildPasswordCredentialData` (`libs/server/federation/src/providers/password.provider.ts:77`),
`{ password_hash, email_verified }` with snake_case keys. Nothing else may hand-roll that object —
a camelCase drift would pass every database constraint and strand every login. Note the asymmetry
with the input schema: this one is deliberately **not** `.strict()`, because later work may add
sibling keys and today's binary must keep parsing then.

If your provider stores anything in `credential_data`, give it the same treatment: one schema, one
constructor, both exported from the provider module.

## The fail-closed pattern

`WalletProvider` (`libs/server/federation/src/providers/wallet.provider.ts:158`) is registered and
**both of its methods throw unconditionally** —
`libs/server/federation/src/providers/wallet.provider.ts:172` and
`libs/server/federation/src/providers/wallet.provider.ts:189`. That is the point of it, and it is
the most useful thing on this page: **you can land a provider in that state on purpose.**

### Why a provider like this exists

Epic #231 splits wallet federation across issues that must be developable in parallel. ADR-003's
promise is that adding a provider is a registration rather than an engine change, so the file, the
`type` discriminator, and the registry entry are established up front and the follow-ups fill in
the two method bodies against a stable shell. The module deliberately contains no protocol logic.

### Why throwing is a security property, not laziness

`libs/server/federation/src/providers/wallet.provider.ts:30` states both halves:

> - A stub that resolved a placeholder `VerifiedIdentity` would be an authentication-bypass
>   primitive the moment `WALLET_FEDERATION_ENABLED` is flipped or a route wires up
>   `resolve('wallet')` — the auth engine upserts whatever `externalSub` it is handed and mints a
>   token for it, with no provider-specific second guess (that is exactly ADR-003's design).
> - A stub that returned `[]` from `extractAttributes()` would look identical to a working provider
>   handed a credential carrying no claims, silently dropping identity data instead of failing
>   loudly.

Both failure modes exist **because** the engine is provider-agnostic. The abstraction that makes
new providers cheap also means the engine will not second-guess a provider that lies to it. So the
provider is the only place that can fail closed, and a skeleton must.

The comment ends with an instruction worth repeating: do **not** soften these into no-ops or
placeholder returns to make a caller compile or a test go green.

### The error type is chosen, too

`walletSkeletonError` (`libs/server/federation/src/providers/wallet.provider.ts:145`) builds a
plain `Error`, not a `@qauth-labs/shared-errors` domain error. Domain errors carry
`statusCode`/`code` and are mapped onto the wire by the global error handler, which would frame
this as a reachable, client-facing outcome with a stable error contract. It is not one. Reaching it
means QAuth is mis-wired, and a generic 500 plus a server-side stack trace is the right signal —
minting a dedicated error class in the shared library would create permanent public wire surface
for a condition that must never occur, and would invite treating the condition as a normal
authentication outcome.

### Constants can be load-bearing

`WALLET_SOURCE` (`libs/server/federation/src/providers/wallet.provider.ts:125`) is `'wallet'`, and
its comment flags that `claims/attribute-trust.ts` ranks that literal above every other attribute
source. Changing the constant without changing `rankAttributeSource` would silently demote every
wallet-issued attribute to the bottom rank. `wallet.provider.test.ts` pins the pair — if you add a
provider whose `source` participates in trust ranking, pin yours the same way.

## Flag gating

`WALLET_FEDERATION_ENABLED` is declared at
`libs/server/config/src/lib/schemas/federation.ts:41` and **defaults to `false`**
(`libs/server/config/src/lib/schemas/federation.ts:43`). The schema's comment is explicit that
every capability flag in this workspace defaults off, so a deployment that never sets the variable
gets the behaviour it had before the capability existed.

Inside `createConfiguredProviders` the check is a strict `=== true`
(`libs/fastify/plugins/federation/src/lib/configured-providers.ts:317`), not truthiness — the
string `'false'`, which an unparsed `process.env` value would supply, is truthy in JavaScript. Copy
that pattern for any flag you add; the env schema returns a real boolean, so the strict comparison
only ever fires for a caller that bypassed it, and when one does the flag must read as off.

Turning the flag on is also gated on posture: see
[the fail-closed boot checks](/extend/architecture/#the-fail-closed-boot-checks).

## Adding one: the checklist

1. **Write the provider** in `libs/server/federation/src/providers/<name>.provider.ts`. Export a
   `create<Name>Provider()` factory, a `<NAME>_PROVIDER_TYPE` constant, and — if it writes
   `credential_data` — the schema and constructor for that shape. Keep it stateless and
   dependency-free so it is safe to construct at bootstrap.
2. **Own your input contract.** A Zod schema parsed inside `verify()`, `.strict()` if callers build
   the object in-process.
3. **Decide the assurance level**, and remember `'low'` suppresses `acr`.
4. **Export it from `libs/server/federation/src/index.ts`.**
5. **Re-export what the app genuinely needs** from
   `libs/fastify/plugins/federation/src/index.ts` — and no more. `apps/auth-server` cannot import
   `scope:server` libraries directly, so this file is the seam; the comment at
   `libs/fastify/plugins/federation/src/index.ts:16` is the precedent for leaving a factory out
   when the flag is what should decide.
6. **Add it to `createConfiguredProviders`**, behind a flag if it is incomplete or optional. Add
   the flag to `libs/server/config/src/lib/schemas/federation.ts` with a default of `false`.
7. **Write the unit tests next to the provider.** The registry contract, the fail-closed paths, and
   any constant that another module ranks or matches on.
8. **Change no routes.** If you find yourself editing a route to accommodate the provider, that is
   the signal that something belongs inside `verify()` or `extractAttributes()` instead.

It is entirely acceptable for step 1 to produce a provider whose methods throw. That is a shipped,
reviewed, registered shell that the protocol work fills in later — and it is safer than a partial
implementation, because a provider that fails closed cannot authenticate anyone by accident.

## A note on ADR-003's header

`docs/adr/003-credential-provider-interface.md` opens with a status note from 2026-06-24 saying the
design had no implementation and that federation was pushed to a later phase. **That note is
superseded** by the correction immediately below it (2026-07-21, #304): the interface and registry
shipped in PR #227, the engine calls `provider.verify()` in production, and a second provider has
since landed as a skeleton. Read the correction, not the note above it — and if you are checking
another ADR, look for the same pattern before trusting its header.

## See also

- [Request lifecycle](/extend/architecture/) — where `createConfiguredProviders` is called and what
  it refuses to boot on.
- [Repository map](/extend/repo-map/) — why the fastify plugin re-exports the provider surface.
- [Testing](/extend/testing/) — which tier would notice if you got this wrong.
