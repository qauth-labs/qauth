---
title: Repository map
description: The apps/ and libs/ layout, the Nx scope tags and the module boundary constraints derived from them, where new code belongs, and the Windows CRLF gotcha that fails the format check on files you never touched.
sidebar:
  order: 3
lastVerified: '2026-10-25'
---

QAuth is an Nx monorepo with two trees: `apps/` for deployable entry points and `libs/` for
everything they compose. Which layer a new file belongs in is not a matter of taste here — it is
enforced by `@nx/enforce-module-boundaries` in `.oxlintrc.json`, which Oxlint runs through
@nx/oxlint's bridge, and getting it wrong surfaces as a lint error naming the tag you violated.

## `apps/`

| Directory               | Nx project         | What it is                                                                 |
| ----------------------- | ------------------ | -------------------------------------------------------------------------- |
| `apps/auth-server`      | `auth-server`      | The OAuth 2.1 / OIDC authorization server. Fastify.                        |
| `apps/developer-portal` | `developer-portal` | The client-management UI. TanStack Start + React.                          |
| `apps/docs-site`        | `docs-site`        | This site. Astro + Starlight, plus the drift-guard invariants.             |
| `apps/migration-runner` | `migration-runner` | The migration runner: one bundled Node program and the image that runs it. |
| `apps/wire-suite`       | `wire-suite`       | The black-box HTTP suite that tests a running server. Ships nothing.       |
| `apps/upgrade-test`     | `upgrade-test`     | The checks of the upgrade test, run against released and new servers.      |

The auth server, the portal and this site are tagged `scope:app` (e.g. `apps/auth-server/project.json:6`).
`apps/wire-suite` is tagged `scope:wire-suite` and `type:testing` instead, because it must import
**nothing** from the workspace — see [the wire suite](#the-wire-suite-imports-nothing) below.
`apps/upgrade-test` is tagged `scope:upgrade-test` and `type:testing` for the same reason: it drives
a released server and the new build from outside, over HTTP and `pg`, and imports no workspace
project (`.oxlintrc.json:298`, and `.oxlintrc.json:302` stops anything importing it).
Nothing in `apps/` may be imported by anything — the app layer is the top of the graph.

Some projects live outside both trees. One is `deploy/reference/proxy` (`reference-proxy`), the
reference reverse-proxy configuration and the container test that runs it in front of stub
upstreams. It is tagged `scope:reference-proxy` and `type:testing`, and imports no workspace
project (`.oxlintrc.json:318`).

Another is `graphs/` (`graphs`), with no tags: it holds the flow graphs of ADR-021 and no code, so
nothing can import it. Its one target, `graphs:check`, runs delurio's pinned checker over the
directory (`graphs/README.md`).

`apps/migration-runner` is tagged `scope:migration-runner`, and may depend only on the database
library (`type:db`) and, in its container suite, the testing library. Its build bundles
`src/main.ts`, `pg` and `drizzle-orm` into one file, `dist/apps/migration-runner/main.js`, beside a
copy of the migrations, which its image runs with Node alone. The logic itself, the lock, the
pending-migration rule and the boot check's wait, lives in `libs/infra/db/src/lib/migrations`,
which the package exports as `@qauth-labs/infra-db/migrations` so the bundle loads nothing else.

## `libs/`

Directory nesting under `libs/` is a readability convention. **The `scope:` tag in each
`project.json` is what the boundary rules actually read**, and the two do not always agree — see
[the crypto-native exception](#a-directory-is-not-a-tag) below.

| Directory                             | Package                                     | Tag                                    |
| ------------------------------------- | ------------------------------------------- | -------------------------------------- |
| `libs/core/crypto`                    | `@qauth-labs/core-crypto`                   | `scope:core`                           |
| `libs/core/crypto-native`             | `@qauth-labs/crypto-native`                 | `scope:server`                         |
| `libs/shared/errors`                  | `@qauth-labs/shared-errors`                 | `scope:shared`                         |
| `libs/shared/validation`              | `@qauth-labs/shared-validation`             | `scope:shared`                         |
| `libs/shared/testing`                 | `@qauth-labs/shared-testing`                | `scope:shared`                         |
| `libs/shared/test-vectors`            | `@qauth-labs/shared-test-vectors`           | `scope:shared`                         |
| `libs/shared/stability`               | `@qauth-labs/shared-stability`              | `scope:shared`                         |
| `libs/shared/interaction-contract`    | `@qauth-labs/shared-interaction-contract`   | `scope:shared`                         |
| `libs/shared/interaction-client`      | `@qauth-labs/shared-interaction-client`     | `scope:shared` + `type:sdk`            |
| `libs/ui`                             | `@qauth-labs/ui`                            | `scope:ui`                             |
| `libs/infra/db`                       | `@qauth-labs/infra-db`                      | `scope:infra`                          |
| `libs/infra/cache`                    | `@qauth-labs/infra-cache`                   | `scope:infra`                          |
| `libs/server/config`                  | `@qauth-labs/server-config`                 | `scope:server` + `scope:server-config` |
| `libs/server/federation`              | `@qauth-labs/server-federation`             | `scope:server`                         |
| `libs/server/jwt`                     | `@qauth-labs/server-jwt`                    | `scope:server`                         |
| `libs/server/keys`                    | `@qauth-labs/server-keys`                   | `scope:server` + `type:key-custody`    |
| `libs/server/password`                | `@qauth-labs/server-password`               | `scope:server`                         |
| `libs/server/pkce`                    | `@qauth-labs/server-pkce`                   | `scope:server`                         |
| `libs/server/dpop`                    | `@qauth-labs/server-dpop`                   | `scope:server`                         |
| `libs/server/realm-policy`            | `@qauth-labs/server-realm-policy`           | `scope:server`                         |
| `libs/server/egress`                  | `@qauth-labs/server-egress`                 | `scope:server`                         |
| `libs/server/email`                   | `@qauth-labs/server-email`                  | `scope:server`                         |
| `libs/server/step-grammar`            | `@qauth-labs/server-step-grammar`           | `scope:server`                         |
| `libs/server/sign-in-engine`          | `@qauth-labs/server-sign-in-engine`         | `scope:server`                         |
| `libs/fastify/plugins/db`             | `@qauth-labs/fastify-plugin-db`             | `scope:fastify`                        |
| `libs/fastify/plugins/cache`          | `@qauth-labs/fastify-plugin-cache`          | `scope:fastify`                        |
| `libs/fastify/plugins/jwt`            | `@qauth-labs/fastify-plugin-jwt`            | `scope:fastify`                        |
| `libs/fastify/plugins/password`       | `@qauth-labs/fastify-plugin-password`       | `scope:fastify`                        |
| `libs/fastify/plugins/pkce`           | `@qauth-labs/fastify-plugin-pkce`           | `scope:fastify`                        |
| `libs/fastify/plugins/email`          | `@qauth-labs/fastify-plugin-email`          | `scope:fastify`                        |
| `libs/fastify/plugins/federation`     | `@qauth-labs/fastify-plugin-federation`     | `scope:fastify`                        |
| `libs/fastify/plugins/signer`         | `@qauth-labs/fastify-plugin-signer`         | `scope:fastify`                        |
| `libs/fastify/plugins/dpop`           | `@qauth-labs/fastify-plugin-dpop`           | `scope:fastify`                        |
| `libs/fastify/plugins/egress`         | `@qauth-labs/fastify-plugin-egress`         | `scope:fastify`                        |
| `libs/fastify/plugins/sign-in-engine` | `@qauth-labs/fastify-plugin-sign-in-engine` | `scope:fastify`                        |
| `libs/sdk/resource-guard`             | `@qauth-labs/resource-guard`                | `scope:sdk` + `type:sdk`               |

## The layering

Every rule below is a `depConstraints` entry in `.oxlintrc.json:155`, and the comments there are
the source of record. `onlyDependOnLibsWithTags` lists what a project carrying that source tag may
import **from inside the workspace**; external npm packages are never restricted.

| Source tag               | May import (workspace)                                                           | In `.oxlintrc.json`  |
| ------------------------ | -------------------------------------------------------------------------------- | -------------------- |
| `scope:core`             | nothing — strict leaf                                                            | `.oxlintrc.json:170` |
| `scope:shared`           | nothing — strict leaf                                                            | `.oxlintrc.json:160` |
| `scope:ui`               | nothing — strict leaf                                                            | `.oxlintrc.json:177` |
| `scope:infra`            | `scope:core`, `scope:infra`, `scope:shared`                                      | `.oxlintrc.json:211` |
| `scope:server`           | `scope:core`, `scope:server`, `scope:shared`                                     | `.oxlintrc.json:219` |
| `scope:fastify`          | `scope:core`, `scope:fastify`, `scope:server`, `scope:infra`, `scope:shared`     | `.oxlintrc.json:227` |
| `scope:app`              | `scope:core`, `scope:fastify`, `scope:shared`, `scope:server-config`, `scope:ui` | `.oxlintrc.json:240` |
| `type:testing`           | see [the dead rule](#the-typetesting-rule-cannot-grant-anything)                 | `.oxlintrc.json:196` |
| `type:key-custody`       | `scope:core`, `scope:shared`                                                     | `.oxlintrc.json:274` |
| `scope:migration-runner` | `type:db`, `type:testing`                                                        | `.oxlintrc.json:255` |
| `scope:wire-suite`       | nothing — and nothing may import it                                              | `.oxlintrc.json:187` |
| `scope:upgrade-test`     | nothing — and nothing may import it                                              | `.oxlintrc.json:298` |
| `type:kek-adapter`       | `scope:core`, `scope:shared`, `type:key-custody` — and nothing may import it     | `.oxlintrc.json:284` |
| `scope:sdk`              | nothing — an SDK is installed outside the workspace                              | `.oxlintrc.json:309` |
| `scope:reference-proxy`  | nothing — it tests the shipped proxy configuration from outside                  | `.oxlintrc.json:318` |

### Key custody has a second, path-based rule

The `type:key-custody` row limits what `@qauth-labs/server-keys` imports. Who imports it is a
separate rule, because ADR-019 Decision 9 provisions the key-encryption key to the signer alone.
The package has two entry points: `@qauth-labs/server-keys`, with the `Signer` interface that any
project may use, and `@qauth-labs/server-keys/custody`, with the KEK provider, envelope encryption,
the key factory and the in-process signer. Module boundaries work per project and cannot tell the
two apart, so a block in `.oxlintrc.json` (the key custody guard: `no-restricted-imports`, plus
`qauth/no-restricted-syntax` from `tools/oxlint/qauth-plugin.mjs` for `require()` and the other
forms an import rule does not see) refuses `/custody`, and any deep path into the package,
everywhere except `libs/server/keys`, the signer's wiring, `libs/fastify/plugins/signer`, and the
KEK adapter packages under `libs/keys/`, which implement its `KekProvider` and run in the signer's
process. Sign through `fastify.signer`; do not widen the list beyond a new KEK adapter.

A KEK adapter (`type:kek-adapter`) reaches only the key library and the core and shared layers, and
no project may depend on one: `KEK_PROVIDER=<name>` imports `@qauth-labs/keys-<name>` by name at run
time, so the auth server and its image ship without it.

### Outbound calls go through the egress client

Server code makes its outbound HTTP calls through the SSRF-safe egress client (`fastify.egress`,
ADR-019 Decision 8), which checks every destination. A block in `.oxlintrc.json` (the egress guard,
`qauth/no-direct-network` from `tools/oxlint/qauth-plugin.mjs`) refuses the global `fetch` and
`request`/`get` of `node:http` and `node:https` in the auth server, the migration runner and the
core, shared, infra, server and fastify libraries. Its exceptions are `libs/server/egress` itself,
tests and their fixtures, and the wallet status-list fetcher, which has not moved yet; the KMS
adapters under `libs/keys/` are outside it.

### Why `scope:core` and `scope:shared` are strict leaves

Both are declared `onlyDependOnLibsWithTags: []`, and the comment at `.oxlintrc.json:164`
explains `scope:core`:

> Core libraries provide low-level, framework-agnostic primitives (crypto, encoding). Like the
> shared layer, they depend on nothing internal (leaf) and are consumable by every layer above
> (infra, server, fastify, app). Kept a strict leaf on purpose: a crypto primitive must not reach
> up into domain/error libs.

That last sentence is the design. A signing primitive that imported `@qauth-labs/shared-errors`
would make the crypto layer's behaviour depend on the domain error taxonomy, which is exactly
backwards — and once the cycle exists, "which layer owns this?" stops having an answer. The same
argument applies to `scope:shared` (pure utilities, errors, common types) and `scope:ui` (React
components).

The practical effect: if you find yourself wanting to import something into `libs/core/crypto` or
`libs/shared/*`, the answer is almost always to invert the dependency — take the value as a
parameter, or return data the caller interprets — rather than to loosen the tag. `libs/core/crypto`
and every `libs/shared/*` library import **no** workspace package today; keep it that way.

Note one sharp edge in how Nx implements an empty list: it reports a violation only when the
imported project **has at least one tag**. A brand-new lib whose `project.json` you forgot to tag
would therefore slip past every leaf constraint. Tag every new lib as the first thing you do.

### The consequence you will actually hit: `scope:app` cannot import `scope:server`

`scope:app`'s allowlist (`.oxlintrc.json:240`) contains `scope:fastify` but **not**
`scope:server`. So `apps/auth-server` cannot import `@qauth-labs/server-federation`,
`@qauth-labs/server-jwt`, or any other `libs/server/*` package directly, even though it is
obviously the consumer of all of them. The only sanctioned route is through the matching
`scope:fastify` plugin.

That is why `libs/fastify/plugins/federation/src/index.ts` is, in large part, a **re-export shim**
rather than only a plugin. Its own comment at `libs/fastify/plugins/federation/src/index.ts:5`
says so:

> Re-exported provider surface: app code (scope:app) may only depend on fastify plugins
> (scope:fastify), never on server libs directly — routes and bootstrap reach the ADR-003 provider
> API through here.

Three things worth understanding about that file before you add to it:

- **The re-export list is a deliberate allowlist, not a convenience.** The comment at
  `libs/fastify/plugins/federation/src/index.ts:16` calls out the asymmetry: `createPasswordProvider`
  is re-exported and `createWalletProvider` is not, so no bootstrap can put a wallet provider in
  the registry while bypassing `WALLET_FEDERATION_ENABLED`. Adding an export here can remove a
  security control. Read the comment above the line you are adding to.
- **Boot-time checks get re-exported for the same reason.**
  `libs/fastify/plugins/federation/src/index.ts:28` re-exports `assertTrustedIssuersUsable`
  precisely because the bootstrap must call it and cannot import `scope:server` to reach it.
- **`server-config` is the one exception, and it is a second tag rather than a hole in the rule.**
  `libs/server/config/project.json:6` carries both `scope:server` and `scope:server-config`, and
  `scope:app`'s allowlist names the latter. Nx's check passes if the imported project has **any**
  of the allowed tags, so the extra tag is what makes `@qauth-labs/server-config` importable from
  an app while every other `libs/server/*` package stays out of reach.

The comment at `libs/fastify/plugins/federation/src/lib/configured-providers.ts:22` records a real
consequence of this arrangement: because `server-config` carries no dependency on `server-federation`
(config is the lowest server layer), the config schema's `OID4VP_VERIFIER_PROFILE` enum duplicates
the federation lib's `VerifierProfileId` union, and `apps/auth-server` is the only place in the
workspace that can see both — which is why the cross-lib pin between the two lists lives in the
app's env test. Verified: nothing under `libs/server/config/src` imports `server-federation`. All
15 references to it there are prose — 13 in comments, two in test description strings.

### A second tag can also narrow

`server-config`'s second tag widens who may import it. `type:key-custody` works the other way.
`libs/server/keys/project.json` carries it beside `scope:server`, and Nx applies every constraint
whose source tag a project carries, so both must pass. The library that opens stored keys may
therefore import only `scope:core` and `scope:shared` libraries, never another `scope:server` one
such as `server-config` (ADR-019 Decision 9). Its configuration keys are declared in
`server-config`'s `kekEnvSchema`, and the key library reads them from the environment itself.

### A directory is not a tag

`libs/core/crypto-native` sits under `libs/core/` and is tagged `scope:server`, not `scope:core`
(`libs/core/crypto-native/project.json:6`). Two consequences that surprise people:

- It is **not** a strict leaf, which is what lets it import `@qauth-labs/core-crypto` (a
  `scope:server` source may depend on `scope:core`).
- `apps/auth-server` **cannot** import it, because `scope:app` does not allow `scope:server`. The
  native backend is reached through `@qauth-labs/core-crypto`'s backend registry, not directly.

So do not infer a project's layer from its path. Read its `project.json`.

### The `type:testing` rule cannot grant anything

`.oxlintrc.json:196` declares that a `type:testing` project may depend on `scope:core`,
`scope:shared`, `scope:ui`, `scope:infra`, `scope:server` and `scope:fastify` — a deliberately
broad allowance, so test helpers can reach whatever they need to build fixtures.

It does not currently do that. Nx collects **every** `depConstraints` entry whose `sourceTag` the
source project carries and requires **all** of them to pass. Three projects carry `type:testing`,
and each pairs it with a strict leaf: `libs/shared/testing` (`libs/shared/testing/project.json:6`)
is also tagged `scope:shared`, `apps/wire-suite` is also tagged `scope:wire-suite`, and
`apps/upgrade-test` is also tagged `scope:upgrade-test`. The constraints intersect to "nothing", so
the broad allowance grants no import at all.

This is inert today because `libs/shared/testing` imports no workspace package. It stops being
inert the moment someone adds a fixture there that imports, say, `@qauth-labs/infra-db` — which
the `type:testing` rule appears to bless and lint will reject. If you hit that, the fix is a
decision about tags, not a cast or a disable comment; raise it rather than working around it.

### The wire suite imports nothing

`apps/wire-suite` tests a running server over HTTP (see [Testing](/extend/testing/)). It may use
`fetch`, `jose` and its own helpers, and no workspace project, because a helper shared with the
server could carry the same encoding bug on both sides and hide it. Two constraints hold that
down. `scope:wire-suite` depends on nothing (`.oxlintrc.json:187`). A second entry with
`sourceTag: '*'` and `notDependOnLibsWithTags: ['scope:wire-suite']` (`.oxlintrc.json:192`)
stops every project from importing the suite. The suite is an application, so Nx's "Imports of apps
are forbidden" check stops that too; the tag rule still holds if it ever becomes a library.

An import of `@qauth-labs/shared-errors` into the suite fails `nx lint` with:

```text
A project tagged with "scope:wire-suite" cannot depend on any libs with tags
```

A relative import of `apps/auth-server` source fails with:

```text
Projects cannot be imported by a relative or absolute path, and must begin with a npm scope
```

## Where new code belongs

| You are adding…                                      | Put it in                                           |
| ---------------------------------------------------- | --------------------------------------------------- |
| A pure crypto or encoding primitive                  | `libs/core/crypto` (no workspace imports allowed)   |
| An error class or a shared type                      | `libs/shared/errors` / `libs/shared/validation`     |
| Domain logic with no Fastify and no I/O              | `libs/server/<area>`                                |
| A database table, migration, or repository           | `libs/infra/db`                                     |
| The graph of a flow or a screen (ADR-021)            | `graphs/flows/<area>/<flow>/` (`graphs/README.md`)  |
| A shared test vector (ADR-018 §6)                    | `test-vectors/<area>/` (`test-vectors/README.md`)   |
| The Fastify wiring that exposes the above to the app | `libs/fastify/plugins/<area>`                       |
| An HTTP route                                        | `apps/auth-server/src/app/routes/<dir>`             |
| Configuration schema an app must read                | `libs/server/config` (already dual-tagged for this) |

Two rules of thumb that follow from the layering:

1. **If an app needs something from a `libs/server/*` lib, the answer is a `scope:fastify`
   re-export, not a tag change.** The plugin layer exists to be that seam.
2. **If a lib needs something from a layer above it, invert the dependency.** Pass it in. Every
   fail-closed check in this codebase is built that way — see
   [Request lifecycle](/extend/architecture/) for `createConfiguredProviders` taking a crypto
   capability descriptor rather than probing the crypto layer itself.

## Local development gotcha: CRLF on Windows

`.gitattributes` sets `* text=auto eol=lf` ([#363](https://github.com/qauth-labs/qauth/issues/363)),
so a fresh checkout has LF line endings in every text file, whatever `core.autocrlf` says. A clone
made before that rule landed can still hold CRLF copies of files it has not rewritten since, and
`git status` stays **clean** for them, because Git normalizes line endings on the way into the
index.

Oxfmt's config sets `endOfLine: "lf"` (`.oxfmtrc.json`), so the format check lists each of those
files as unformatted:

```console
$ pnpm format:check
Checking formatting...

apps/developer-portal/src/client.tsx (0ms)

Format issues found in above 1 files. Run without `--check` to fix.
```

The confusing part is the surrounding silence: the files look untouched, `nx lint` passes (Oxlint
does not check formatting), and CI stays green, because Linux runners check out LF.

**Do not fix this by running `pnpm format` across the tree.** That rewrites every affected file,
and the diff is invisible to you (`git status` clean) but not to reviewers. Check
`git config core.autocrlf` instead: if it is `true` and the checkout predates the rule, a fresh
clone has none of this.

## See also

- [Request lifecycle](/extend/architecture/) — how `apps/auth-server` composes the plugins above.
- [Frontmatter contract](/extend/frontmatter/) — required reading before adding a page to this
  site.
