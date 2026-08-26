---
title: Repository map
description: The apps/ and libs/ layout, the Nx scope tags and the eslint boundary constraints derived from them, where new code belongs, and the Windows CRLF gotcha that breaks nx lint on files you never touched.
sidebar:
  order: 3
lastVerified: '2026-08-10'
---

QAuth is an Nx monorepo with two trees: `apps/` for deployable entry points and `libs/` for
everything they compose. Which layer a new file belongs in is not a matter of taste here — it is
enforced by `@nx/enforce-module-boundaries` in `eslint.config.mjs`, and getting it wrong surfaces
as a lint error naming the tag you violated.

## `apps/`

| Directory               | Nx project         | What it is                                                                      |
| ----------------------- | ------------------ | ------------------------------------------------------------------------------- |
| `apps/auth-server`      | `auth-server`      | The OAuth 2.1 / OIDC authorization server. Fastify.                             |
| `apps/developer-portal` | `developer-portal` | The client-management UI. TanStack Start + React.                               |
| `apps/docs-site`        | `docs-site`        | This site. Astro + Starlight, plus the drift-guard invariants.                  |
| `apps/migration-runner` | —                  | Not an Nx project: a `Dockerfile` and an entrypoint script that run migrations. |

All three real apps are tagged `scope:app` (e.g. `apps/auth-server/project.json:6`). Nothing in
`apps/` may be imported by anything — the app layer is the top of the graph.

`apps/migration-runner` has no `project.json` and no `package.json`, so `nx show projects` does not
list it. It is deliberately just a container image; if you are looking for the migration logic
itself it lives in `libs/infra/db`.

## `libs/`

Directory nesting under `libs/` is a readability convention. **The `scope:` tag in each
`project.json` is what the boundary rules actually read**, and the two do not always agree — see
[the crypto-native exception](#a-directory-is-not-a-tag) below.

| Directory                         | Package                                 | Tag                                    |
| --------------------------------- | --------------------------------------- | -------------------------------------- |
| `libs/core/crypto`                | `@qauth-labs/core-crypto`               | `scope:core`                           |
| `libs/core/crypto-native`         | `@qauth-labs/crypto-native`             | `scope:server`                         |
| `libs/shared/errors`              | `@qauth-labs/shared-errors`             | `scope:shared`                         |
| `libs/shared/validation`          | `@qauth-labs/shared-validation`         | `scope:shared`                         |
| `libs/shared/testing`             | `@qauth-labs/shared-testing`            | `scope:shared`                         |
| `libs/ui`                         | `@qauth-labs/ui`                        | `scope:ui`                             |
| `libs/infra/db`                   | `@qauth-labs/infra-db`                  | `scope:infra`                          |
| `libs/infra/cache`                | `@qauth-labs/infra-cache`               | `scope:infra`                          |
| `libs/server/config`              | `@qauth-labs/server-config`             | `scope:server` + `scope:server-config` |
| `libs/server/federation`          | `@qauth-labs/server-federation`         | `scope:server`                         |
| `libs/server/jwt`                 | `@qauth-labs/server-jwt`                | `scope:server`                         |
| `libs/server/password`            | `@qauth-labs/server-password`           | `scope:server`                         |
| `libs/server/pkce`                | `@qauth-labs/server-pkce`               | `scope:server`                         |
| `libs/server/email`               | `@qauth-labs/server-email`              | `scope:server`                         |
| `libs/fastify/plugins/db`         | `@qauth-labs/fastify-plugin-db`         | `scope:fastify`                        |
| `libs/fastify/plugins/cache`      | `@qauth-labs/fastify-plugin-cache`      | `scope:fastify`                        |
| `libs/fastify/plugins/jwt`        | `@qauth-labs/fastify-plugin-jwt`        | `scope:fastify`                        |
| `libs/fastify/plugins/password`   | `@qauth-labs/fastify-plugin-password`   | `scope:fastify`                        |
| `libs/fastify/plugins/pkce`       | `@qauth-labs/fastify-plugin-pkce`       | `scope:fastify`                        |
| `libs/fastify/plugins/email`      | `@qauth-labs/fastify-plugin-email`      | `scope:fastify`                        |
| `libs/fastify/plugins/federation` | `@qauth-labs/fastify-plugin-federation` | `scope:fastify`                        |
| `libs/fastify/plugins/mcp-guard`  | `@qauth-labs/mcp-guard`                 | `scope:fastify`                        |

## The layering

Every rule below is a `depConstraints` entry in `eslint.config.mjs:117`, and the comments there are
the source of record. `onlyDependOnLibsWithTags` lists what a project carrying that source tag may
import **from inside the workspace**; external npm packages are never restricted.

| Source tag      | May import (workspace)                                                           | In `eslint.config.mjs`  |
| --------------- | -------------------------------------------------------------------------------- | ----------------------- |
| `scope:core`    | nothing — strict leaf                                                            | `eslint.config.mjs:132` |
| `scope:shared`  | nothing — strict leaf                                                            | `eslint.config.mjs:122` |
| `scope:ui`      | nothing — strict leaf                                                            | `eslint.config.mjs:139` |
| `scope:infra`   | `scope:core`, `scope:infra`, `scope:shared`                                      | `eslint.config.mjs:158` |
| `scope:server`  | `scope:core`, `scope:server`, `scope:shared`                                     | `eslint.config.mjs:166` |
| `scope:fastify` | `scope:core`, `scope:fastify`, `scope:server`, `scope:infra`, `scope:shared`     | `eslint.config.mjs:174` |
| `scope:app`     | `scope:core`, `scope:fastify`, `scope:shared`, `scope:server-config`, `scope:ui` | `eslint.config.mjs:187` |
| `type:testing`  | see [the dead rule](#the-typetesting-rule-cannot-grant-anything)                 | `eslint.config.mjs:143` |

### Why `scope:core` and `scope:shared` are strict leaves

Both are declared `onlyDependOnLibsWithTags: []`, and the comment at `eslint.config.mjs:126`
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
and all three `libs/shared/*` libraries import **no** workspace package today; keep it that way.

Note one sharp edge in how Nx implements an empty list: it reports a violation only when the
imported project **has at least one tag**. A brand-new lib whose `project.json` you forgot to tag
would therefore slip past every leaf constraint. Tag every new lib as the first thing you do.

### The consequence you will actually hit: `scope:app` cannot import `scope:server`

`scope:app`'s allowlist (`eslint.config.mjs:187`) contains `scope:fastify` but **not**
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

### A directory is not a tag

`libs/core/crypto-native` sits under `libs/core/` and is tagged `scope:server`, not `scope:core`
(`libs/core/crypto-native/project.json:6`). Two consequences that surprise people:

- It is **not** a strict leaf, which is what lets it import `@qauth-labs/core-crypto` (a
  `scope:server` source may depend on `scope:core`).
- `apps/auth-server` **cannot** import it, because `scope:app` does not allow `scope:server`. The
  native backend is reached through `@qauth-labs/core-crypto`'s backend registry, not directly.

So do not infer a project's layer from its path. Read its `project.json`.

### The `type:testing` rule cannot grant anything

`eslint.config.mjs:143` declares that a `type:testing` project may depend on `scope:core`,
`scope:shared`, `scope:ui`, `scope:infra`, `scope:server` and `scope:fastify` — a deliberately
broad allowance, so test helpers can reach whatever they need to build fixtures.

It does not currently do that. Nx collects **every** `depConstraints` entry whose `sourceTag` the
source project carries and requires **all** of them to pass. The only `type:testing` project is
`libs/shared/testing` (`libs/shared/testing/project.json:6`), which is also tagged `scope:shared`
— and `scope:shared` is the strict leaf above. The two constraints intersect to "nothing", so the
broad allowance grants no import at all.

This is inert today because `libs/shared/testing` imports no workspace package. It stops being
inert the moment someone adds a fixture there that imports, say, `@qauth-labs/infra-db` — which
the `type:testing` rule appears to bless and lint will reject. If you hit that, the fix is a
decision about tags, not a cast or an eslint-disable; raise it rather than working around it.

## Where new code belongs

| You are adding…                                      | Put it in                                           |
| ---------------------------------------------------- | --------------------------------------------------- |
| A pure crypto or encoding primitive                  | `libs/core/crypto` (no workspace imports allowed)   |
| An error class or a shared type                      | `libs/shared/errors` / `libs/shared/validation`     |
| Domain logic with no Fastify and no I/O              | `libs/server/<area>`                                |
| A database table, migration, or repository           | `libs/infra/db`                                     |
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

`.gitattributes` forces `eol=lf` **by enumerated extension** — `.sh`, `.bash`, `.js`, `.ts`,
`.json`, `.yml`, `.yaml`, `.md`, `.mdx`. Several extensions in the tree are not on that list:
`.tsx` (51 tracked files), `.mjs` (4), `.astro` (2) and `.css` (1).

On a Windows checkout with `core.autocrlf=true`, those files land on disk with CRLF line endings.
Prettier's config sets `endOfLine: "lf"` (`.prettierrc`) and `eslint.config.mjs:242` promotes
`prettier/prettier` to `error`, so:

```console
$ pnpm exec eslint apps/developer-portal/src/client.tsx
   1:60  error  Delete `␍`  prettier/prettier
   2:53  error  Delete `␍`  prettier/prettier
   ...
✖ 12 problems (12 errors, 0 warnings)
```

The confusing part is the surrounding silence. `git status` stays **clean**, because `autocrlf`
normalizes back to LF on the way into the index — so the files look untouched while `nx lint`
reports dozens of errors in code you never opened. CI stays green too: Linux runners check out LF.

**Do not fix this by running `--write` across the tree.** That rewrites every affected file, and
the diff is invisible to you (`git status` clean) but not to reviewers. Instead:

- Check what you are actually seeing with `git config core.autocrlf`. If it is `true`, this is
  what you have.
- Scope your lint runs to what you changed while you work.
- The underlying fix — extending `.gitattributes` to cover the remaining extensions and
  renormalizing — is tracked in
  [#363](https://github.com/qauth-labs/qauth/issues/363). That issue owns it; please do not fix it
  as a drive-by inside an unrelated change, because the renormalization commit touches every
  affected file and needs to land on its own.

`.mdx` was added to `.gitattributes` recently for exactly this reason, so the pattern is already
established — it just has not been finished.

## See also

- [Request lifecycle](/extend/architecture/) — how `apps/auth-server` composes the plugins above.
- [Frontmatter contract](/extend/frontmatter/) — required reading before adding a page to this
  site.
