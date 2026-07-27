# Documentation findings

Defects surfaced while building `docs.qauth.dev`, July 2026.

Seven issues, one of them a live security defect. None were found by looking for bugs — every
one surfaced because writing accurate documentation requires checking whether a claim is true,
and several long-standing claims were not.

---

## Summary

| #                                                      | Finding                                                                                          | Severity | Status                                                           |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------ | -------- | ---------------------------------------------------------------- |
| [#365](https://github.com/qauth-labs/qauth/issues/365) | The app-level error handler never runs for any route; a merged security control is inert         | **High** | Fixed on `fix/365-error-handler-unreachable`, verified, unmerged |
| [#366](https://github.com/qauth-labs/qauth/issues/366) | The portal's `/consents` page cannot work for a portal-authenticated user                        | High     | Filed                                                            |
| [#359](https://github.com/qauth-labs/qauth/issues/359) | `JWT_PUBLIC_KEY` documented as optional, but omitting it fails at boot                           | Medium   | Filed                                                            |
| [#362](https://github.com/qauth-labs/qauth/issues/362) | No pinnable tag for the pre-0011 release, so the ADR-002 upgrade path cannot be followed         | Medium   | Filed                                                            |
| [#363](https://github.com/qauth-labs/qauth/issues/363) | `.gitattributes` omissions make `nx lint` fail locally on Windows with unexplainable CRLF errors | Medium   | Filed (`.mdx` half fixed on the docs branch)                     |
| [#364](https://github.com/qauth-labs/qauth/issues/364) | The "`openssl genrsa` emits PKCS#1" pitfall has been stale since OpenSSL 3.0                     | Low      | Filed                                                            |
| [#361](https://github.com/qauth-labs/qauth/issues/361) | Nx discovers every project twice while a worktree exists under `.claude/`                        | Low      | Filed (resolved in practice by removing the worktree)            |

---

## #365 — The error handler has never run

**The defect.** `apps/auth-server/src/app/app.ts` registered the custom error handler _after_
the two `@fastify/autoload` calls, commented _"Register error handler last to catch all
unhandled errors"_. Fastify does not work that way: a route's context captures its error handler
when the enclosing plugin finishes loading — `fastify/lib/route.js:375-379` assigns
`context.errorHandler` inside a `this.after(...)` callback as a **snapshot**, not a live lookup.
A handler registered afterwards reaches no route. `plugins/error-handler.ts` was dead code in
production.

**Confirmed three ways** by booting the real application:

- `POST /oauth/token` with an invalid body returned `FST_ERR_VALIDATION` instead of the app's shape.
- `GET /oauth/userinfo` without a token returned 401 with **no `WWW-Authenticate` header** — an RFC 6750 §3 violation.
- Against a live database, a duplicate `POST /auth/register` returned:

```json
{
  "statusCode": 409,
  "code": "UNIQUE_CONSTRAINT_VIOLATION",
  "error": "Conflict",
  "message": "Unique constraint violated: idx_user_credentials_realm_provider_sub_unique"
}
```

That last one is the important one. `error-handler.ts:154-171` exists specifically to suppress
it — security finding **F-01**, fixed and merged in **PR #212**. Its own comment reads:

> The offending constraint name is an account-enumeration oracle … so it is logged for operators
> but NEVER returned to the caller.

The control shipped, was reviewed, was merged, and did nothing.

**Scope note, for accuracy:** the `409` status is deliberate and preserved by design — the same
comment keeps `code` and `statusCode` "so legitimate clients can still branch on the conflict".
The defect is narrower than "enumeration is wide open": what leaks is the internal index name.

**Why nothing caught it.** Every existing test either stubs Fastify or exercises the handler in
isolation. `error-handler.test.ts` passes today and would have passed throughout the entire
period the bug was live. 768 tests, a code-traced security review, and a merge — none of them
asked whether the handler was _reachable_.

**Fix.** Registration moved above the AutoLoad calls, plus
`apps/auth-server/src/app/error-handler.wiring.test.ts` — a test that boots the assembled app
and is mutation-checked: all three assertions fail if the registration moves back. 768 → 771
tests. Reviewed and confirmed at Fastify's source level.

---

## #366 — The portal's consents page cannot work

`consents.tsx` is the only page in the portal that calls the auth-server directly from the
browser rather than through a server function. Three independent blockers, each fatal alone:

1. **Wrong cookie.** It depends on `__Host-qauth_session`, set only by the auth-server's own
   hosted UI. Portal login sets `__Host-qauth_portal_session`.
2. **`SameSite=Lax`.** Even with the cookie present, `Lax` is not sent on cross-site `fetch()`
   subresource requests. The file's comment says `credentials: 'include'` is there so the cookie
   is sent cross-origin; that is not what `Lax` does.
3. **CORS.** Production resolves `origin: false` unless `CORS_ORIGIN` is set explicitly.

**Why nothing caught it.** It is the only route in the portal without a colocated test, and it
sits outside the `_authed` layout unlinked from the dashboard — so no test exercised it and no
navigation reached it. PR #332 corrected its route path at some point, which suggests the wiring
got attention without the page ever being driven end to end.

---

## #359 — Documented key derivation that fails at boot

`.env.example:191-213` and the OIDF certification runbook both tell operators `JWT_PUBLIC_KEY`
is optional and "can be derived from private key". Omitting it throws at boot.

`fastify-plugin-jwt.ts:88` derives the public half with jose's `exportSPKI` on a private key.
`libs/server/jwt/src/lib/key-management.ts:91-95` already documents why that cannot work —
jose 6 imports private keys as non-extractable — and provides `derivePublicKeyPemFromPrivate`,
which is wired only into the RS256 path. The correct helper sits beside the broken call.

An operator following the documented configuration gets a server that will not start, and a
`catch` block relabels it as their configuration error.

---

## #362 — An unpinnable upgrade path

The ADR-002 migration requires a two-hop deploy: install the release containing
`db:backfill-identity`, run the backfill, then upgrade. The only tag in the repository is
`v0.1.0-rc.0`, which **postdates** migration 0011 — so the intermediate hop has nothing to name.

This is the worst possible place for that gap. Migration 0011 drops `users.email`,
`users.email_normalized` and `users.password_hash`; there is no rollback, because password
hashes are unrecoverable by design. And the step the intermediate release exists to enable
fails **silently**: skipping the backfill strips `email`/`email_verified` claims from existing
users — including users whose email was verified — with no error and no failed migration.

The runbook documents a commit range and states the limitation, which is the honest option
available to it.

---

## #363 — Local lint failures with no visible cause

`.gitattributes` enumerates eight extensions for `eol=lf` and misses `.tsx`, `.mjs`, `.astro`,
`.css` and `.mdx`. With `core.autocrlf=true` those check out CRLF while their committed blobs
are LF, so `prettier/prettier` reports dozens of `Delete ␍` errors in files the contributor
never touched — while `git status` stays clean and CI (Linux) stays green.

A red local lint, a green pipeline, and no diff to explain either is close to the least
actionable failure shape there is.

Worth recording _how_ this was found: the CRLF failures were observed early and correctly ruled
out as "pre-existing and environmental" — twice, by two different tasks. Both descriptions were
locally reasonable and both were wrong; the `.mdx` files were created _on this branch_. A defect
can survive an arbitrarily long chain of individually-correct scope decisions, and "pre-existing"
is a phrase that stops enquiry.

---

## #364 — A pitfall that stopped being true three majors ago

`docs/oidf-op-certification-runbook.md:44` and `.env.example` both warn that `openssl genrsa`
emits PKCS#1, which QAuth's `importPKCS8` rejects. Since **OpenSSL 3.0**, `genrsa` defaults to
PKCS#8; `-traditional` is needed for the old format:

```
$ openssl version            → OpenSSL 3.5.6
$ openssl genrsa 2048 | head -1  → -----BEGIN PRIVATE KEY-----
```

The underlying requirement is still correct — private keys must be PKCS#8, and `openssl genpkey`
is still the right recommendation. Only the claim about `genrsa`'s default is stale.

This one is structurally interesting: a new `operate/keys.md` page inherited the error verbatim
from the runbook it was extracted from. **Migrating a document migrates its errors.** And no
automated guard could ever catch it — it is a claim about an external tool's behaviour, not
about this repository, so the documentation invariants have no visibility into it by
construction.

---

## #361 — Nx double-discovery under worktrees

Creating a git worktree at `.claude/worktrees/<name>/` puts a second copy of every project
_inside_ the repository, and Nx's project discovery walks into it — so `nx` commands from the
main checkout fail with duplicate-project errors until the worktree is removed.

The repo already handles the same root cause for Vitest (`vitest.config.ts` excludes
`**/.claude/**`, with a comment explaining exactly this). Nx needs the equivalent via
`.nxignore`.

---

## Two claims that did not survive checking

Not filed as issues; both are code comments asserting more than the code provides. Recorded here
because the reasoning matters more than the instances.

**Hook-ordering comments in `app.ts`.** Several plugins carry "register before routes" comments
implying Fastify enforces an ordering it does not. `onRequest`/`onSend` hooks added to a parent
context _after_ a child plugin was registered still run for that child's routes — the AutoLoad
calls are not awaited, so their children are created later via avvio's queue and receive the
sliced hook arrays. What actually binds is those plugins' order relative to _each other_:
`security-headers.ts:159` must overwrite helmet's CSP in `onSend`.

**The rate-limit ordering, which genuinely is load-bearing and said nothing at all.**
`@fastify/rate-limit` does all its work in a single `onRoute` hook, and `onRoute` is never
replayed over routes that already exist. Registering it below the AutoLoad calls would silently
disable **every** limit in the application — the global one as well as every per-route cap,
including `/auth/login`'s. No error, no warning, an unthrottled auth server. That constraint now
carries a comment.

The asymmetry is the point: the orderings that were documented as critical mostly were not, and
the one that actually was critical was undocumented.

---

## What this suggests

**The tests were honest and the suite was green.** Nothing here was caused by carelessness or by
a missing test that someone declined to write. `error-handler.test.ts` correctly tests the error
handler. The route tests correctly test route handlers. Each is a good test of the thing it
tests. The gap was that nothing tested whether the pieces were _connected_ — and a test suite
made entirely of correct unit tests can be uniformly green while the assembled application is
broken.

**Documentation is an unusually good defect detector, and not for the reason usually claimed.**
It is not that writing things down reveals confusion. It is that explaining _why_ a constraint
exists forces someone to check whether it does — and a codebase accumulates comments asserting
protections nobody has re-verified since they were written. Four of these seven findings came
from an agent being asked to explain a mechanism and checking it first.

**Automated guards protect a narrower surface than they appear to.** The four drift guards built
alongside these docs check links, `path:line` anchors, endpoint coverage and status claims. They
are worth having. But they verify that documentation matches _the repository_ — they have no
opinion on whether the repository matches reality, and #364 shows they cannot by construction.
Every guard was green throughout.

**"Pre-existing" is not a diagnosis.** It is a decision to stop looking, and it was wrong twice
here about the same defect.
