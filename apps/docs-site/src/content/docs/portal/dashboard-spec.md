---
title: Dashboard specification
description: The specification the developer dashboard is to be built from — four surfaces, two proposed endpoints, and the ordering constraints an implementer must respect.
sidebar:
  order: 3
lastVerified: '2026-07-27'
unbuiltClaims: true
---

Every other page in this documentation set describes what QAuth does. This one describes what the
developer dashboard **should** do. It exists so that the implementation phase is a matter of
writing code rather than making design decisions, and it is deliberately written before any of
that code exists.

Read [Portal guide](/portal/guide/) for the portal's session model and shipped flows, and
[Known gaps](/portal/known-gaps/) for the honest account of the dashboard as it stands. This page
does not repeat either; it builds on both.

## How to read this page

The single thing a reader must never have to work out is whether a paragraph describes today or
tomorrow. Two conventions carry that:

- A **Shipped** callout, or a `path:line` anchor in backticks, means the behaviour is in the tree
  at the `lastVerified` date above. Every such anchor was opened and read.
- A **Proposed** heading, or a sentence in the form "the dashboard **must**/**should**", describes
  work that does not exist. No proposed path in this page names a file that exists, and no
  proposed field is present in any shipped schema.

Where this page names a value — a page size, a cache TTL, a colour treatment, a route — that value
is a decision, not a suggestion. Changing one is fine; re-opening it because the page "left it
open" is not. The reasoning is given inline so a later change is made knowingly.

## Scope

Four surfaces, in the order an implementer should build them:

| #   | Surface                                 | Backend work required                                                         |
| --- | --------------------------------------- | ----------------------------------------------------------------------------- |
| A   | Surface what already ships              | None for API keys; **#366** for consents                                      |
| B   | Effective environment policy per client | Response widening (see [Surface B](#surface-b--effective-environment-policy)) |
| C   | Agent visibility                        | Response widening (see [Surface C](#surface-c--agent-visibility))             |
| D   | Activity feed and metrics tiles         | Two new endpoints and one index migration                                     |

### Non-goals, dated 2026-07-27

- **Wallet-federation provider configuration UI.** Deferred with the T4 platform track; wallet
  login cannot complete end to end today (`apps/docs-site/src/lib/status.ts:147`, the
  `WALLET_FEDERATION_ENABLED` row), so a configuration surface would configure something a
  developer cannot then use.
- **Realm administration.** No admin-panel application exists in the workspace. Realm-level
  controls (`max_environment_laxity`, `dynamic_registration_allowed_scopes`) are operator-set by
  design (`apps/auth-server/src/app/helpers/environment-policy.ts:22`), and putting them in a
  self-service developer portal would invert that.
- **An operator-tier audit view.** There is no operator role in the system. The redacted,
  client-scoped developer view specified in [Surface D](#surface-d--activity-feed-and-metrics-tiles)
  is the deliberate answer, not a placeholder for a fuller one.

## Information architecture

**Shipped.** `/dashboard` is a 48-line component under the `_authed` layout: a welcome heading and
two cards, one of which advertises API keys as unshipped
(`apps/developer-portal/src/routes/_authed/dashboard.tsx:42`). The authed layout renders a header
with the developer's email and a log-out button and no navigation at all
(`apps/developer-portal/src/routes/_authed.tsx:30`).

**Proposed.** The dashboard becomes a real landing page and gains three sibling destinations:

| Route        | Purpose                                          | Layout                                     |
| ------------ | ------------------------------------------------ | ------------------------------------------ |
| `/dashboard` | Overview counters, metric tiles, recent activity | `_authed` (unchanged)                      |
| `/clients`   | Client list                                      | `_authed` (unchanged, shipped)             |
| `/api-keys`  | API keys across every client the developer owns  | `_authed` (new)                            |
| `/activity`  | The full activity feed                           | `_authed` (new)                            |
| `/consents`  | Granted consents and revocation                  | `_authed` (**moved**; blocked on **#366**) |

The authed header gains a navigation row linking Dashboard, Clients, API keys, Activity and
Consents. It is one row of links, not a collapsible sidebar: five destinations do not justify a
navigation chrome the app does not otherwise have.

**Decision — `/consents` keeps its URL.** `_authed` is a pathless layout route
(`apps/developer-portal/src/routes/_authed.tsx:8`), so moving
`apps/developer-portal/src/routes/consents.tsx` to `routes/_authed/consents.tsx` puts it behind the
session gate without changing the URL a developer may have bookmarked. Do not rename it to
`/settings/consents` on the way past.

**Decision — the feed page is called "Activity", not "Audit".** The API resource genuinely is
`audit_logs` and the endpoint is named for it. The page is not, because "audit" promises a
complete record and this view is deliberately incomplete: it is scoped to one developer's clients,
it withholds end-user data, and it structurally cannot show rows that carry no client attribution
(see [what the feed cannot show](#what-the-feed-structurally-cannot-show)). Naming the page for the
table would be a promise the page does not keep.

### Dashboard layout order

Top to bottom: overview counters → metric tiles → the ten most recent activity rows → destination
cards. Numbers that answer "is anything wrong" come before the evidence, and the evidence before
the navigation. A developer who opens this page because something broke should not have to scroll
past a card grid to find out.

## Universal rendering rules

These apply to every counter, tile, card and feed on the dashboard, and exist because the most
likely way this dashboard misleads someone is by rendering a failure as a zero.

1. **Three states, always.** Loading renders a skeleton of the final shape. Error renders an inline
   "Couldn't load" with a retry control. Loaded renders the value. There is no fourth state.
2. **An error never renders as `0`, `—`, or an empty list.** A tile that shows `0` failed token
   exchanges when the query failed is worse than one that shows nothing, because it is believed.
3. **Empty is not zero.** A developer with no clients gets an empty state that links to
   `/clients/new`, not a row of zeros. A developer with clients but no events in the window gets
   "No events in the last 24 hours", not `0`.
4. **Timestamps render in the viewer's local time zone, with the UTC value in the element's
   `title` attribute.** Activity data gets compared against server logs; an unambiguous UTC
   reading has to be available without leaving the page.
5. **Operator-set values render as authoritative; self-asserted values render as claims.** See
   [Surface C](#surface-c--agent-visibility) for the concrete treatment. It is applied consistently
   across the dashboard, not only on the agent row.

## Surface A — surface what already ships

### A1. Overview counters

**Proposed.** Three counters at the top of `/dashboard`: clients in `development`, `staging` and
`production`, plus a total.

**Shipped foundation.** `GET /api/clients` already returns each client's **effective** environment
— the stricter of the client's own column and its realm's ceiling — resolved through
`resolveEnvironmentPolicy` (`apps/auth-server/src/app/routes/clients/index.ts:347`) and projected
by `toClientResponse` (`apps/auth-server/src/app/routes/clients/index.ts:95`).

**Decision — count in the browser from the existing list response, do not add a counts endpoint.**
The clients list is already fetched for `/clients`; a developer's client count is small; and a
server-side counting endpoint would need its own filtering and caching story for a number that is
`array.filter(...).length`. The honest limit: this is `O(clients)` in one response body, and
`GET /api/clients` has no pagination today (`apps/auth-server/src/app/routes/clients/index.ts:333`
lists every row for the developer). **If `GET /api/clients` ever gains pagination, these counters
must move server-side in the same change** — a paginated list would silently make them count only
the first page.

### A2. API keys promoted to a first-class destination

**Shipped.** Static developer API keys work end to end. The backend registers mint
(`apps/auth-server/src/app/routes/clients/api-keys.ts:103`), list
(`apps/auth-server/src/app/routes/clients/api-keys.ts:179`) and revoke
(`apps/auth-server/src/app/routes/clients/api-keys.ts:204`), and the portal has a full
create/list/revoke UI in
`apps/developer-portal/src/components/api-keys-section.tsx`, rendered inside the client-detail page
(`apps/developer-portal/src/routes/_authed/clients.$clientId.tsx:222`). The delivery record agrees:
`apps/docs-site/src/lib/status.ts:162` carries API keys as `shipped`. The dashboard card that says
otherwise (`apps/developer-portal/src/routes/_authed/dashboard.tsx:42`) is simply stale.

**Proposed.** A `/api-keys` page listing every key the developer holds, grouped by client, and a
dashboard card linking to it.

**Decision — the page fans out server-side over the developer's clients.** There is no cross-client
key-listing endpoint, and this specification does not add one: the fan-out is
`listClientsHandler` followed by one `GET /api/clients/{clientId}/api-keys` per client, all inside a
single TanStack Start server function, so the browser makes one round trip. This reuses the
existing per-client endpoint rather than adding a fourth way to ask about keys.

**Decision — every client gets a section, including clients that cannot mint keys.** Only a client
whose effective environment resolves to `development` may mint — the gate is
`assertStaticApiKeysAllowed`, called before any hashing work
(`apps/auth-server/src/app/routes/clients/api-keys.ts:138`). It is tempting to list only those
clients. Do not: a client whose environment was tightened after a key was issued still **holds**
that key, and hiding the section would strand a live credential with no revocation path in the UI.
The create form still renders only where `staticApiKeysAllowed` is true — that gate is already
implemented and documented in the component's own contract
(`apps/developer-portal/src/components/api-keys-section.tsx:31`) — and clients that cannot mint show
the existing `client_credentials` guidance instead.

**Decision — the embedded section on the client-detail page stays.** `/api-keys` is an additional
route into the same component, not a replacement. Removing the embedded section would break the
flow a developer already knows for the sake of tidiness.

#### The fan-out's failure and scale behaviour

A fan-out is n requests pretending to be one, and every one of them can fail independently. The
universal rendering rules are written for a single surface; here is how they apply to n:

- **Concurrent, bounded at 8 in flight.** Sequential would make page load linear in client count;
  unbounded would let one developer with many clients open a connection burst against the
  auth-server from a single page view.
- **Partial failure renders per section, never as a silent gap.** If k of n sub-requests fail, the
  n − k that succeeded render normally and each of the k renders its own inline "Couldn't load keys
  for this client" with a retry that re-issues **only** that sub-request. The page does not fail
  whole, and — per universal rule 2 — a failed section never renders as "no keys", which would read
  as "nothing to revoke here."
- **A page-level banner states the count** — "2 of 9 clients couldn't be loaded" — because a reader
  scanning for a key they know exists needs to know the list is incomplete without finding the one
  broken section.
- **A `401` from any sub-request is different in kind** and short-circuits: it means the portal
  session expired mid-fan-out, so the page routes to `/login` rather than rendering eight
  successes and one auth error.
- **Section order is the client list's own order**, so `/api-keys` and `/clients` agree; within a
  section, keys are newest-first with revoked keys last.

**The scale ceiling is real, not hypothetical.** `GET /api/clients` is unpaginated — it returns
every row for the developer (`apps/auth-server/src/app/routes/clients/index.ts:333`) — so n is
unbounded by anything except how many clients someone has made.

**Decision — the design inverts at 25 clients.** Above that, `/api-keys` stops fanning out, renders
a client picker plus one client's keys at a time, and the dashboard card links to the picker. 25 is
chosen as roughly three screens of sections and, at 8 concurrent, about three round-trip waves —
past that the page is neither fast nor readable and the fan-out has stopped paying for itself. An
implementer hitting this ceiling in practice should read it as the signal to build the cross-client
list endpoint this specification declined to add, not as a reason to raise the number.

### A3. Consents — linked, but only after #366

**Shipped.** `/consents` exists and is functional in the sense that its code paths are written, but
it cannot authenticate for a developer who signed in through this portal. Issue **#366** records
three independent blockers, each fatal on its own:

1. The page depends on `__Host-qauth_session`, the auth-server's hosted-UI cookie
   (`apps/auth-server/src/app/helpers/session-cookie.ts:18`). The portal sets
   `__Host-qauth_portal_session` instead (`apps/developer-portal/src/server/session-cookie.ts:5`)
   and never visits `/ui/login`, so the cookie the page needs is simply absent.
2. That cookie is issued `SameSite=Lax` (`apps/auth-server/src/app/helpers/session-cookie.ts:153`),
   which withholds it from cross-site `fetch()` subresource requests regardless of
   `credentials: 'include'`.
3. Production CORS is fail-closed: `origin` resolves to `false` unless an operator sets
   `CORS_ORIGIN` (`apps/auth-server/src/app/app.ts:255`).

The page is the only one in the portal that calls the auth-server directly from the browser
(`apps/developer-portal/src/routes/consents.tsx:45` for the list,
`apps/developer-portal/src/routes/consents.tsx:70` for revoke). See
[the portal guide](/portal/guide/#the-consents-page) for the full account.

**Hard prerequisite.** Moving the consent calls behind TanStack Start server functions — #366's
first task — is a **prerequisite for the dashboard's consents link, not a follow-up**. A dashboard
that links to a page which answers "Please sign in to manage authorized applications" to a
signed-in developer is worse than a dashboard that does not link it: it converts a page nobody
finds into a page everybody finds broken.

**Decision — no feature flag for the link.** The consents entry appears in the dashboard and the
authed header in the same pull request that lands #366's server-function migration, and not before.
A runtime flag for a two-line navigation change adds a configuration surface with no operational
benefit, and a flag that defaults off is a link nobody ever turns on.

**Proposed, as part of that same change.** The server functions must follow the shipped portal
pattern exactly: read the access token from the signed session cookie via a `readAccessToken`
equivalent (`apps/developer-portal/src/server/actions/clients.server.ts:19`), return the
`UNAUTHENTICATED` result when it is missing or expired
(`apps/developer-portal/src/server/actions/clients.ts:24`), and proxy with
`Authorization: Bearer <token>`.

**Two things #366 must solve that its task list does not name.** Both follow from the same fact —
the consents endpoints are built around a browser session, and a server function does not have one:

1. **Authentication.** They authenticate by **session cookie** and have no Bearer path at all
   (`apps/auth-server/src/app/routes/consents/index.ts:17`); the handlers resolve the caller through
   `resolveBrowserSession` (`apps/auth-server/src/app/routes/consents/index.ts:95`), which reads
   `__Host-qauth_session`. A portal server function holds a Bearer access token instead.
2. **CSRF.** `DELETE /consents/:id` requires the caller to echo an `X-CSRF-Token` header whose value
   is a per-session token minted (or reused) by the `GET` and stored on the browser session
   (`apps/auth-server/src/app/routes/consents/index.ts:63`, `ensureApiCsrfToken`), then compared
   with `csrfTokensEqual` on the delete
   (`apps/auth-server/src/app/routes/consents/index.ts:142`); the control and its timing-safe
   comparison are described in the module doc comment
   (`apps/auth-server/src/app/routes/consents/index.ts:30`). The token is anchored to an
   auth-server session that a Bearer-authenticated server function never establishes, so there is
   nothing to mint it against. **#366 must redesign this control, not merely relay the header.** The
   good news is that the control's own stated purpose — defending a cookie-authed, state-changing
   endpoint against cross-site and same-origin-XSS calls — largely evaporates once the caller is a
   server function presenting a Bearer token from an `HttpOnly` cookie the browser cannot read; but
   "largely" is doing work in that sentence and the decision belongs to #366 with security review,
   not to this page.

This specification records both as dependencies and pre-empts neither.

## Surface B — effective environment policy

**Shipped.** `apps/auth-server/src/app/helpers/environment-policy.ts` is the single authority.
`resolveEnvironmentPolicy` (`apps/auth-server/src/app/helpers/environment-policy.ts:236`) takes the
stricter of the client's declared environment and the realm ceiling — strictness ordering lives in
one map (`apps/auth-server/src/app/helpers/environment-policy.ts:46`) — and returns the frozen
profile from `ENVIRONMENT_PROFILES`
(`apps/auth-server/src/app/helpers/environment-policy.ts:158`). Both inputs fail safe to
`production`. See [Environment-Aware Authorization](/operate/environment-authorization/#the-profiles)
for the profile table itself.

**The rule the UI must obey: render the response, never re-derive the policy.** A UI that
reimplements strictness ordering will drift from what the server enforces, and the drift is
invisible until the moment it matters — a client shown as `development` while the server treats it
as `production`, or worse, the reverse.

### The gap this surface actually has

The brief for this work stated that Surface B needs no backend change because `GET /api/clients`
already returns the resolved policy. That is **half true, and the half that is false is
load-bearing.** The route resolves the full ten-field `EnvironmentPolicy`
(`apps/auth-server/src/app/helpers/environment-policy.ts:106`), but `toClientResponse` projects
exactly two of its fields — `environment` and `staticApiKeysAllowed`
(`apps/auth-server/src/app/routes/clients/index.ts:108`) — and `clientSchema` carries only those two
(`apps/auth-server/src/app/schemas/clients.ts:40` and
`apps/auth-server/src/app/schemas/clients.ts:48`). Token TTL tier, PKCE enforcement,
loopback-redirect tolerance, rate-limit tier, agent step-up and the T3 hardening bundle are all
resolved server-side and then dropped on the floor.

So the UI has two options, and only one of them is acceptable:

- Re-derive the other eight fields in the portal from `environment`, by copying the profile table.
  **Rejected.** This is precisely the drift the rule above forbids, and the portal cannot import the
  authority module — `apps/developer-portal` and `apps/auth-server` are separate Nx applications
  with no dependency between them.
- Widen the response so the server keeps saying what it decided. **Chosen.**

**Rejected alternative — move `environment-policy.ts` into a shared library** so both apps import
it. It is the cleaner long-term shape and it is not this change: relocating the single authority
for every policy checkpoint in the system is a refactor with its own blast radius, whereas widening
a response schema is additive and reversible. Record it as a future option, do not do it here.

### Proposed — widen `clientSchema` with the resolved policy

Add a nested `policy` object to `clientSchema`
(`apps/auth-server/src/app/schemas/clients.ts:20`) carrying every field of the resolved
`EnvironmentPolicy`, populated directly from the resolver's return value inside `toClientResponse`.
Concretely: `environment`, `staticApiKeysAllowed`, `localhostRedirectAllowed`, `pkceRequired`,
`accessTokenLifespanTier`, `refreshRotationRequired`, `rateLimitTier`, `openDynamicRegistration`,
`agentStepUpEnforced`, `t3SecurityEnforced`.

**Plus two fields that are not on `EnvironmentPolicy`,** for reasons given below:
`declaredEnvironment` (the raw column, see [the effective-environment note](#the-policy-cards-two-traps))
and `loopbackRedirectPermitted` (a server-computed answer, see the same section).

**Decision — the widening cascades to two response schemas, deliberately.**
`createClientResponseSchema` (`apps/auth-server/src/app/schemas/clients.ts:132`) and
`regenerateSecretResponseSchema` (`apps/auth-server/src/app/schemas/clients.ts:177`) both
`.extend()` `clientSchema`, so both grow the new fields automatically. That is correct rather than
accidental: both are served through `toClientResponse`
(`apps/auth-server/src/app/routes/clients/index.ts:479` and `:694`), so the data is already there
and a client created or rotated through those paths gets the same policy view as one fetched later.
Name them in the pull request anyway — a schema that changes by inheritance is the kind of thing a
reviewer should be told about rather than discover.

**Decision — keep the existing top-level `environment` and `staticApiKeysAllowed`, duplicated.**
The shipped portal reads `client.staticApiKeysAllowed` to gate the API-key create form
(`apps/developer-portal/src/components/api-keys-section.tsx:31`). Removing the top-level fields
would break it for no gain. The duplication is deliberate and should be commented as such at the
schema.

**Decision — `policy` is read-only and must not appear in `createClientRequestSchema` or
`updateClientRequestSchema`.** The update schema's field list is closed
(`apps/auth-server/src/app/schemas/clients.ts:149`) and the existing `environment` field's own
contract already states why it is response-only: a developer must not be able to self-relax their
security posture through the management API
(`apps/auth-server/src/app/schemas/clients.ts:36`). The same reasoning covers every field of
`policy`.

### Proposed — what the UI renders

On the client-detail page, a **Policy** card. On the client list card, a compact environment badge
only. The detail card shows the six consequences an operator actually cares about, each as a
labelled row with the value and a one-line explanation of what it means for this client:

| Row                    | Source                                            | Rendered as                                                                       |
| ---------------------- | ------------------------------------------------- | --------------------------------------------------------------------------------- |
| Access token lifetime  | `policy.accessTokenLifespanTier`                  | "Short" / "Long", with the tier name in the tooltip                               |
| PKCE                   | **Not a policy field — always "Required (S256)"** | See [the two traps](#the-policy-cards-two-traps) below                            |
| Loopback redirect URIs | `policy.loopbackRedirectPermitted` (new)          | "Permitted" / "Rejected"                                                          |
| Rate limit             | `policy.rateLimitTier`                            | "Strict" / "Lenient"                                                              |
| Agent step-up          | `policy.agentStepUpEnforced`                      | "Enforced" / "Not enforced"                                                       |
| T3 hardening bundle    | `policy.t3SecurityEnforced`                       | "Enforced" / "Relaxed", linking to [Browser security](/operate/browser-security/) |

### The Policy card's two traps

Two rows in that table do **not** come from the obviously-named policy field, and both would be
false security statements if they did. This section exists because the first draft of this
specification got both of them wrong — which is the best evidence available that "render the
response, never re-derive" is necessary but **not sufficient**. Faithfully rendering a field whose
name reads like the answer, when it is only one input to the answer, produces exactly the drift the
rule was written to prevent.

**Trap 1 — PKCE is mandatory for every client in every environment, and `pkceRequired` does not say
so.** `authorizeQuerySchema` declares `code_challenge` and
`code_challenge_method: z.literal('S256')` as **required, non-optional** query parameters
(`apps/auth-server/src/app/schemas/oauth.ts:32` and
`apps/auth-server/src/app/schemas/oauth.ts:37`). No client can obtain an authorization code without
an S256 challenge, whatever its environment. The token endpoint then enforces the downgrade floor
unconditionally — a `code_verifier` presented against a code carrying no challenge is
`invalid_grant` in **every** environment including `development` — the code calls it "a HARD FLOOR
enforced in EVERY environment" (`apps/auth-server/src/app/routes/oauth/token.ts:361`), implemented
at `apps/auth-server/src/app/routes/oauth/token.ts:368`. The surrounding comment states plainly
that the no-challenge branch exists only as defence-in-depth "for any future dev-only flow"
(`apps/auth-server/src/app/routes/oauth/token.ts:354`).

`policy.pkceRequired` is therefore not "is PKCE required" — its own contract says it governs only
whether the environment profile _additionally_ hard-requires it, on top of the project-wide floor
(`apps/auth-server/src/app/helpers/environment-policy.ts:123`). Rendering it as the PKCE row would
tell a `development` client's owner that PKCE is optional while `/oauth/authorize` rejects every
request without it.

**Decision — the PKCE row reads "Required (S256)", unconditionally, and is not sourced from any
policy field.** Its tooltip names the enforcement point: the authorize endpoint's own schema. There
is no false-y branch to render.

**Decision — do not render `oauth_clients.require_pkce` either.** It is already in the response
(`apps/auth-server/src/app/schemas/clients.ts:31`) and already typed in the portal
(`apps/developer-portal/src/server/auth-server-client.ts:82`), which makes it the obvious thing for
an implementer to reach for — and it would give the card two conflicting PKCE renderings.

The claim that matters is that **`requirePkce` is never read as an enforcement gate anywhere in
`apps/auth-server`.** Every reference to it is a write, the response projection
(`apps/auth-server/src/app/routes/clients/index.ts:107`), or a comment; no branch anywhere consults
it. A stored, exposed, unenforced flag must not be presented as a security control.

Do **not** reach instead for the weaker-sounding but tempting "and anyway it is always `true`" — it
is not. The developer-facing write paths do set it `true`
(`apps/auth-server/src/app/routes/clients/index.ts:449`, dynamic registration at
`apps/auth-server/src/app/routes/oauth/register.ts:127`, CIMD at
`apps/auth-server/src/app/helpers/cimd.ts:272`, and the column default at
`libs/infra/db/src/lib/schema/core.ts:147`), but `getOrCreateSystemClient` creates the internal
system client with `requirePkce: false`
(`apps/auth-server/src/app/helpers/oauth-client.ts:31`), reached from first-party login
(`apps/auth-server/src/app/routes/auth/login.ts:170`) and the authorize route
(`apps/auth-server/src/app/routes/oauth/authorize.ts:343`). The column genuinely varies. The
conclusion is unchanged — it is unenforced either way — but the supporting claim has to be the one
that is true.

**Trap 2 — loopback redirects are permitted in all three environments, and
`localhostRedirectAllowed` says otherwise.** The gate is `isRedirectUriAllowedForPolicy`, which
permits an `http://localhost` redirect when **either** the environment opts in **or** PKCE is
enforced: `policy.localhostRedirectAllowed || policy.pkceRequired`
(`apps/auth-server/src/app/helpers/oauth-redirect.ts:73`). Across the three shipped profiles
(`apps/auth-server/src/app/helpers/environment-policy.ts:158`) that disjunction is `true` every
time — `development` via the first term, `staging` and `production` via the second. The reasoning is
in the function's own doc comment: loopback plus S256 is safe on any host, and gating it on PKCE
rather than https-only is what lets native and MCP clients complete the auth-code flow against a
production authorization server (`apps/auth-server/src/app/helpers/oauth-redirect.ts:49`).

So a card rendering `localhostRedirectAllowed` would print "Rejected — https only" for every
staging and production client, while the server accepts their loopback URIs.

**Decision — the server computes and sends the answer, as `policy.loopbackRedirectPermitted`.**
`toClientResponse` evaluates the same disjunction the gate uses and puts the **result** in the
response; the UI renders that boolean and never sees the two inputs as a choice. Both inputs stay in
`policy` as well, because the response is the complete record of what the server decided — but the
rendered row is sourced from the computed field.

This is the general rule, stated once: **where an enforcement decision is a function of several
policy fields, the server sends the decision, not the arguments.** A field named after an input is
not an answer, and a UI that combines inputs is re-deriving policy no matter how simple the
combination looks.

**Decision — four `policy` fields are carried in the response and rendered nowhere.**
`pkceRequired` and `localhostRedirectAllowed` for the reasons in the two traps above — they are
inputs, not answers. `refreshRotationRequired` and `openDynamicRegistration` because neither is a
consequence a developer can act on from the portal: refresh rotation is transparent to a correctly
implemented client, and dynamic registration is a realm-level posture this client's page cannot
influence. Carrying all four and rendering none is deliberate — it keeps the response the complete
record of what the server decided while keeping the card to what a reader can use.

**Decision — render tier names, not seconds.** `accessTokenLifespanTier` is a coarse label by
design; the concrete seconds come from realm and environment configuration through
`resolveAccessTokenLifespanSeconds`
(`apps/auth-server/src/app/helpers/environment-policy.ts:281`), which the client response does not
carry. Displaying a number the portal cannot actually resolve would be an invented capability.
"Short" with the tier name in the tooltip is honest; "3600 s" would not be.

**Decision — the card states that the environment is the _effective_ one, and why it may differ
from what the developer set.** A realm pinned to `production` overrides a client asking for
`development` (`apps/auth-server/src/app/helpers/environment-policy.ts:242`). A developer who set
`development` and sees `production` with no explanation will file a bug. One sentence — "Capped by
your realm's ceiling" — prevents it, shown only when the effective value is stricter than the
client's declared value. That comparison needs the declared value, which the response does not
carry; **so the widened `policy` object also carries `declaredEnvironment`**, the raw
`oauth_clients.environment` column (`libs/infra/db/src/lib/schema/core.ts:226`), read-only.

## Surface C — agent visibility

**Shipped semantics.** Two columns, two very different trust levels:

- `isAgent` (`libs/infra/db/src/lib/schema/core.ts:182`) is **self-asserted, unverified client
  input**. It arrives in the client's own dynamic-registration body or its own CIMD metadata
  document. The schema comment says so in as many words
  (`libs/infra/db/src/lib/schema/core.ts:172`), and the fail-closed accessor `isAgentClient`
  (`apps/auth-server/src/app/helpers/client-resolution.ts:94`) exists so nothing reads the column
  directly.
- `maxAgentMode` (`libs/infra/db/src/lib/schema/core.ts:199`) is **operator-set server state**. It
  is not part of any registration request; a client cannot raise its own cap
  (`libs/infra/db/src/lib/schema/core.ts:190`).

A reserved `agent:*` scope is granted only when **both** hold: the client is classified as an agent
**and** its cap covers the requested mode. `findExceedingAgentScopes`
(`apps/auth-server/src/app/helpers/scope-modes.ts:156`) rejects a reserved scope when either
condition fails, and `isModeWithinCap` returns `false` for a `null` cap
(`apps/auth-server/src/app/helpers/scope-modes.ts:105`). An absent or unrecognised cap grants
**nothing** — `parseAgentMode` returns `null` for anything it does not recognise rather than
defaulting to a mode (`apps/auth-server/src/app/helpers/scope-modes.ts:76`). Cap ordering is
`readonly < admin < exec`, and a cap is a maximum, not an exact match
(`apps/auth-server/src/app/helpers/scope-modes.ts:59`). See
[Agent authorization](/integrate/agent-authorization/) for the full layer.

### The gap this surface actually has

As with Surface B: neither column is in the client response. `toClientResponse`
(`apps/auth-server/src/app/routes/clients/index.ts:95`) does not project them and `clientSchema`
does not declare them (`apps/auth-server/src/app/schemas/clients.ts:20`). **Surface C is not
read-only-in-the-UI-only; it needs the same response widening as Surface B.**

**Proposed.** Add `isAgent: boolean` and `maxAgentMode: 'readonly' | 'admin' | 'exec' | null` to
`clientSchema`, projected read-only in `toClientResponse`, and — as with `policy` — **absent from
the create and update request schemas**. Ship both widenings in one change; they touch the same two
functions and splitting them means reviewing the same diff twice.

### Proposed — rendering the fail-closed state

This is the part that matters more than the widget. An empty field reads as "unrestricted", which
is the exact opposite of what a `null` cap means. The agent row therefore has **three** states and
never a blank:

| Condition                           | Badge                                          | Body copy                                                                                                              |
| ----------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `isAgent` false                     | "Not an agent" (neutral)                       | "`agent:*` scopes are refused for this client."                                                                        |
| `isAgent` true, `maxAgentMode` null | "Agent — no modes granted" (warning)           | "No `agent:*` scope can be granted. The cap is unset, and an unset cap grants nothing."                                |
| `isAgent` true, `maxAgentMode` set  | "Agent — up to `agent:<mode>`" (informational) | The three reserved scopes listed with permitted/refused markers, so the `readonly ⊂ admin ⊂ exec` relation is visible. |

**Decision — the third state enumerates all three reserved scopes, not just the cap.** Showing
"Cap: admin" requires the reader to know the ordering. Showing `agent:readonly` ✓,
`agent:admin` ✓, `agent:exec` ✗ does not. The subset relation is the part people get wrong.

**Decision — self-asserted and operator-set values get visually distinct treatments, applied
site-wide.** Operator-set values (`maxAgentMode`, effective `environment`, the whole `policy`
object) render as solid-filled badges. Self-asserted values (`isAgent`, and the client's
`declaredEnvironment`) render with a dashed outline and no fill, and their tooltip begins "Declared
by the client; not verified." One consistent visual rule for one real distinction, rather than a
footnote nobody reads.

**Decision — no edit controls anywhere on this surface.** Neither field is accepted by
`updateClientRequestSchema` (`apps/auth-server/src/app/schemas/clients.ts:149`), so an edit control
would either be disabled-on-arrival or would need a new write path that ADR-007's trust boundary
exists to prevent. The card carries a single line instead: "Set by an operator. Contact your
operator to change this."

## Surface D — activity feed and metrics tiles

**Shipped foundation.** The audit-logs repository has four read methods.
`findByRealmId` (`libs/infra/db/src/lib/repositories/audit-logs.repository.ts:112`),
`findByRealmAndUserId` (`libs/infra/db/src/lib/repositories/audit-logs.repository.ts:155`) and
`findByRealmAndActorClientId`
(`libs/infra/db/src/lib/repositories/audit-logs.repository.ts:218`) are realm-guarded — each adds a
realm predicate over an `innerJoin`. **`findByUserId` is not.** Its conditions are
`[eq(auditLogs.userId, userId)]` alone, with no realm predicate and no join
(`libs/infra/db/src/lib/repositories/audit-logs.repository.ts:81`); the guarded sibling
`findByRealmAndUserId` is the one that adds `eq(users.realmId, realmId)`
(`libs/infra/db/src/lib/repositories/audit-logs.repository.ts:164`).

That distinction matters for what follows. It is tempting to describe these four as a ready-made,
uniformly-safe base and reach for whichever one is closest — and one of them is not tenant-scoped at
all. **None of the four answers the question this surface asks anyway**: the developer-scoped query
is "rows whose owning client belongs to this developer", which is neither a user nor a realm nor an
actor predicate. What is missing is an HTTP surface **and** a new developer-scoped repository
method. Nothing here proposes a new data _layer_, but it does propose a fifth finder, and that
finder must carry its ownership predicate itself rather than inheriting a guarantee from a sibling.

Pagination in the existing options object is **offset-based**: `limit` and `offset`
(`libs/infra/db/src/lib/repositories/audit-logs.repository.ts:18`, the `FindAuditLogsOptions`
interface).

### Proposed — `GET /api/audit`

**Decision — a top-level collection with a `clientId` filter, not a route nested under
`/api/clients/{id}`.** The primary view is cross-client: the dashboard shows the newest events
across everything the developer owns. A nested route cannot answer that without N requests and a
client-side merge, which cannot be paginated correctly at all. Ownership is enforced identically
either way, so nesting buys nothing and costs the main use case.

**Decision — mounted the same way `/api/clients` is**, from a `routes/audit/` directory whose entry
file exports `autoPrefix = '/api/audit'`, mirroring
`apps/auth-server/src/app/routes/clients/index.ts:71`. Route paths stay resource-relative (`/` and
`/metrics`).

#### Authorization

`preHandler: fastify.requireJwt`, exactly as the list-clients route does
(`apps/auth-server/src/app/routes/clients/index.ts:307`), with `security: [{ bearerAuth: [] }]` in
the schema. `request.jwtPayload.sub` is the developer's `users.id`.

Ownership is the same rule the management API already enforces — scope by
`oauth_clients.developer_id` (`libs/infra/db/src/lib/schema/core.ts:159`), the rule
`resolveOwnedClient` applies per-client
(`apps/auth-server/src/app/routes/clients/index.ts:155`). For a collection it becomes a join
predicate rather than a per-row check:

> `audit_logs.oauth_client_id IN (SELECT id FROM oauth_clients WHERE developer_id = :sub)`

**Do not invent a second ownership pattern.** In particular, do not scope by realm: realm scoping
is the operator-tier boundary the repository's existing methods use, and it would return every
developer's rows in a single-realm deployment.

**Decision — a non-UUID `sub` short-circuits to an empty list**, mirroring
`apps/auth-server/src/app/routes/clients/index.ts:329`. A `client_credentials` token's `sub` is an
opaque `client_id`, not a UUID; querying Postgres with it raises `22P02` and surfaces as a 500.

**The empty case is a first-class requirement, not a fallback.** A developer with no clients gets
`200` and an empty array. Never a 403, never a 404, and never — under any code path, including the
one where the ownership subquery returns no rows — another developer's rows. The ownership
predicate must be applied unconditionally; there must be no branch that skips the `WHERE` clause
when the client set is empty.

#### Pagination

**Cursor-based, keyset over `(created_at DESC, id DESC)`.**

**Decision — the cursor is an opaque base64url string** encoding
`{ t: <created_at>, i: <id>, w: { from, to }, f: <filter fingerprint> }`.

- **Why keyset, not the repository's existing offset.** `audit_logs` is append-heavy. Under
  offset paging, rows inserted between two requests shift the window, so page 2 re-shows rows from
  page 1 and skips others. Deep offsets also degrade. A feed whose second page silently repeats
  its first is the kind of wrong nobody reports.
- **Why `(created_at, id)` is a valid total order.** `created_at` is epoch milliseconds
  (`libs/infra/db/src/lib/schema/audit.ts:62`) and can tie. `id` defaults to `uuidv7()`
  (`libs/infra/db/src/lib/schema/audit.ts:23`), which is time-ordered, so the pair breaks ties in a
  direction consistent with insertion order.
- **Why opaque.** The encoding must stay free to change — adding a field to it later must not break
  callers who stored one. Opacity is not a security control here; ownership is enforced server-side
  on every request regardless of what a caller puts in the cursor.

##### The window is resolved once and frozen in the cursor

This is the part a naive reading gets wrong, and getting it wrong breaks "Load more" outright. The
window has a default (`from` defaults to `to - 30 days`, and `to` defaults to **the time the first
request was received**). The fingerprint check rejects a cursor whose filters do not match the
request's. Put those two together carelessly and every Load-more either `400`s — because `to`
re-defaults to a later "now" and the fingerprint no longer matches — or silently slides the window
forward between pages and drops rows at the boundary. Both were latent in the first draft of this
specification.

**Decision — a pagination session is a snapshot, and the resolved window travels in the cursor.**

1. **First request (no cursor).** The server resolves `to` (query value, else request-receipt time)
   and `from` (query value, else `to - 30 days`), validates the span (`400` if wider than 90 days,
   `400` if `from > to`), and runs the query against that resolved window.
2. **`nextCursor` carries the resolved window** in `w`, alongside the position and the fingerprint.
3. **Subsequent request (with a cursor).** The window comes **from the cursor**, never re-defaulted.
   `to` is not re-evaluated against the clock, so the window cannot slide.
4. **If a cursor request also sends `from` or `to` and either disagrees with the cursor's window, it
   is a `400`** (`invalid_cursor`), not a silent override. Changing the window means starting a new
   pagination session; pretending otherwise would hand back a page from a different query.

The consequence, stated so the UI can be honest about it: **events written after a pagination
session begins do not appear in it.** That is the correct behaviour for a paged feed and it is why
"Refresh" (which discards the cursor and starts a fresh session) is a separate, explicit control —
see [the feed UI](#proposed--the-feed-ui).

##### The fingerprint, constructed

**Decision — the fingerprint is computed over the _resolved_ filter set, after defaults are
applied.** Because defaults are resolved before hashing on the first request and thereafter read
from the cursor, "explicit value" and "same value arrived by default" produce the same fingerprint.
There is no defaults-versus-explicit ambiguity left for the check to trip over; a mismatch means a
caller genuinely changed a filter.

Construction, exactly:

1. Build an object from the resolved filters — `clientId`, `event`, `eventType`, `success`, `from`,
   `to`. **Absent filters are omitted, never serialised as `null`**, so "not filtering by event" and
   "filtering by a null event" cannot collide.
2. Canonicalise: keys sorted lexicographically; booleans as `true`/`false`; integers in decimal with
   no separators; UUIDs lowercased; strings verbatim. Serialise as compact JSON, no whitespace.
3. `SHA-256` the UTF-8 bytes, take the **first 8 bytes**, encode base64url.

Eight bytes is deliberate: this is a consistency check against a caller accidentally mixing filter
sets across pages, not an adversarial control. Ownership and redaction are enforced server-side on
every request from the JWT, independently of anything in the cursor, so a forged fingerprint buys an
attacker nothing but their own rows in a confusing order.

**Decision — `limit` does NOT participate in the fingerprint.** Under keyset pagination the cursor
is a _position_, not an offset, so changing page size mid-session is harmless and correct. Making it
a `400` would break a legitimate UI (dashboard preview of 10, then "see all" at 25) for no
correctness gain.

`limit` defaults to `25`, maximum `100`. **A `limit` above the maximum is a `400`, not a silent
clamp** — a caller that asks for 500, receives 100, and sees no `nextCursor` will conclude it has
seen everything.

**Decision — fetch `limit + 1` rows and return `nextCursor` only when the extra row exists.**
Returning a cursor on a full-but-final page produces a "Load more" button that loads nothing.

#### Filters

All optional, all `AND`-combined.

| Parameter    | Type                                                | Notes                                                                               |
| ------------ | --------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `clientId`   | UUID                                                | `oauth_clients.id`, matching every other per-client path in this API                |
| `event`      | string, exact match                                 | e.g. `oauth.token.exchange.failure`                                                 |
| `eventType`  | `auth\|token\|client\|security\|user\|realm\|agent` | The shipped enum (`libs/infra/db/src/lib/repositories/audit-logs.repository.ts:13`) |
| `success`    | boolean                                             |                                                                                     |
| `from`, `to` | integer, epoch milliseconds                         | Matches the column's own units                                                      |

**Decision — `clientId` is the row UUID, not the public `client_id` string.** Every other
per-client path in this API takes the UUID — `clientIdParamsSchema` is `z.object({ id: z.uuid() })`
on the client routes (`apps/auth-server/src/app/routes/clients/index.ts:119`) and
`z.object({ clientId: z.uuid() })` on the API-key routes
(`apps/auth-server/src/app/routes/clients/api-keys.ts:47`). The two identifiers are easy to confuse;
consistency with the existing surface is the tiebreaker. The response carries both so the UI never
has to guess.

**Decision — time bounds are epoch milliseconds, not ISO-8601.** `created_at` is a `bigint` in
milliseconds (`libs/infra/db/src/lib/schema/audit.ts:62`). Accepting ISO strings would put a parse
and a time-zone assumption between the caller and the column, and a boundary that is silently off
by an offset is the worst kind of filter bug.

**Decision — the default window is 30 days and the maximum span is 90 days**, resolved and frozen as
described under [the window](#the-window-is-resolved-once-and-frozen-in-the-cursor). This
bounds the keyset scan. There is no retention or pruning job for `audit_logs` anywhere in the tree
(searched `libs/infra/db/src` and `apps/auth-server/src` for retention/prune/purge; nothing matches
`audit_logs`), so the table only grows. This is an operational view, not an export.

#### Response shape and redaction

**Decision — the response is camelCase.** The management API's payloads are app-specific rather
than RFC wire formats, and the project's convention for those is camelCase
(`apps/auth-server/src/app/schemas/clients.ts:6`). The column names are snake_case; the wire format
follows the repository's existing management-API surface. Mixing the two would make `/api/audit`
the only inconsistent endpoint in the JSON API.

Returned per row:

| Field             | Source column         | Notes                                                                                                                                                                               |
| ----------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`              | `id`                  | Row key for the UI, and the cursor's second component                                                                                                                               |
| `event`           | `event`               |                                                                                                                                                                                     |
| `eventType`       | `event_type`          |                                                                                                                                                                                     |
| `success`         | `success`             |                                                                                                                                                                                     |
| `createdAt`       | `created_at`          | Epoch milliseconds                                                                                                                                                                  |
| `client`          | via `oauth_client_id` | A nested `{ id, clientId, name }` — the owning client's UUID, its public `client_id` string, and its name. The feed is cross-client, so a row has to say which client it belongs to |
| `scopeMode`       | `scope_mode`          | `libs/infra/db/src/lib/schema/audit.ts:60`                                                                                                                                          |
| `actorClientId`   | `actor_client_id`     | A public client identifier only, never a secret (`libs/infra/db/src/lib/schema/audit.ts:44`)                                                                                        |
| `delegationChain` | `delegation_chain`    | Ordered public `client_id`s; contains no token, secret or subject material (`libs/infra/db/src/lib/schema/audit.ts:51`)                                                             |

Withheld, always, with no query parameter that can turn any of them on:

- **`ip_address`** (`libs/infra/db/src/lib/schema/audit.ts:36`) and **`user_agent`**
  (`libs/infra/db/src/lib/schema/audit.ts:37`). End-user device and network data. A developer is not
  an operator; the portal is self-service with no operator vetting.
- **`user_id`** (`libs/infra/db/src/lib/schema/audit.ts:29`) — **omitted entirely, not
  pseudonymised.** Omission is the strictly smaller surface, no surface in this specification groups
  or joins by user, and a pseudonym is a stable correlator that would exist purely because it was
  available. If a future feature genuinely needs per-user grouping, adding a pseudonym then is
  additive; removing one that has shipped is a breaking change. Choose the reversible direction.
- **`metadata`** (`libs/infra/db/src/lib/schema/audit.ts:61`) — withheld wholesale. It is free-form
  `jsonb` written by many call sites with no shared schema (for example
  `apps/auth-server/src/app/routes/clients/index.ts:464`), so its contents cannot be
  redaction-reviewed once and trusted afterwards: a future call site could add end-user data to it
  without anyone revisiting this endpoint. **The projection is an allowlist of columns, never a
  denylist** — a column added to `audit_logs` later must not appear here by default.

This follows the data-minimisation precedent of **#259**, which gated ID-token email claims on
scope rather than emitting them because they were available.

##### The same rule applied to `event`, which is where it was initially missed

The argument for withholding `metadata` — an open namespace that a future call site can extend
without anyone revisiting this endpoint — applies verbatim to `event`, and the first draft of this
specification returned `event` unrestricted. It is a `varchar(100)`
(`libs/infra/db/src/lib/schema/audit.ts:33`) with no enum and no allowlist anywhere in the tree.

The leak is not hypothetical, and it is worth being precise about where it is and is not.
`delegation_chain`, `actor_client_id` and `scope_mode` are **not** the vector — those columns carry
public client identifiers and a coarse mode label, and nothing else
(`libs/infra/db/src/lib/schema/audit.ts:44`, `:51`). The vector is **an open event namespace plus a
millisecond timestamp.** Client-attributed rows already describe end-user authentication behaviour:
`oauth.stepup.required` is written with `oauthClientId: client.id` at **six** sites — five in the
authorize route (`apps/auth-server/src/app/routes/oauth/authorize.ts:304`,
`apps/auth-server/src/app/routes/oauth/authorize.ts:437`,
`apps/auth-server/src/app/routes/oauth/authorize.ts:503`,
`apps/auth-server/src/app/routes/oauth/authorize.ts:540`,
`apps/auth-server/src/app/routes/oauth/authorize.ts:569`) and one in the consent UI
(`apps/auth-server/src/app/routes/ui/consent.ts:736`) — and `oauth.consent.revoked` likewise
(`apps/auth-server/src/app/routes/consents/index.ts:181`). A developer holds their own application
logs; joining "a step-up was demanded at 14:02:11.431" against their own request log identifies
which of their users it was, and what that user was doing at the time. `user_id` being absent does
not help when the timestamp is the join key.

**Decision — both halves: an event allowlist, and coarsened timestamps.**

1. **`event` and `eventType` are served from an explicit allowlist**, applied with the same
   structural rule as the column allowlist: **a row whose `event` is not on the list is not
   returned at all** — not returned with the event redacted, which would leak its existence and its
   timestamp. A new event name added to the tree is invisible to this endpoint until someone puts it
   on the list, which is the same fail-closed direction as the column rule. The complete list, and
   the verdict for every other event in the tree, is
   [enumerated below](#every-event-in-the-tree-classified).
2. **`createdAt` is truncated to whole seconds on this surface.** Millisecond precision is what makes
   a log join a reliable identification, and no developer-facing use case here needs it: the feed is
   read by eye and the tiles count over a 24-hour window. Truncation happens in the projection, not
   in storage — the column keeps full precision for operators.

**The cursor keeps full millisecond precision**, because the keyset order depends on it
(`(created_at, id)` is only a total order at the stored resolution). The cursor is opaque and
server-minted, so this does not hand the precision back through the front door; it means only that
the coarsening is a display-and-response concern, never a query-correctness one.

##### Every event in the tree, classified

An allowlist that names some events and leaves the rest to fail closed is not a decision — it is a
decision deferred to whoever next reads the code and cannot tell whether an omission was reasoned or
overlooked. So: **every `event` string written anywhere in `apps/auth-server/src` or `libs` appears
exactly once below, with a verdict and a reason.** The enumeration is mechanical (all `event: '…'`
audit writes, test files excluded) and gives **32 distinct names** at the `lastVerified` date.

Three verdicts, not two — because a third category turned out to exist and matters:

- **Allow** — client-attributed, and it is the developer's own integration activity.
- **Exclude (policy)** — reachable, but it describes what an identified end user did. This is the
  category with a real cost.
- **Unreachable** — written with `oauth_client_id: null`, or attributed to a client whose
  `developer_id` is `null`. The ownership predicate already excludes these; the allowlist never gets
  a say. Recorded so nobody re-argues the policy for an event that cannot appear.

| Event                             | Verdict           | Reason                                                                                                                                                        |
| --------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `oauth.client.created`            | Allow             | The developer's own client lifecycle                                                                                                                          |
| `oauth.client.updated`            | Allow             | ditto                                                                                                                                                         |
| `oauth.client.deleted`            | Allow             | ditto                                                                                                                                                         |
| `oauth.client.secret_regenerated` | Allow             | ditto                                                                                                                                                         |
| `api_key.created`                 | Allow             | ditto                                                                                                                                                         |
| `api_key.revoked`                 | Allow             | ditto                                                                                                                                                         |
| `oauth.token.exchange.success`    | Allow             | The developer's own token traffic; 23 of 25 write sites are client-attributed                                                                                 |
| `oauth.token.exchange.failure`    | Allow             | ditto — the single most useful event for debugging an integration                                                                                             |
| `oauth.authorize.success`         | Allow             | The developer's own authorize traffic                                                                                                                         |
| `oauth.authorize.failure`         | Allow             | ditto; 7 of 8 sites attributed                                                                                                                                |
| `oauth.introspect.success`        | Allow             | The developer's own resource server introspecting a token (`apps/auth-server/src/app/routes/oauth/introspect.ts:207`)                                         |
| `oauth.introspect.failure`        | Allow             | ditto                                                                                                                                                         |
| `oauth.revoke.success`            | Allow             | The developer's own revocation call (`apps/auth-server/src/app/routes/oauth/revoke.ts:103`)                                                                   |
| `oauth.revoke.failure`            | Allow (no effect) | Policy says allow, but every write site is `oauthClientId: null` (`apps/auth-server/src/app/routes/oauth/revoke.ts:76`) — written before client auth succeeds |
| `oauth.stepup.required`           | Exclude (policy)  | Six attributed sites; describes an identified end user being challenged                                                                                       |
| `oauth.stepup.elevation`          | Exclude (policy)  | Attributed; an identified end user re-authenticating for a dangerous scope                                                                                    |
| `oauth.consent.granted`           | Exclude (policy)  | Attributed; an identified end user's consent decision                                                                                                         |
| `oauth.consent.denied`            | Exclude (policy)  | ditto, 3 sites                                                                                                                                                |
| `oauth.consent.revoked`           | Exclude (policy)  | ditto                                                                                                                                                         |
| `user.login.success`              | Exclude (policy)  | End-user behaviour. Also unreachable — attributed to the system client, whose `developerId` is `null`                                                         |
| `user.login.failure`              | Exclude (policy)  | End-user behaviour; `oauthClientId: null`                                                                                                                     |
| `user.logout.success`             | Exclude (policy)  | ditto                                                                                                                                                         |
| `user.logout.failure`             | Exclude (policy)  | ditto                                                                                                                                                         |
| `ui.login.success`                | Exclude (policy)  | Hosted-UI end-user behaviour; `oauthClientId: null`                                                                                                           |
| `ui.login.failure`                | Exclude (policy)  | ditto                                                                                                                                                         |
| `ui.login.csrf_failure`           | Exclude (policy)  | ditto                                                                                                                                                         |
| `oauth.userinfo.success`          | Unreachable       | `oauthClientId: null` (`apps/auth-server/src/app/routes/oauth/userinfo.ts:78`). Policy answer if that ever changes: allow                                     |
| `oauth.userinfo.failure`          | Unreachable       | `oauthClientId: null` (`apps/auth-server/src/app/routes/oauth/userinfo.ts:96`). Policy answer if that ever changes: allow                                     |
| `oauth.client.registered`         | Unreachable       | Attributed, but dynamic registration creates clients with `developerId: null` — see below                                                                     |
| `oid4vp.response.received`        | Unreachable       | `oauthClientId: null` (`apps/auth-server/src/app/routes/oid4vp/response.ts:224`); also wallet federation behind a default-off flag                            |
| `oauth.consent.csrf_failure`      | Unreachable       | `oauthClientId: null` (`apps/auth-server/src/app/routes/ui/consent.ts:565`)                                                                                   |
| `consents.revoke.csrf_failure`    | Unreachable       | `oauthClientId: null` (`apps/auth-server/src/app/routes/consents/index.ts:145`)                                                                               |

**On the three that prompted this enumeration.** `oauth.introspect.success` was a genuine omission —
`oauth.introspect.failure` was already on the list, so excluding its success twin was an
inconsistency, not a decision, and it is now allowed. `oauth.userinfo.success` / `.failure` are the
developer's own resource-server traffic and would be allowed on the same reasoning — but both write
`oauthClientId: null`, so allowlisting them would change nothing today and would misleadingly imply
they appear. They are recorded as unreachable **with their policy answer written down**, so if
userinfo ever becomes client-attributed the question does not have to be re-derived.
`oid4vp.response.received` is settled twice over: unattributed, and wallet-federation transport
behind a flag that is off by default.

**A fourth structural gap, found while enumerating: dynamically registered clients are invisible to
this feed entirely.** Both `POST /oauth/register`
(`apps/auth-server/src/app/routes/oauth/register.ts:129`) and CIMD registration
(`apps/auth-server/src/app/helpers/cimd.ts:274`) create clients with `developerId: null`. The
ownership predicate is `oauth_clients.developer_id = :sub`, so **no** row belonging to a DCR or CIMD
client can ever match it — not just `oauth.client.registered`, but every token exchange and
authorize event those clients generate. A developer whose clients were all registered dynamically
sees an empty feed and no explanation. This is a property of the ownership model, not of the
allowlist, and it cannot be fixed here: `developer_id` is the only ownership signal the schema has.
The feed's empty state must therefore say so rather than reading as "nothing happened" — see the
footnote below.

##### The allowlist's cost, stated in one place

So that this never has to be reconstructed from two lists again, here is everything the feed does
not show, complete:

1. **End-user authentication and consent activity for the developer's own clients** — step-up
   challenges, step-up elevations, and consent granted / denied / revoked. These are reachable,
   client-attributed rows that are deliberately withheld. **This is the real cost of the policy
   decision**, and it is larger than "consent and step-up were excluded" suggests in the abstract:
   it means a developer cannot see, for their own application, that a user was challenged for
   step-up or withdrew consent.
2. **All first-party and hosted-UI login/logout activity** (`user.*`, `ui.*`) — excluded on the same
   grounds, and unreachable anyway.
3. **Anything belonging to a dynamically registered or CIMD client** — the whole client, not
   selected events, per the structural gap above.
4. **Anything recorded before a client was identified**, and **anything belonging to a client the
   developer has since deleted**.
5. **Millisecond precision on every timestamp** — the feed shows whole seconds.

Items 1 and 5 are reversible policy choices and should be re-confirmed with the owner before
implementation rather than after. Items 2, 3 and 4 are structural.

#### What the feed structurally cannot show

Four categories of row will never appear, and the UI must say so rather than leave an unexplained
gap. The first is a policy choice; the other three are structural. The complete cost is stated in
[one place above](#the-allowlists-cost-stated-in-one-place); this section covers only the three
structural causes and their code anchors.

1. **Rows whose `event` is not on the allowlist** — see
   [the classification table](#every-event-in-the-tree-classified). A policy choice.
2. **Rows written before a client was resolved.** Many failure paths record `oauthClientId: null` —
   for example `apps/auth-server/src/app/routes/oauth/authorize.ts:158` and
   `apps/auth-server/src/app/routes/oauth/token.ts:146`. They have no client to be scoped to.
3. **Rows belonging to a deleted client.** The FK is `set null` on delete
   (`libs/infra/db/src/lib/schema/audit.ts:30`), so deleting a client detaches its entire audit
   history from the ownership predicate.
4. **Every row belonging to a dynamically registered or CIMD client**, because those clients carry
   `developerId: null` (`apps/auth-server/src/app/routes/oauth/register.ts:129`,
   `apps/auth-server/src/app/helpers/cimd.ts:274`) and the ownership predicate is
   `developer_id = :sub`.

**Decision — gap 4 gets its own empty state, not the generic one.** A developer whose clients were
all registered dynamically would otherwise see the ordinary "No events yet", which reads as "nothing
happened" when the truth is "this surface cannot show your clients at all". When the developer owns
zero clients by `developer_id` **and** the feed is empty, the empty state says so explicitly and
points at `/clients/new`. Distinguishing the two cases costs one extra count and prevents a bug
report that would be impossible to reproduce.

**Decision — an `event` or `eventType` filter naming something outside the allowlist is a `400`, not
an empty result.** An empty result is an existence oracle: it lets a caller distinguish "no such
events for me" from "that event is withheld" only by guessing, and it invites an implementer to
treat the filter as the authority instead of the allowlist. Reject the request and name the
constraint.

**Decision — a permanent footnote under the feed**, not a tooltip and not a documentation-only
note: "This feed shows a defined set of client and token events for the clients you own. Your end
users' sign-in, step-up and consent activity is not shown. Neither is anything recorded before a
client was identified, anything belonging to a client you have since deleted, or anything from a
dynamically registered client. Times are shown to the nearest second."

Say all five things. A feed that quietly omits a category is an audit-shaped surface making a
promise it does not keep, which is the failure mode this whole page is trying to avoid.

#### Proposed — index migration

The ownership predicate plus the keyset order needs a composite index. The shipped indexes are
`idx_audit_logs_oauth_client_id` on the FK alone
(`libs/infra/db/src/lib/schema/audit.ts:66`) and `idx_audit_logs_created_at` on the timestamp alone
(`libs/infra/db/src/lib/schema/audit.ts:69`); neither supports "this client's rows, newest first"
without a sort. **Add exactly one index — `idx_audit_logs_client_created_at` on
`(oauth_client_id, created_at DESC)` — in a migration that lands before the endpoint**; see
[ordering](#implementation-order-and-dependencies).

**Be honest about what that index does and does not do.** The common case is the feed with **no**
`clientId` filter, which is not a single-value lookup: the predicate is
`oauth_client_id = ANY(<the developer's clients>)`. Postgres serves that from this index as one
index scan per array element, and it will generally **not** preserve the global
`created_at DESC` ordering across them — expect a sort, or a merge, above the scans. The index still
earns its place: it turns each per-client access into a range scan already ordered within that
client and already bounded by the window, so the sort input is "this developer's rows in the last 30
days" rather than the table. **That bound is the real protection, and it is why the window is
mandatory and capped rather than optional.**

**Decision — do not add a second index for the tiles.** The tile window is 24 hours against the
feed's 30 days, so the same composite index reaches a set roughly thirty times smaller, and the
event/`success` predicates are applied as a filter above it. One index that serves both surfaces
adequately beats two that each serve one perfectly, on a table with no pruning where every index is
a permanent write cost.

**Retracted: two claims of index support that do not hold.** An earlier draft of this page credited
the two existing partial indexes for the metrics tiles. Neither works, and the reasoning is worth
keeping so it is not re-invented:

- **`idx_audit_logs_failed`** is `(event, created_at) WHERE success = false`
  (`libs/infra/db/src/lib/schema/audit.ts:71`). A partial index is only usable when the query's
  predicate **implies** the index predicate, and Postgres cannot infer `success = false` from
  `event = 'oauth.token.exchange.failure'` — the naming convention is a project convention, not a
  constraint the planner knows about. The fix is in the query, below.
- **`idx_audit_logs_actor_client_id`** is `(actor_client_id, created_at) WHERE actor_client_id IS
NOT NULL` (`libs/infra/db/src/lib/schema/audit.ts:77`). The "agent actions" count constrains the
  leading column only with `IS NOT NULL`, which is the index's own partial predicate — so there is
  no range to seek to and the scan degenerates to reading the whole partial index. It also carries
  no ownership column, so every row it returns still needs checking. It is the right index for
  "this specific agent's activity, newest first", which is the query
  `findByRealmAndActorClientId` was built for
  (`libs/infra/db/src/lib/repositories/audit-logs.repository.ts:218`) — not for this tile.

### Proposed — `GET /api/audit/metrics`

**Decision — a separate path, not a query flag on the feed.** A `?metrics=true` parameter that
changes the response shape cannot be expressed in one OpenAPI schema, and the two surfaces need
different cache policies. Two paths, two schemas.

**Decision — the tiles aggregate from `audit_logs`, never from the Prometheus registry.** The
registry is a per-process `Registry` instance created at plugin registration
(`apps/auth-server/src/app/plugins/metrics.ts:46`) and served by `GET /metrics`
(`apps/auth-server/src/app/routes/metrics.ts:22`). It is process-local, it resets on restart, and
behind replicas each process holds a different partial count. It is also global — it has no notion
of which developer owns what — so it could not answer a per-developer question even if it were
durable. `audit_logs` is durable, attributable and indexed. See
[Observability](/operate/observability/) for what the registry is legitimately for.

**Window: a rolling 24 hours** (`created_at >= now_ms - 86_400_000`), stated on the tile group, not
implied.

Four tiles, all scoped by the same ownership predicate and the same 24-hour window, all served from
the one composite index above:

| Tile                    | Predicate                                                    |
| ----------------------- | ------------------------------------------------------------ |
| Tokens issued           | `event = 'oauth.token.exchange.success'`                     |
| Token failures          | `event = 'oauth.token.exchange.failure' AND success = false` |
| Authorizations          | `event = 'oauth.authorize.success'`                          |
| Agent-attributed events | `actor_client_id IS NOT NULL`                                |

**Decision — the "Token failures" predicate carries `AND success = false` explicitly**, even though
it is redundant against today's data. Every `.failure` event in the tree is written with
`success: false` — verified by extracting all 45 `.failure` audit writes across
`apps/auth-server/src` and checking each one's `success` field — so this changes no result. It is
there because the redundancy is the _contract_: it documents at the query site that the naming
convention and the boolean must agree, and it is the form a partial index on `success = false`
could ever match. Without it the predicate silently depends on a convention nothing enforces.

**Decision — one aggregate query with four `count(*) FILTER (WHERE ...)` clauses, not four
queries.** All four share the ownership predicate, the window and the index access path; splitting
them multiplies that work by four for no benefit. This is an assertion about query shape, not a
benchmarked claim about performance — if it proves wrong under load, the tiles are independent
enough to split without changing anything else in this specification.

**Decision — the fourth tile is called "Agent-attributed events", not "Agent actions".** It counts
audit rows that carry an `actor_client_id`, which is a narrower and more literal thing than "actions
an agent took": today exactly three call sites write that column — `client_credentials` token
issuance (`apps/auth-server/src/app/routes/oauth/token.ts:728`), delegated token exchange
(`apps/auth-server/src/app/routes/oauth/token.ts:1385`), and consent step-up elevation
(`apps/auth-server/src/app/routes/ui/consent.ts:830`). Whatever an agent then does against a
resource server is invisible to this authorization server. "Agent actions" would promise the latter.

**A note on what this tile counts, because it is easy to get backwards.** All three write sites set
`oauthClientId` and `actorClientId` from the **same** client — the agent is both the row's owning
client and its actor. So under an ownership predicate on `oauth_client_id`, this counts rows where
**the developer's own agent client acted**, which is the intended question. It does not count rows
where someone else's agent acted upon the developer's client; no such row exists, because nothing
writes an `actor_client_id` that differs from the row's `oauth_client_id`. Delegation depth is
recorded in `delegation_chain`, not by splitting the two columns
(`libs/infra/db/src/lib/schema/audit.ts:54`).

**Decision — "Token failures" is labelled "attributed to your clients" in its helper text.** It
undercounts: failures recorded before the client is resolved carry no `oauth_client_id` (see
[above](#what-the-feed-structurally-cannot-show)). A tile that undercounts without saying so is a
tile that gets trusted for something it cannot do.

**Decision — the tiles are not filtered by the feed's event allowlist.** They are aggregate counts
over named events, and every event they count is on the allowlist anyway. Stating it prevents an
implementer from wiring the allowlist in twice and quietly zeroing a tile.

**Decision — cache for 60 seconds in Redis, keyed by `developerId` and window.** Redis, not
in-process memory, for the same reason the Prometheus registry was rejected: a per-process cache
gives different replicas different answers. `fastify.redis` is already available and the
set-with-TTL pattern is established (`apps/auth-server/src/app/helpers/cimd.ts:312`). Sixty seconds
bounds the worst case to one aggregate query per developer per minute while staying visibly fresh
for a surface that is a trend indicator, not a monitor.

#### Rate limits for both endpoints

`POST /api/clients` sets the precedent that an expensive authenticated handler gets its own per-route
budget rather than riding the global default
(`apps/auth-server/src/app/routes/clients/index.ts:374`, capped per-IP because create runs an
argon2id hash). These two reads are the most expensive in this API for a different reason — an
uncached keyset scan and an aggregate, both over a table with no pruning — so they need budgets too,
but keyed differently.

**Decision — both endpoints are rate-limited per authenticated developer, not per IP.** The
argon2id routes cap by IP because the cost is inflicted before the caller is known to be legitimate.
Here the caller is already authenticated by `requireJwt` and the cost scales with _their_ data, so
`request.jwtPayload.sub` is the correct key; an IP key would throttle a whole office behind one NAT
and would not throttle a single developer looping from many addresses.

- **`GET /api/audit`** — 60 requests per minute per developer. Comfortably above a human clicking
  "Load more" and far below a scripted export, which is not what this surface is for.
- **`GET /api/audit/metrics`** — 30 requests per minute per developer. The 60-second cache already
  absorbs repeat traffic, so this only bounds a caller deliberately missing the cache.

Both are ordinary `config.rateLimit` blocks in the route definition, the same mechanism
`POST /api/clients` uses. Neither is rate-limit-exempt: `GET /metrics` is exempt because a scraper
polls it (`apps/auth-server/src/app/routes/metrics.ts:31`), and that reasoning does not transfer to a
developer-facing endpoint.

**Decision — the tiles render an "as of" relative timestamp.** A number that can be 60 seconds
stale must say so, or it will be read as live and disbelieved when it disagrees with the feed
directly beneath it.

### Proposed — the feed UI

**Decision — a "Load more" button, not infinite scroll.** Infinite scroll over a live-append table
with a keyset cursor produces duplicates across re-renders and gives the reader no stable sense of
position. A button makes each fetch an explicit action and the cursor a single monotonic hand-off.

**Decision — no auto-refresh; a manual "Refresh" resets the cursor and clears the loaded pages.**
Auto-refresh would put the visible list and the held cursor into permanent disagreement.

**Decision — the dashboard preview shows ten rows and links to `/activity`; `/activity` fetches
twenty-five at a time.** The preview exists to make a problem visible, not to be read in full.

**Decision — the portal reaches both endpoints only through TanStack Start server functions.** The
browser must never call the auth-server directly. This is the exact mistake #366 documents
(`apps/developer-portal/src/routes/consents.tsx:45`), and the whole portal holds the opposite
property everywhere else. Do not add a second exception.

## Implementation order and dependencies

Ordered. Each step assumes every step above it has landed.

1. **Correct the API-keys card and ship `/api-keys`.** No backend dependency, and it is the only
   change that retracts an actively false statement
   (`apps/developer-portal/src/routes/_authed/dashboard.tsx:42`). Ship it first.
   - **Docs dependency:** [Known gaps](/portal/known-gaps/) opens with that stale card. Its first
     section becomes wrong the moment this lands and must be updated in the **same** pull request.
2. **Widen `clientSchema` with `policy`, `declaredEnvironment`, `isAgent` and `maxAgentMode`.** One
   change, covering Surfaces B and C — they touch the same two functions.
   - The portal's own `OAuthClient` interface
     (`apps/developer-portal/src/server/auth-server-client.ts:71`) must be widened in the same pull
     request, or the new fields arrive at runtime with no types and get quietly ignored.
   - **`apps/docs-site/public/openapi.json` must be regenerated in the same pull request**
     (`pnpm exec nx run auth-server:openapi-export`, declared at
     `apps/auth-server/project.json:65`). The response schema is part of the spec.
3. **Ship Surfaces B and C in the UI.** Depends on 2.
4. **Land the `idx_audit_logs_client_created_at` migration.** Before the endpoint, not with it — an
   endpoint merged ahead of its index is a sequential scan in production for however long the two
   pull requests are apart.
5. **Ship `GET /api/audit` and `GET /api/audit/metrics`, with the ownership filter and the redaction
   allowlist tested, before any UI consumes them.** A UI built against an unredacted response bakes
   fields into components that then have to be removed, and the removal is the change nobody
   prioritises.
   - **`apps/docs-site/public/openapi.json` and
     [the API reference](/integrate/api-reference/) must change in the same pull request as the
     route**, regenerating the spec with `pnpm exec nx run auth-server:openapi-export`. This is a
     hard CI constraint, not a courtesy: `findRoutesMissingFromOpenApi`
     (`apps/docs-site/src/invariants/endpoint-coverage.test.ts:76`) asserts that every route
     statically extracted from `apps/auth-server/src/app/routes` appears in `openapi.json`, and the
     legs-2-and-3 case (`apps/docs-site/src/invariants/endpoint-coverage.test.ts:115`) asserts exact
     path-set equality between `openapi.json` and the API reference page. Merging the route alone
     red-fails the docs-site suite, and merging the docs alone fails it in the other direction.
6. **Ship the metrics tiles and the activity feed UI.** Depends on 5.
7. **#366 — move the consent calls behind server functions.** Independent of 1–6; can run in
   parallel. Its own internal order: settle how a server function authenticates **and** what
   replaces the session-anchored `X-CSRF-Token` control
   (`apps/auth-server/src/app/routes/consents/index.ts:142`) before writing the server functions —
   both change the auth-server side, and discovering the CSRF problem after the portal side is
   written means writing it twice.
8. **Link consents from the dashboard and the authed header.** Depends on 7, in the same pull
   request as 7. Never before.

### One more dependency, in the opposite direction

The guard that catches documentation claiming a shipped feature is unbuilt scans the site content
tree and the two READMEs (`apps/docs-site/src/invariants/status-claims.ts:248`, the
`findStaleStatusClaims` function). It does **not** scan `apps/developer-portal`. That is precisely
why "Coming soon in Phase 2.3" survived in a React component for two shipped issues while the
documentation stayed correct. Extending the guard's scan set to portal source is a reasonable
follow-up and is **not** a prerequisite for anything above — it is recorded here so the next person
to ask "how did that survive?" has the answer.

## What this specification does not settle

Stated plainly, so nobody mistakes silence for a decision:

- **How a portal server function authenticates to the auth-server's consents endpoints, and what
  replaces their session-anchored CSRF token.** Both are set out under
  [Surface A3](#a3-consents--linked-but-only-after-366); both are #366's to answer, and the CSRF
  half is not on #366's task list today.
- **Whether `environment-policy.ts` should move to a shared library.** Rejected for this change,
  with reasons, but the question is legitimate and will recur.
- **Retention for `audit_logs`.** There is none today. The 90-day query cap bounds the read side;
  it does nothing about the table growing without limit.
- **Realm-level visibility of any kind.** Out of scope by the non-goals above, and it should stay
  out until an operator role exists to own it.

## See also

- [Portal guide](/portal/guide/) — the session model, and every flow the portal implements today.
- [Known gaps](/portal/known-gaps/) — the baseline this specification is written against.
- [Environment-Aware Authorization](/operate/environment-authorization/) — the ADR-008 policy
  Surface B renders.
- [Agent authorization](/integrate/agent-authorization/) — the ADR-007 layer Surface C makes visible.
- [Observability](/operate/observability/) — what the Prometheus registry is for, and why the
  metrics tiles do not use it.
- [API reference](/integrate/api-reference/) — where `/api/audit` must be documented when it ships.
