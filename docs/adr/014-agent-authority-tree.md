# ADR-014: Agent Authority Tree — Session-Rooted, Sender-Constrained Delegation for AI Agents

**Status:** Proposed
**Date:** 2026-09-21
**Authors:** QAuth Team

> **Proposed 2026-09-21.** Nothing below is implemented. Every fork takes the
> fail-closed option, every new surface is inert until an operator provisions
> it, and the whole record sits behind `AGENT_TREE_ENABLED` (default `false`,
> [Decision](#decision)), so a default deployment's behaviour is byte-for-byte
> unchanged by this record. No existing token-exchange gate is loosened.
> With the flag on, GATE 2 refuses an ID-JAG mint by an agent type (§4).
> From P1b, with the flag on, two gates are added (§4): GATE 4d on every
> exchange, and GATE 3d on every exchange whose subject token carries `cnf`.
> 3d's ledger check also runs on every exchange, and its allowlist check on
> every exchange of a `sid`-carrying subject by another client. The denylist
> check already ships on every exchange as GATE 3a. One choice since
> 2026-09-30 is the maintainer's rather than the fail-closed one. From P2,
> with the flag on, a sign-out leaves agent trees running, and a separate
> revoke-all is the kill switch (decision 1). The vitrin composition is a
> proposal into vitrin's open questions, not a description of anything
> vitrin does today.
>
> **Amended 2026-09-22** (before any implementation): a durable agent
> principal with an owner (§13), agent-transmitted action events and the
> members that name the agent and the model it reports (§7), and a
> provenance convention for commits (§9). Every addition sits behind the same
> switch; the rows it adds — an agent, its bindings, its transmitters — are
> the owner's to create and exist for nobody until an owner creates them,
> the way a client registration is a developer's (ADR-012). QAuth holds the
> identity, the ledger and the log, and nothing about what an agent does
> with its identity elsewhere — that is the owner's own record
> ([Explicitly out of scope](#explicitly-out-of-scope)).
>
> **Amended 2026-09-24** (before any implementation): remote approval (§14)
> — a refused request the owner approves from a phone with a passkey, as a
> separate elevation leaf that never widens a token or a tree — with its
> threat, T8, and parked decisions 14–16; a clause in T3 on why vitrin is
> listed beside PostgreSQL; and the 2026-09-22 text its first commit dropped.
> Remote approval sits behind a second switch, `AGENT_APPROVAL_ENABLED`.
>
> **Amended 2026-09-30** (before any implementation). The maintainer read the
> record as merged and, in his comments on it, decided four parked questions:
>
> - **1:** agent trees survive sign-out (`POST /auth/logout`, which the
>   portal's sign-out calls). A separate revoke-all, the owner's kill switch,
>   ends every tree the user rooted, and every agent refresh family not yet
>   in one (§6).
> - **10:** history keeps the owner of its time, and from the transfer the
>   agent acts under the new owner (§13).
> - **14:** five of the six lasting answers — two windows, two mutes and a
>   standing block (§14).
> - **15:** a passkey is the only approval factor, in every profile (§14).
>
> Decision 12 stays parked, its purpose restated. New questions are parked as
> decisions 17–22. Decision 21 parks the point where two of his merged rules
> meet. §1 lets a resumed session reuse its root while its refresh token
> lives. §6's dead-man switch ends a root, and that token with it, when its
> process exits and the walk reaches QAuth. Decision 21 also parks stricter
> rules for when a root ends, such as on a new `session_id` inside its
> process. Decisions 17 and 22 park stricter rules that would change what he
> merged: no skip of the consent screen for an agent client, and a frozen
> agent during a transfer. The record keeps his merged rules until he
> decides.
>
> The amendment also brings the record in line with main after the twelve
> security advisories published on 2026-09-25 and PR #415, which accepts
> loopback redirect URIs on any port. The body cites the seven whose fixes it
> builds on: GHSA-6fcx-34r3-24v4, GHSA-c2gj-r6hx-292c, GHSA-c863-7xrr-ww9v,
> GHSA-46p8-vmjm-2jpq, GHSA-54c2-vvpr-33mf, GHSA-893p-69r3-pw26 and
> GHSA-4pqf-fmj4-wjgx. Its Context table and code anchors describe main as it
> stands, and the watch list is re-pinned.
>
> Separately, the record adds rules of its own, each the fail-closed choice.
> The main ones:
>
> - a sign-out still ends a `sid` family whose client is no longer an agent
>   client, and an agent family not yet in a tree (§6);
> - the end of a root's refresh family, or the deletion of its client, ends
>   its tree, and a revocation walk and a mint never race (§6);
> - a refresh never widens a tree, and a lowered cap cuts the live over-cap
>   nodes (§6, §11);
> - a refused renewal ends its node and never narrows it (§4);
> - until P1b, a `cnf` subject is exchanged only under its own key (Phasing);
> - an agent type mints no ID-JAG (§4);
> - at `/oauth/token`, the node leg of the identifier API and the CIBA
>   backchannel endpoint, an agent type authenticates by client assertion only
>   with the issuer as its sole `aud` and a `typ` header (§3);
> - every added route names its own rate limit, and a 429 is never a grant
>   (Decision);
> - every owner route runs the management guard, which refuses a tree token
>   (§6);
> - an approval never lifts an operator's ceiling, and a window renews
>   without a token exchange;
> - a refused subject token or spawn assertion at the exchange answers
>   RFC 8693's `invalid_request`, not `invalid_grant`;
> - an agent owner needs a verified address;
> - a transfer needs the recipient's acceptance. The acceptance is the moment
>   of transfer, and its own transaction cuts the agent's live trees (§13,
>   decision 10).
>
> It also drops every power the merged text gave a realm admin, such as
> revoke-by-agent (§13) and decision 11's power to disable a transmitter.
> QAuth has no realm-admin or operator role (ADR-012 §4), so each is the
> owner's alone. And the session owner now reads ancestors' `jkt` and `scope`
> from `GET /api/agent-sessions/{sid}`, not from introspection, because
> introspection authenticates a client and names no user (§2).

## Context

A session's main agent — Claude Code on a developer's machine, an Agent SDK
process, an executor-spawned worker — authenticates to QAuth and receives a
token. That token is the **first gate** on what the agent may do, at an MCP
server and equally at the CLI tools the agent can run (`gh`, `psql`) — on a
host where the model's uid holds no other credential (§9). The agent then
spawns helpers: teammates, sub-agents, one process per task. Today QAuth can
express one thing about that spawn — the RFC 8693 `act` chain of `client_id`
values — and nothing else. The deployment needs five more things:

1. **Recursive, inspectable delegation.** Every agent has its own scope, and
   the record shows from which agent it inherited what. Today `act` carries
   only `sub` (`ActClaim`, `libs/server/jwt/src/types/jwt-service.ts:15`): no
   instance, no parent token, no timestamp.
2. **A hard, cryptographic gate before any judgement.** A write-capable agent
   spawns a read-only agent, and the child cannot write — enforced by the
   token the child holds, not by a hook, a classifier or a model's restraint.
3. **Live observation.** Which agent, in which session, with which scopes, for
   what purpose, did what — as a tree on the dashboard, while it runs.
4. **A durable agent identity with an owner.** Every name this record had for
   an agent is either shared or ephemeral: a `client_id` names a harness
   _type_ (`claude-code`) that every user and every box runs, a `cnf.jkt`
   names a process that dies with it, a `sid` names one grant. Nothing names
   "the agent that belongs to this person", so nothing can be attributed to
   it across sessions, bound to a platform identity, or shown to the public
   with its owner's name on it (§13).
5. **Approval from a distance.** The owner sometimes drives a session from a
   phone, through Claude Code's Remote Control, with no shell and no SSH.
   When an agent hits its ceiling, the owner needs to approve one step from
   there — once, or for a while — without widening what the tree was
   granted (§14).

The CLI leg is designed with Vitrin OS in mind, and vitrin's rules are the
posture adopted here: a scope is a ceiling on what may be asked for, never a
grant; the verifier canonicalises identity, the agent does not assert it;
expiry refreshes and revocation kills; the authorization server is never on
the actuation hot path. The standards cover the grammar of a hop (RFC 8693),
sender constraint (RFC 9449), typed rights (RFC 9396), introspection and
revocation (RFC 7662, RFC 7009), events (RFC 8417, SSF/CAEP), decisions
(AuthZEN 1.0) and, since June 2026, the shape of an agent identity record
(SCIM Agent resource, an individual draft) — and nothing about sessions,
instances, spawn, or a tree. Individual 2026 drafts cover the rest in
overlapping pieces. McGuinness's actor profile gives actor identity and chain
shape. Its companions add actor-signed hop proofs and issuer-signed actor
receipts. His mission, agent-instance and client-instance drafts, and a `cnf`
token-exchange response parameter, sit beside it. Liu gives signed per-hop
records. Niyikiza and Asor give offline attenuation. AAuth defines sub-agents
in its own HTTP-signature protocol. None is adopted by a working group.
QAuth defines the seams itself and says so
([Standards position](#standards-position)).

### What exists today and what this record adds

| Concern           | Today (verified 2026-09-30)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | This record adds                                                                                                                                                                                                                                                        |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Delegation hop    | `handleTokenExchange`, `apps/auth-server/src/app/routes/oauth/token.ts:1291` — confidential-only, gates 1–4c (GATE 3a, since GHSA-6fcx-34r3-24v4, refuses a subject or actor token whose `jti` is on the denylist), `act = { sub: client_id, act? }`, depth ≤ `MAX_DELEGATION_DEPTH` (`apps/auth-server/src/app/helpers/agent-audit.ts:22`), lifetime capped by the subject's remaining life, no refresh token issued                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | A spawn assertion signed by the parent's key, a DPoP proof from the child, an instance thumbprint, and a ledger row per hop                                                                                                                                             |
| Session root      | None. `jti` is `randomUUID()` with no issued-token row in Postgres and no parent link (`libs/server/jwt/src/lib/jwt-service.ts:80`) — it reaches Postgres only as audit metadata when exchange GATE 3a refuses a revoked subject or actor token (`apps/auth-server/src/app/routes/oauth/token.ts:1438`); Redis holds it only as a TTL'd denylist key (and, with hybrid signing on, the PQC sidecar key); no `sid` in non-test code; the browser login session is a Redis record keyed by the signed `__Host-qauth_session` cookie (`apps/auth-server/src/app/helpers/browser-session.ts:33`); the `authorization_code` grant, like `POST /auth/login`, also writes a record into that Redis session store under a fresh `randomUUID()` (`apps/auth-server/src/app/routes/oauth/token.ts:648`), but no response carries its id and nothing reads it back; and the Postgres `sessions` table (`libs/infra/db/src/lib/schema/sessions.ts:7`) is defined but nothing reads or writes it                                                                                                                                                        | `sid` on every agent access token, inherited unchanged by every exchange                                                                                                                                                                                                |
| Instance identity | None. No `cnf`, no DPoP, no mTLS; every agent token is a plain bearer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | DPoP-bound agent tokens (`cnf.jkt`), key held by a local helper                                                                                                                                                                                                         |
| Chain record      | `audit_logs.delegation_chain` (flattened `client_id` list, `libs/infra/db/src/lib/schema/audit.ts:54`); `findByRealmAndActorClientId` has no HTTP caller (`libs/infra/db/src/lib/repositories/audit-logs.repository.ts:218`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | An agent-token ledger keyed by `jti` with `parent_jti` and a stable node id, served by introspection and the dashboard                                                                                                                                                  |
| Introspection     | `POST /oauth/introspect` returns no `act`, `jti` or `token_use` (response built at `apps/auth-server/src/app/routes/oauth/introspect.ts:229`); secret-based client auth only                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `act`, `jti`, `sid`, `token_use`, `cnf`, `authorization_details`, `qauth_delegation`; `private_key_jwt` accepted                                                                                                                                                        |
| Revocation        | Per-`jti` Redis denylist with TTL (`revokeJti`, `apps/auth-server/src/app/helpers/token-revocation.ts:30`), read by `requireJwt`, introspection and, since GHSA-6fcx-34r3-24v4, exchange GATE 3a (`apps/auth-server/src/app/routes/oauth/token.ts:1438`); ownership = `client_id` of the token (`apps/auth-server/src/app/routes/oauth/revoke.ts:164`); `family_id` cascade (refresh tokens only) on RFC 7009 revocation and on reuse (rotation is a compare-and-set since GHSA-c2gj-r6hx-292c, so a lost race counts as reuse); a user's refresh tokens for one client are revoked on consent withdrawal (`apps/auth-server/src/app/helpers/consent-management.ts:95`, since GHSA-6fcx-34r3-24v4); the refresh grant revokes the presented refresh token when its user is disabled (`apps/auth-server/src/app/routes/oauth/token.ts:1037`); a client's refresh tokens and consents are deleted by foreign-key cascade when its developer deletes it (`apps/auth-server/src/app/routes/clients/index.ts:645`); and all of a user's refresh tokens are revoked on `POST /auth/logout` (`apps/auth-server/src/app/routes/auth/logout.ts:79`) | Revocation by `sid` (tree), `jti` (subtree), agent, and user (every tree, decision 1), with cascade; the session owner and any live ancestor node in the tree (by its key) may revoke; the end of a root's refresh family ends its tree; CAEP `session-revoked` emitted |
| Purpose / rights  | RFC 9396 absent; the only reference rejects inbound `authorization_details` on the ID-JAG path (`apps/auth-server/src/app/helpers/id-jag.ts:433`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | One RAR type, narrow-only across hops, returned in introspection                                                                                                                                                                                                        |
| Consent           | `consentPage` has no agent input; `agent:*` renders raw (`apps/auth-server/src/app/routes/ui/consent.ts:138`, `describeScope` in `apps/auth-server/src/app/helpers/consent.ts:114`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | The tree ceiling on the consent screen (§11)                                                                                                                                                                                                                            |
| Resource side     | `McpGuard` validates `iss`/`aud`/`exp`/scope exactly, normalises no `act`/`jti`, emits nothing back (`libs/fastify/plugins/mcp-guard/src/lib/core.ts:78`, `ValidatedToken` in `libs/fastify/plugins/mcp-guard/src/types.ts:31`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `act`/`sid`/`jti` normalised, DPoP verified per resource, optional event emission and online decisions                                                                                                                                                                  |
| Events            | None — no SSF, SET, CAEP or webhooks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | An SSF transmitter (revocation) and an RFC 8935 push endpoint (resource-side and agent-side actions), with a registered-transmitter roster the owner can extend                                                                                                         |
| CLI               | Nothing                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `qauth-broker` (keys, spawn, `git`/`gh`/`psql` credentials), a QAuth-side GitHub STS and a PostgreSQL 18 validator module                                                                                                                                               |
| Agent identity    | None. `oauth_clients.is_agent` is a self-asserted flag on a client registration (`libs/infra/db/src/lib/schema/core.ts:234`); `developer_id` is the only ownership signal and is NULL for every anonymous DCR client ([ADR-012](./012-dynamic-client-ownership.md)); `logo_uri` and `client_uri` are kept in the `metadata` jsonb at registration (`apps/auth-server/src/app/routes/oauth/register.ts:178`; `apps/auth-server/src/app/helpers/cimd.ts:403`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | An `agents` table — a principal with an owner, a name, an avatar and per-platform bindings — served as a SCIM `Agent` resource and a public profile (§13)                                                                                                               |
| Human approval    | None. The only step-up is a fresh browser login during authorization (`evaluateStepUp`, `apps/auth-server/src/app/helpers/step-up.ts:196`); no passkey, TOTP or CIBA code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | A CIBA poll-mode approval request, a passkey-confirmed approval page and a separate elevation leaf for the approved step (§14)                                                                                                                                          |

Two facts in that table shape everything below. GATE 3c requires the subject
token's `aud` to contain the exchanging client's `client_id`
(`apps/auth-server/src/app/routes/oauth/token.ts:1458`), and `resolveAudience`
sets `aud` to the RFC 8707 `resource` when one is present, else the client's
audience allowlist, else the client's own id
(`apps/auth-server/src/app/helpers/client-auth.ts:521`) — so a child with a
distinct `client_id` can exchange only if the root token already named it, and
an MCP client that sends `resource`, as MCP 2026-07-28 requires, gets a root
token that names nobody. And exchange is confidential-only at three layers
(`allowPublic: false` at `apps/auth-server/src/app/routes/oauth/token.ts:204-205`,
DCR refusal at `apps/auth-server/src/app/helpers/dynamic-client-registration.ts:224`,
CIMD drop at `apps/auth-server/src/app/helpers/cimd.ts:368`) — so a child needs
a credential something other than the model holds.

### Threat model

**T1 — Chain splicing.** A compromised intermediary presents a `subject_token`
and an actor identity from different contexts and the STS mints a chain that
never happened (OAuth WG thread, Feb–Mar 2026). Closed at every hop: the spawn
assertion verifies under the subject token's own `cnf.jkt`, hashes the exact
subject token, and names the child's key, which must equal the DPoP proof's.
There is no `actor_token` to splice; GATE 3c stays as the second binding.

**T2 — Key exfiltration via environment.** A model that can run `env` or
`gh auth token` reads any secret placed where the process can. Closed by
custody for per-process keys and node tokens: they live in `qauth-broker`'s
memory behind a unix socket, never on disk or in env. Three credentials
outlive a process on the CLI leg. The GitHub App's private key lives in
QAuth's configuration beside the vend policy and never on the developer box,
so an agent with a shell cannot edit its own ceiling (§9). The other two are
on the box: the agent type's `private_key_jwt` key (or client secret), which
the broker must load from storage — the user keyring or a 0600 file readable
by the broker's uid only — because its public half is operator-provisioned in
the type's `jwks` (§3, §9); and the root refresh token, which the broker keeps
in memory only — a broker restart means a new `login` — and which RFC 9449 §5
leaves bound to client authentication, not to the DPoP key (§3). A same-uid
process that reads both can authenticate as the type and refresh the root
from any host. It mints DPoP-bound tokens under its own key with the same
`sid`, until the user revokes the `sid` or every tree (§6, decision 1). The
broker's next refresh can end it sooner. It presents the token the thief
rotated out, and reuse detection revokes the family and, by §6, the tree
with every node the thief minted. A thief that also stops the broker avoids
that, so explicit revocation stays the bound. A stricter rule is parked as
decision 21. The type key alone buys less. It cannot spawn: GATE 3d needs
the parent's DPoP key, held only in broker memory. Nor can it root a tree by
itself. A `client_credentials` token roots nothing (§1), and a code-grant root
needs the user's signed-in browser and the user's consent (§11). A consent is
not authentication. A same-uid process that opens the request in the user's
browser roots a tree for itself when the user approves the screen, or when a
stored consent skips it (decision 17), because PKCE binds the code to whoever
started the request. To keep such a leak to one box, the operator registers one key per box
in the type's `jwks` with a distinct `kid`, never one key per type. **Not closed
for what the broker vends.** A GitHub installation token is a plain bearer that
`git credential fill` prints to stdout, that the `gh` shim places in the real
`gh`'s `GH_TOKEN` — so `gh auth token` prints it and any pager or editor `gh`
launches inherits it — and the psql leaf sits in libpq inside the model's own
process. The model can read each and replay it from any host, within its
ceiling — the node's `locations` and `actions` (§5, §9) — for GitHub's hour
minus the broker's deletion (§6), or the leaf's lifetime (T3), off the
broker's log; GitHub attributes those uses to the App with no token
identifier. Custody covers only what the broker holds: a `gh auth login`, a
stored git credential, an SSH key or a `.pgpass` already present on the
agent's uid is the user's, not the tree's, and no ceiling here reaches it —
which is why §9 requires that uid to carry no ambient credential. Residual:
the process can still _use_ its key through the broker; and same-uid
isolation is soft — under Yama `ptrace_scope=1` a sibling cannot attach to
the broker or read its memory (where Yama is off, a debugger has its keys and
its refresh token), but it can read any same-uid process's
`/proc/<pid>/environ` (`PTRACE_MODE_READ`, which scope 1 does not restrict),
write to the user's tmux socket, and edit the shim, the git config and the
hooks the parent process will execute, so a same-uid child can make its
parent act; a hard gate between two agents needs two uids or a user namespace
(§12). Sender constraint stops off-host replay of QAuth node
tokens. It stops neither the root refresh path, nor vended bearers, nor
misuse within the ceiling.

**T3 — Replay.** DPoP proofs carry `jti`, `iat`, `htu`, `htm`, `ath` and are
accepted for a bounded window (RFC 9449 §11.1); spawn assertions are
single-use with a 60 s life; leaves are single-audience and short; a GitHub
installation token is cached per node for at most its GitHub hour. Residual:
a leaf replayed inside its lifetime at a resource that does not verify the
proof — PostgreSQL, vitrin, an mcp-guard host with DPoP off — which RFC 9449
§7.2 concedes for any DPoP-unaware resource; the answer is the lifetime (§6).
Vitrin is in that list for its wire alone, bearer-shaped and DPoP-unaware,
not as a CLI resource a scope opens: it is the actuation gate one layer
below QAuth, where `vitrin:observe` and `vitrin:actuate` only cap what an
agent may petition, the grant comes from vitrin's own consent card and
powerbox, and a delivered file descriptor is kernel authority no QAuth
revocation reaches (§10).

**T4 — Confused deputy.** Every agent holds its own token, mcp-guard never
forwards a bearer upstream
(`libs/fastify/plugins/mcp-guard/src/lib/core.ts:10`), and every credential
the broker vends is derived by QAuth from the caller's token — repositories,
permissions and roles intersected with its `authorization_details` on the
server — so neither the broker nor the model can be talked into a credential
wider than the token that asked.

**T5 — AS outage.** Existing tokens verify offline until `exp`; nothing
already vended is torn down; the tree stops growing and the broker vends
nothing new, while a cached installation token carries an in-flight push.
Revocation is fail-open for at most one access-token lifetime and an outage
extends that window — vitrin's WS-D §7.6 says no document may imply otherwise.
The dead-man switch (§6) is the broker's pidfd on the process, not a call to
QAuth.

**T6 — Prompt injection.** A hook can be argued out of; a credential cannot.
A read-only child persuaded to write gets `403 insufficient_scope` from
mcp-guard's exact match (`missingScopes`,
`libs/fastify/plugins/mcp-guard/src/lib/scope.ts:41`), no `contents: write`
from the STS, no writable role from the validator, and cannot forge its
lineage because `caused_by` is written by QAuth (§5). Not closed: actions
_within_ the ceiling, and the free-text `purpose` a model writes about itself,
which is display, never policy. QAuth authenticates a workload, not an
intelligence (vitrin WS-D §7.7(2)).

**T7 — Forged attribution.** Anything an agent writes about itself outside
QAuth is unauthenticated where it lands: a `Co-authored-by` or `Author` line
in a commit, a `QAuth-Session` trailer, a model name, a `purpose`. Anyone can
write any of them into any commit in any repository, and the agent itself can
(T2: a same-uid process edits the hooks that write them). Closed for what
QAuth records and only there: an agent identity is a row QAuth owns (§13), a
node is a key QAuth verified (§3), an action event is a SET whose transmitter
QAuth registered and whose subject `jti` the ledger knows (§7), and a public
profile states what it does and does not attest. Not closed: the world
outside the ledger. A commit that names an agent is a claim until the owner's
record ties its hash to a node (§9, provenance), and a model name is a
harness's report of itself, never something QAuth verified (§7). No surface
in this record presents either as QAuth's word.

**T8 — Approval fatigue.** An agent under prompt injection asks for more
rights again and again, until a tired owner taps yes — the push-bombing
pattern known from MFA. Closed as far as a gate can close it (§14). Asking
needs a scope of its own, which only an operator-seeded agent type can
hold and no approval can grant or extend. A per-`sid` budget caps how
often a node may ask. A mute, or the owner's standing block,
turns further asks into silent denials. The approval page shows the typed
request from QAuth's own records; the model's words appear only in an
attributed box. And an approval covers one delta, for one node, for a bounded
time, and is never passed down. Not closed: an owner who approves what they
should not. The record can make each approval small, specific and costly to
ask for; it cannot make the owner read it.

Not closed either: a platform authenticator on the machine the agent runs on,
unlocked by a PIN or a password (§14, A stated residual).

**T8 as BCP 247's risk assessment.** §14 is a cross-device flow, the
Backchannel-Transferred Session Pattern of RFC 10027 (BCP 247) §3.1.2. Its
§2 asks for a risk assessment and for mitigations chosen from §6.1, and this
is that assessment. The attack is §4.1.2's: requests at an inconvenient
time, in volume, until the user approves to make them stop (Example B9,
§4.3.9). The mitigations:

- limited scopes (§6.1.9): one delta, one resource;
- short-lived tokens (§6.1.10): the leaf's lifetime, and no refresh token;
- rate limits (§6.1.11): the budget, the mute and the block;
- sender-constrained tokens (§6.1.12): `cnf.jkt` is the node's key;
- detect and remediate (§6.1.6): revocation by `sid` or `jti` (§6);
- user experience (§6.1.14): the typed page, with no choice preselected and
  Deny at least as prominent as either approve choice.

§6.1.15 (authenticate, then initiate) holds only by analogy. Filing needs the
node's live, DPoP-bound token as the hint, so an outsider who knows only the
owner's identifier cannot start a request, the CIBA weakness §6.2.2.2 names.
The root login need not be phishing-resistant, and the injected node is what
the budget, the mute and the block are for. `binding_message` is CIBA's own
interlock, not a §6.1 item. Proximity (§6.1.1) is not established, by design:
remote approval exists for an owner who is away, and §2 asks for it only "if
possible".

Same-device approval, by an owner on the machine the agent runs on, is a
stated deviation. §5 says cross-device protocols SHOULD NOT be used for
same-device scenarios. §6.2.2.5, the CIBA guidance that §2 item 3 asks
implementers to follow, says the same. §5 lets an authorization server block
such use when it detects it, and QAuth
cannot detect it. The attachment a client reports is not signed (§14, A stated
residual), and §5 itself warns that a network address misleads behind NAT.
So the page recommends a separate device and says why. For this case §5 asks
that the mitigations above still apply, and they apply to every approval.

The invariant the record exists to make provable: for every child token `c`
with parent `p`, `scope(c) ⊆ scope(p)`, `scope(c) ⊆ registered(type(c))`,
`aud(c) ⊆ aud(p)`, `mode(c) ≤ cap(type(c))`, `exp(c) ≤ exp(p)`,
`rights(c) ⊆ rights(p)`, `depth(c) ≤ 4`, `sid(c) = sid(p)`, `cnf(c)` = the key
that presented the exchange (a leaf that §3's `AGENT_BEARER_LEAF_RESOURCES`
election mints carries no `cnf`), and the exchange was authorised by the
holder of `cnf(p)`. Each is one check at mint; by induction every leaf is
bounded by the root. A code-grant root is bounded by the human's consent
(§11). A root that §1 starts from a sid-less subject or a
NULL-`sid` refresh family passes no §11 screen. The grant behind its subject
token or its refresh family bounds it. At every refresh a root is also
bounded by its type's current `max_agent_mode` (§4). One consequence of
[ADR-007](./007-mcp-first-positioning.md)'s maintainer decision: the modes are
independent scopes and the check is exact set inclusion, so **a parent holding
only `agent:exec` cannot hand out `agent:readonly`**. The root grant carries
the union of the modes the tree may use, each child takes a subset, and the
consent screen shows the union (§11). An elevation (§14) stands outside this
chain on purpose: no exchange derives it, a passkey-confirmed approval of one
delta bounds it instead of a parent, and it can neither spawn nor narrow — so
no child ever holds what it grants. It stands outside the parent bounds only.
For an elevation `e` requested by node `n`, the operator bounds and the
audience bound still hold, and `e` never carries the right to ask:
`scope(e) ⊆ registered(type(n))`, `agent:request ∉ scope(e)`,
`mode(e) ≤ cap(type(n))`, `aud(e) ⊆ aud(n)`, `sid(e) = sid(n)`,
`cnf(e) = cnf(n)` (§14).

## Decision

One switch gates all of it: `AGENT_TREE_ENABLED`, a boolean in the auth env
schema, default **`false`** — the shape `ID_JAG_ENABLED`,
`WALLET_FEDERATION_ENABLED` and `HYBRID_SIGNING_ENABLED` set. When false,
nothing in this record runs: no `sid` is minted, no ledger row is written,
no new gate is evaluated, and the token exchange is byte-for-byte today's,
whatever the seed manifest or any other `AGENT_*` setting says. When true,
P0's behaviour applies to every agent-client mint, and the new exchange
gates, as each phase lands them, run as §4 states. Remote approval (§14) has
a second switch, `AGENT_APPROVAL_ENABLED`, default `false`, which does
nothing unless `AGENT_TREE_ENABLED` is on. The flag also gates the rules this
record adds outside the exchange:

- the consent rules for agent clients (§11);
- the root's stored `aud`, its enrichment, and the rule that a refresh never
  widens it (§11);
- the revoke-all refusals at the `authorization_code` and refresh grants: an
  agent client's code issued before the owner's revoke-all instant, and the
  first refresh of a NULL-`sid` agent family once its user has that instant
  (§6);
- the sign-out rule of decision 1 (§6);
- the walk on `DELETE /api/clients/{id}`, which runs with its ownership check
  and its delete in one transaction (§6);
- the tree walks on the other shipped paths that end a root's refresh family
  (§6);
- the client-assertion rule for agent types (§3);
- the owner-route guard's refusal of `sid` (§6);
- the `agent:request` reservation (§14).

With the flag off, each of those paths is byte-for-byte today's.

**Rate limits.** This record raises no existing limit for agents and adds no
per-host allowance.

- Every route it adds names its own limit, in the phase that lands it. The
  limit is per IP before authentication, plus a per-client, per-transmitter
  or per-`sid` limit inside the handler where it authenticates its caller. No
  added route falls back to the global default (`RATE_LIMIT_MAX`, 100 per
  `RATE_LIMIT_WINDOW` of 3600 s per address), which is the wrong shape for a
  polled route.
- `/oauth/token` keeps its per-IP limit (`TOKEN_RATE_LIMIT`, 30 per
  `TOKEN_RATE_WINDOW` of 60 s in a production realm). Every root refresh,
  re-spawn, narrow and CIBA poll from one address shares it, and so does
  every broker behind one address. At the 300 s lifetime, that limit bounds
  how many tokens one address keeps alive.
- The broker renews early, parent before child, paced under the limit it is
  answered with. Each session's sweep starts at its own offset. The broker
  honours `Retry-After`.
- A 429 mints nothing, and it is not a refused renewal (§4). It is never a
  grant and never a revocation signal; the broker logs it and retries. A
  revocation answered 429 is retried the same way. Until then, the written
  one-lifetime window bounds it.
- The CIBA acknowledgement always carries `interval`, 20 s by default and
  never lower. QAuth answers `slow_down` to a faster poll (CIBA Core 1.0
  §7.3, §11). Without it, CIBA's 5 s default lets the default three pending
  requests poll 36 times a minute, above the token limit.
- Per-IP limits name the real caller only when `TRUST_PROXY` names the
  deployment's reverse proxy (GHSA-4pqf-fmj4-wjgx).

### 1. Session root — `sid` on agent access tokens

Every access token minted to an agent client (`isAgentClient`,
`apps/auth-server/src/app/helpers/client-resolution.ts:94`) from a
human-consented grant carries `sid`. It is an opaque string, unique within
the issuer, and a version 4 UUID from a CSPRNG (`randomUUID()`, as `jti` is;
122 random bits, RFC 9562 §5.4). It is minted once per `authorization_code`
grant and bound to that grant's consent, the one active consent for the
(`user_id`, `oauth_client_id`) pair
(`libs/infra/db/src/lib/schema/consents.ts:40`). The `kind: root` row names
that consent by its `user_id` and `client_id`. So every root of one agent
type that a user holds shares that consent, and withdrawing the consent ends
them all (§6). `sid` is a column on the `refresh_tokens` row, copied on rotation as
`family_id` already is (`libs/infra/db/src/lib/schema/tokens.ts:178`), so a
refreshed token keeps it; every token derived by exchange inherits it
unchanged. The agent the grant names (§13), when it names one, travels the
same way: a nullable `refresh_tokens.agent_id` beside `sid`, copied on
rotation, inherited by every exchange. The ID token issued by the same code
exchange does **not** carry
`sid`: the registered ID-token `sid` (Front-Channel Logout 1.0 §3) identifies a
User-Agent or device session for logout. QAuth's browser login session, the
Redis record behind the `__Host-qauth_session` cookie, is one; this grant
identifier is not, and one browser session may root several grants. Nor is
`sid` the id of the session record the code grant already writes to Redis
(Context table). `sid` is minted apart from it, and P0 neither reuses nor
exposes that id. A `client_credentials` token carries none and cannot root
a tree: exchange already requires an enabled user
(`apps/auth-server/src/app/routes/oauth/token.ts:1474`), so the root of a tree
is always a human `sub`.

**One root per main-agent process.** The broker runs the `authorization_code`
grant when a main agent's `SessionStart` hook registers its harness `session_id`
and pid over the socket (the registration [Harness reality](#harness-reality)
describes for teammates). So one main-agent process holds one `sid`, the
ledger's root row records the harness `session_id`, and the root key is the
one keyed to that process. The broker keeps each root's `session_id` beside
its `sid` and sends it with the code grant's token request. A resumed session
(`--resume`/`--continue`, same `session_id`) reuses its root while the grant's
refresh token lives. The old process's exit fires the dead-man switch. From
P2, when its walk reaches QAuth, it revokes the root, and with it the `sid`
and the refresh family (§6). A session resumed after that runs a new
`login`. So a resume reuses a root only before P2, or when that walk did not
reach QAuth; decision 21 parks this. A second `claude`
process is a second root with its own `sid`. The alternative, one root per
broker start, is parked as decision 8.

`SessionStart` also fires inside a running process: on `/clear`, on compaction,
on a `/resume` inside the session and on some forks (Harness reality). A later
registration from a bound pid roots nothing and runs no `login`, whatever its
`session_id`: the process keeps its root. The broker decides by the pid and the
`session_id`, never by the hook's `source` field, which is only a report. A
stricter rule, under which a root also ends on a new `session_id`, is parked
as decision 21.

The return leg is a native app's (RFC 8252 §7.3). The broker opens the
user's browser on the authorization URL with PKCE `S256` and a `state` it
minted. It listens once on a loopback redirect URI,
`http://127.0.0.1:<port>/callback`, on a port the operating system assigns
for that login. It uses the IP literal rather than `localhost`, which §8.3
says is NOT RECOMMENDED. Before it redeems the code, the broker checks three
things:

- `state` is the one it minted;
- `iss` equals the `issuer` in QAuth's metadata, by simple string comparison
  (RFC 9207 §2.4). QAuth sends `iss` on every authorization response and
  advertises `authorization_response_iss_parameter_supported` (RFC 9207 §3),
  so a response without `iss`, or with another one, is refused, error
  responses included. A client that talks to one server need not check this
  (RFC 9700 §4.4.2); it is the fail-closed choice;
- the response arrived on the exact redirect URI it sent, port included
  (RFC 8252 §8.10).

It then closes the listener (§8.3: open the port for the request, close it on
the response). It exchanges the code as the type's confidential
`private_key_jwt` client, repeating that URI verbatim. The token endpoint
compares it exactly with the URI stored on the code
(`apps/auth-server/src/app/routes/oauth/token.ts:428`).

QAuth matches a registered redirect URI exactly, except for the port of an
`http` loopback URI, which §7.3 says MUST be allowed to vary. It has done so
since 2026-09-26 (PR #415): `redirectUriMatchesRegistered`
(`apps/auth-server/src/app/helpers/oauth-redirect.ts:114`), called at
`apps/auth-server/src/app/routes/oauth/authorize.ts:181` and on the consent
routes. The match is lexical: `127.0.0.1` never matches `localhost` or
`[::1]`. So the type seeds one portless entry, `http://127.0.0.1/callback`
(decision 7). The port authenticates nothing: redeeming a code needs both
that request's PKCE verifier and the type's `private_key_jwt` key.

§7.3 makes trying both IPv4 and IPv6 loopback RECOMMENDED; this record takes
the narrower path.

- A broker that cannot bind `127.0.0.1` refuses `login`. It never falls back
  to `localhost`, `[::1]` or another interface. A host without IPv4 loopback
  needs a dated change to decision 7.
- The listener never sets `SO_REUSEPORT` (RFC 8252 Appendix B.5). Node.js,
  which runs decision 5's default (`apps/qauth-broker`, a TypeScript app),
  sets `SO_REUSEADDR` on every TCP bind on a Unix host: a stated deviation
  from the same appendix. On Linux it still refuses a second bind while the
  broker listens.
- The leg completes only in a browser on the broker's host, or through a
  forward of that login's port. QAuth has no device grant.
  draft-richer-oauth-oob-authcode is watched, not adopted.
- Plain-HTTP loopback passes the environment gate in every profile.
  `development` allows it outright, and `staging` and `production` allow it
  because they require PKCE (`isRedirectUriAllowedForPolicy`,
  `apps/auth-server/src/app/helpers/oauth-redirect.ts:152`).

A subject token with no `sid` — a legacy token, or one issued to a non-agent
client whose `aud` happens to name the agent — is not refused for lacking a
`sid`, nor left sid-less. The exchanged token **starts a new tree** with a
fresh `sid` and a `kind: root` ledger row (§2). That row's `depth` is the
minted token's own
`act` depth. It is at least 1, because the exchange nests the new actor
over the subject's `act`. The row's `origin_jti` and `origin_client_id`
record the subject's `jti` and `client_id`. Refusing would break an
exchange that works today; a sid-less agent token is one no tree can
revoke. The same rule covers any `refresh_tokens` row with a NULL
`sid` whose client is an agent client at that refresh. It covers the row
whether it predates the migration or its client's CIMD document turned
`is_agent` on after the grant. That
`refresh_token` grant mints a `sid` and writes it onto the refresh token the
rotation issues, inside the rotation transaction (§6). It writes a
`kind: root` row for the token it issues. The family joins a tree at its next
refresh rather than staying sid-less until an exchange. Once the user has
used revoke-all, such a family starts no tree, and neither does a sid-less
subject issued before that instant (§6).

**`sid` follows the refresh row, not the client's current `is_agent`.** Since
GHSA-893p-69r3-pw26 a CIMD client is re-resolved through its metadata
document on every use, and its `is_agent` follows the document
(`apps/auth-server/src/app/helpers/cimd.ts:399`). A family that carries a
`sid` keeps it on rotation, and keeps writing a ledger row per mint, after
its client stops being an agent client.

`sid` is the IANA-registered "Session ID" claim (OIDC Front-Channel Logout 1.0
§3; Back-Channel Logout 1.0 §2.4 carries it in the Logout Token; the Standards
table has the rest of its trail). No specification places it in an access
token; this record defines that placement: **the session is the human's
authorization grant to the root agent, not a browser session**. Introspection
returns it as a service-specific member (RFC 7662 §2.2).

### 2. Ledger, not wire — the agent-token ledger

Every mint of a token that carries a `sid` writes one row to a new table,
`agent_token_ledger`, whatever its client's `is_agent` is now (§1). Those are
the mints of the `authorization_code`, `refresh_token` and exchange grants
and, from P5, of the CIBA grant (§14). Every ID-JAG mint from a token that
carries a `sid` writes one row too; an agent type never mints an ID-JAG (§4;
[Explicitly out of scope](#explicitly-out-of-scope)). A `client_credentials`
token (§1) writes nothing. The row's columns are `jti` (key),
`sid`, `realm_id`, `user_id`, `agent_id` (nullable; the principal the tree
roots in, §13, copied from the root row to every descendant), `node_id`,
`parent_node_id` and `parent_jti` (null at the root), `kind` (`root` |
`refresh` | `spawn` | `narrow` | `id-jag` | `elevation`, §14), `origin_jti`
and `origin_client_id` (set only on the `kind: root` row a sid-less subject
started, §1), `session_id` (nullable; the harness `session_id` the broker
sent, set only on a code grant's `kind: root` row, §1), `client_id`,
`instance_jkt`, `scope`, `aud`,
`authorization_details`, `depth`, `spawn_receipt` (the verified spawn
assertion's claims, §4), `approval_receipt`
(the owner's approval of an elevation, §14), `issued_at`, `expires_at`,
`revoked_at`, `revoked_by`, `revoke_reason`. `user_id` is the human who rooted
the tree. For a tree rooted in an agent, that is the agent's owner at root
time, since only the owner may root one (§13). It is never rewritten
(decision 10). `depth` is the length of the `act` chain the mint computed and
capped. It is 0 for a code or refresh root, which carries no `act`, and an
elevation takes its node's depth. Only public identifiers are stored — never a
token, key or secret, the rule `audit_logs` already keeps. `client_id` and
`origin_client_id` are stored values, not foreign keys to `oauth_clients`. So a
client's deletion neither cascades into the ledger nor is blocked by it (§6).
Rows outlive their tokens and are purged by `AGENT_LEDGER_RETENTION_DAYS`
(default 90). **A ledger write failure fails the mint**: a token the ledger
does not know is a token the tree cannot revoke.

A **node** is a process, not a token — or, for the by-type case in
[Harness reality](#harness-reality), a key the session process holds on a
sub-agent type's behalf. `node_id` is a random identifier, never computed
from the thumbprint. It is minted at the first row for a (`sid`,
`instance_jkt`) pair, and that row is the node's anchor (§6). Every later
token under that key in that session — a renewal, a narrowing — joins the
node. So a 300 s renewal is a new row under the same node, and the dashboard
tree and subtree revocation key on nodes. Until §3 lands a node is one token.

Introspection serves the row: `POST /oauth/introspect` adds `act`, `jti`,
`cnf` and `authorization_details` (registered members), the QAuth markers
`sid` and `token_use`, and one service-specific member, **`qauth_delegation`**
— `node_id`, `parent_jti`, `depth`, `revoked`, `agent` (the row's
`agent_id` handle, absent when NULL, §13) and `chain`, a root-first array
of `{ jti, client_id, issued_at }` for a resource caller; ancestors' `jkt` and
`scope` are returned only to a node of the same tree presenting its own
DPoP-bound token (§6), which already holds them (RFC 7662 §2.2 lets the AS
answer each caller differently). Introspection authenticates a client, and a
client names no user, so the session owner reads them from
`GET /api/agent-sessions/{sid}` under the owner-route guard (§6). The name is
vendor-prefixed on purpose: `delegation` is already a registered JWT claim
(OpenID Federation 1.0 §13.6) with unrelated semantics. RFC 8693 §4.1 forbids
using prior actors in access-control decisions; the chain is for audit and
display. Introspection and revocation also start accepting `private_key_jwt`
(`apps/auth-server/src/app/helpers/discovery.ts:147` is secret-only today).
Discovery lists `private_key_jwt` for each endpoint only once that endpoint
accepts it. It lists it together with
`introspection_endpoint_auth_signing_alg_values_supported` and
`revocation_endpoint_auth_signing_alg_values_supported`, taken from
`ASSERTION_SIGNING_ALG_VALUES_SUPPORTED`, the token endpoint's list
(`apps/auth-server/src/app/helpers/discovery.ts:146`). RFC 8414 §2 says each
MUST be present when `private_key_jwt` is listed.

**draft-liu's `delegation_chain` claim is not adopted** (the Alternatives
table has the size, the `wit://` scheme — WIMSE defines `wimse://` and has
asked IANA to register it, WIMSE-ID — and the moving signed-field set); its
own §10.6 names "chain by reference" — a compact token plus introspection —
as the mitigation, and that is this decision. Trigger to
revisit: working-group adoption, or a stable signed-field set. The ledger
holds every field of its record except the two detached signatures, so
emitting the claim later is a serialisation, not a migration.

### 3. Instance identity — DPoP-bound tokens, keys in a helper

Agent tokens are DPoP-bound (RFC 9449) to a per-process key: `cnf.jkt` binds
the token to the process's key, `token_type: DPoP`. Agent types are registered
with `dpop_bound_access_tokens: true`, so a token request without a `DPoP`
header is refused (RFC 9449 §5.2). §5's "regardless of grant type" makes the
exchange grant carry the proof. Only the operator sets that value, in the seed
manifest, as with `max_agent_mode`
(`libs/infra/db/src/scripts/seed-oauth-clients.ts:102`). No registration
writes it. CIMD re-resolution never touches it either. Since
GHSA-893p-69r3-pw26 a CIMD client is re-resolved on every use. A changed
document rewrites only the `set` list of `upsertCimdClient`
(`libs/infra/db/src/lib/repositories/oauth-clients.repository.ts:142`), and an
unchanged one writes nothing (`CIMD_REFRESHED_FIELDS`,
`apps/auth-server/src/app/helpers/client-resolution.ts:125`). No column this
record adds joins either list. The root client is confidential
(`private_key_jwt`), so its refresh token is sender-constrained by client
authentication, not by the key — RFC 9449 §5 says exactly that.

**Client assertions of agent types.** An agent type is a client with
`is_agent` whose operator-set `max_agent_mode` is non-null, which only the
seed manifest writes. With the flag on, an agent type authenticates by client
assertion only when:

- `aud` is QAuth's issuer identifier as its sole value (a string, or an array
  holding exactly that one element); and
- the header carries `typ: client-authentication+jwt`.

Anything else is `invalid_client`, audited. The rule holds at `/oauth/token`,
at the node leg of the identifier API (§6) and at the CIBA backchannel endpoint
(§14). The last two are new endpoints, and they apply it to every client. Every
other client keeps [ADR-011](./011-enterprise-managed-authorization.md) §7's
rule at `/oauth/token`.

The basis is draft-ietf-oauth-rfc7523bis-11 §4, item (b), now in the RFC
Editor queue: for client authentication, `aud` MUST be the issuer identifier
as its sole value. Two departures are deliberate:

- Requiring `typ` goes beyond the same section, which calls rejecting untyped
  JWTs NOT RECOMMENDED. `qauth-broker` is the only presenter of an agent
  type's assertion, and it always types.
- At the CIBA endpoint the rule departs from CIBA Core 1.0 §7.1, which says
  the OP MUST accept its issuer, token endpoint or backchannel endpoint URL.
  It follows the FAPI-CIBA working copy's §4.1.1 note on the issuer as the
  sole audience.

**Node and leaf.** A **node token** — `aud` names an agent type, itself or a
child — can spawn or narrow and is always DPoP-bound. A **leaf token** is
minted by narrowing (§4) with `resource` = one resource and can do neither. A
leaf is DPoP-bound too and carries `cnf.jkt` — except a leaf whose resource is
listed in `AGENT_BEARER_LEAF_RESOURCES` (below), the one election that mints
an unbound leaf — even across a bearer-shaped wire: PostgreSQL's `oauth`
method and vitrin's `hello` never carry a proof, but both are single-scheme,
DPoP-unaware verifiers, which RFC 9449 §7.2 foresees accepting a DPoP-bound
token as a bearer; there `cnf.jkt` is an instance label, not a sender
constraint, and the protection is the short lifetime (§6) and the single
audience — an accepted, stated weakness. The one case
§7.2 forbids is a dual-scheme resource receiving a DPoP-bound token as Bearer:
an mcp-guard host with DPoP verification on, reached by Claude Code's own MCP
client, which sends Bearer only. For exactly those resources the operator
lists the resource identifier in `AGENT_BEARER_LEAF_RESOURCES` (default empty,
operator-set like `ID_JAG_TRUSTED_ISSUERS`) and QAuth exercises §5's election:
their leaves are `token_type: Bearer` without `cnf`, protected by lifetime and
audience alone. The election covers only a leaf minted by narrowing. It never
applies to an elevation leaf (§14), which is always bound to the node's key.
So §14 refuses, before filing, a delta that names a listed resource.
mcp-guard's DPoP verification is a per-resource opt-in; a
resource that opts in is reached through the broker's proxy (§9) or listed.

**The model never touches the key.** Keys are generated and held by
`qauth-broker` (§9), one per agent process, in memory, keyed to the process's
pidfd (§12), never on disk, in env or in a file the model can read —
draft-ietf-wimse-aims-00 §8: the LLM MUST
NOT have access to an agent's credentials. The broker signs proofs and
assertions on request and never returns a private key. A key dies with the
process (§6). The one exception is a by-type sub-agent node
([Harness reality](#harness-reality)): its key is held per (session, agent
type) behind the proxy path and dies with the session process.

`act` adopts the shape of the actor profile
(draft-mcguinness-oauth-actor-profile-00): `iss`, `sub`, `sub_profile` set to
`ai_agent`, and an optional nested `act`. `iss` is QAuth's issuer identifier,
the namespace of `sub`. `sub` is the actor's `client_id`, the value an
RFC 7523 client assertion presented as `actor_token` would yield (actor
profile §6.3.1, §6.3.1.2 step 3; its §14.2 calls `iss` = `sub` = `client_id`
the conformant pattern). Nested `act` is the prior chain, preserved exactly.
The actor profile's §3.2 says `client_id` itself is a client identifier, not
an actor identifier (its §14.7: an auxiliary client-identity signal). The
same section makes the actor identifier the (`act.iss`, `act.sub`) pair,
durable and never a thumbprint (§14.12). Using the `client_id` as `act.sub`
deviates from §14.7's SHOULD: where one `client_id` fronts several acting
instances, the draft wants `act.sub` to name the specific instance. QAuth
keeps the instance in `cnf.jkt` and the ledger node instead. It does so
because §14.12 says `act.sub` SHOULD NOT be key-derived, and the only
per-instance identifier this record mints, `node_id` (§2), is a random ledger
key that stays out of `act`. QAuth never infers an
identifier from a thumbprint — the line
draft-mcguinness-oauth-client-instance-id-00 §5 draws for its receivers
(Alternatives, "One DCR client per agent instance" and "An attested instance
identifier"). Prior actors' thumbprints live in the ledger, not inside
`act`: RFC 8693 §4.1 makes `act` members identity claims only, and the
actor profile defines no per-actor confirmation members in nested `act`
(§3.7). Its receipts companion also keeps `cnf` out of `act`. It can
record a hop's historical `cnf` only in a separately signed receipt, as an
optional member that issuers SHOULD NOT include without a disclosure
review (draft-mcguinness-oauth-actor-receipts-00 §7.2.1, §7.2.2). The
ledger holds that fact instead. The current presenter is the top-level
`cnf` (actor profile §3.7.1). `actClaimSchema`
(`libs/server/jwt/src/lib/access-token-claims.ts:29`) becomes a loose
object requiring `sub` and admitting `iss` and `sub_profile`, so extension
members are ignored rather than stripped (actor profile §3.4).
`sub_profile` and its `ai_agent` value come from draft-mora-oauth-entity-profiles-01 (§4.2,
§3.1.7), which the actor profile cites normatively. If at P1b neither that
draft nor a successor is active, `act` omits `sub_profile` rather than
emit an unregistered value. The member is RECOMMENDED only (actor profile
§3.4), and draft-mora's syntax admits no URI (its §3.3).

### 4. Spawn = RFC 8693 exchange with a parent-signed spawn assertion

A spawn is one `POST /oauth/token` with
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, made by the
broker on the child's behalf: `subject_token` is the parent's token,
`subject_token_type` the access-token URN, and:

- **(a) `DPoP` header** — the child's proof, signed with the child's fresh key.
- **(b) `spawn_assertion`** — a new token-request parameter (RFC 6749 §8.2 is
  the extension point; draft-liu §5.2 adds `delegatee_id` the same way): a JWT
  typed `typ: spawn-assertion+jwt`, token-type identifier
  `https://schemas.qauth.dev/token-type/spawn-assertion`, signed by the
  **parent's** DPoP key with its public key in the `jwk` header: `iss` =
  parent `client_id`, `sub` = child `client_id`, `aud` = QAuth issuer
  identifier as its sole value (draft-ietf-oauth-rfc7523bis-11 §4 item (b),
  by analogy: a spawn assertion is neither a grant nor client
  authentication), `iat`, `exp` ≤ `iat` + 60 s, `jti` (single
  use), `ath` = the hash of the `subject_token` computed as RFC 9449 §4.2
  computes it for a DPoP proof (binding one token instance —
  draft-niyikiza's `par_hash` property), `cnf.jkt` = the child's key
  thumbprint, `scope` = the ceiling the parent grants, `authorization_details`
  = the child's purpose and rights (§5), optional `resource`/`audience`.

The AS adds one gate, **3d**, after GATE 3c and before the enabled-user
check. It lands whole in P1b (Phasing), except its `kind: elevation` check,
which lands in P5 (§14). The denylist half of the revocation check already
ships as GATE 3a
(`apps/auth-server/src/app/routes/oauth/token.ts:1431-1449`, since
GHSA-6fcx-34r3-24v4). GATE 3a refuses, with `invalid_request`, a subject or
actor token whose `jti` is on the RFC 7009 denylist, and an unreadable
denylist fails the exchange closed. 3d adds the rest:

- when the subject has a ledger row, neither that row nor its node is
  revoked (§6), and, from P5, the row is not `kind: elevation` (§14), for a
  spawn and a narrow alike;
- `typ` is exact;
- the header `jwk` thumbprint equals the subject token's `cnf.jkt`, and the
  signature verifies under that key;
- `aud` is the issuer identifier as its sole value;
- the assertion is unexpired, and its lifetime is ≤ 60 s;
- `jti` is unseen (Redis `SET NX EX`, the mechanism of `consumeIdJagJti`,
  `apps/auth-server/src/app/helpers/id-jag.ts:244`); a store that cannot
  record it is an outage, not a 3d refusal (below);
- `ath` matches the presented `subject_token`;
- `sub` equals the authenticated client, and `iss` equals the subject token's
  `client_id`;
- `sub` is in the registered `spawn_allowlist` of the `iss` type (one
  `oauth_clients` lookup by the subject token's `client_id`, operator-set like
  `max_agent_mode`). So the root's `aud` bounds which types the tree may
  contain, and each type's own allowlist bounds what it may spawn, itself
  included. A same-key narrow presents no assertion and never reaches this
  check;
- `cnf.jkt` equals the DPoP proof's key;
- when (`sid`, `cnf.jkt`) already names a node, that node is not revoked,
  its `client_id` is the assertion's `sub`, and its parent node is the
  subject token's. So a revoked node cannot be renewed by the next sweep, and
  two agent types never share a node;
- for every subject that carries a `sid`, bearer or bound: a
  requesting client other than the subject's own `client_id` must be in the
  subject type's `spawn_allowlist`, so `aud` alone never authorises a spawn.

Every 3d refusal is `invalid_request`, audited with its reason — RFC 8693
§2.2.2's code for an invalid request or an invalid or unacceptable subject
token, and the code GATE 3–3c already answer. A DPoP proof that fails
RFC 9449 §4.3 is `invalid_dpop_proof` (RFC 9449 §5). A replay-store outage
is not a refusal (When a renewal is refused, below; T5). The exchange answers
503 with `Retry-After`, is audited, and mints nothing. It fails closed, as
GATE 3a does when its denylist is unreadable. The ledger
check also runs for a legacy bearer subject, where it and the `sid`
allowlist check are the only new parts of 3d. GATE 4d below runs for every
subject, bearer or bound.

The DPoP key is generated per process and is never a key registered in the
type's `jwks`, so no assertion it signs can authenticate the client; the
client-assertion verifier additionally rejects `typ: spawn-assertion+jwt`
and DPoP-proof verification rejects any JWT carrying `sub` or `cnf`, so the
three JWT types the key family produces are disjoint by `typ` and by claim
set, not by `typ` alone (RFC 8725 §3.12). The verified claims
become the row's `spawn_receipt` — the post-hoc proof the OAuth-list thread
distinguishes from cross-validation, and the dashboard's "who authorised this
hop". **A subject token that carries `cnf` cannot be exchanged to a new key
without a spawn assertion**; a DPoP-bound token presented by a party that
cannot prove the holder authorised it is exactly the captured token GATE 3c
exists to stop.

This is **QAuth-defined, not the actor profile's presenter rebind**: §3.7.3
installs a new presenter only through a validated `actor_token` whose own
top-level `sub` names it, and there is no `actor_token` here. The profile's
conformant shape is §6.3.1 — the child's RFC 7523 client assertion as
`actor_token` with `actor_token_type=urn:ietf:params:oauth:token-type:jwt`,
which GATE 2 refuses today
(`apps/auth-server/src/app/routes/oauth/token.ts:1366`) — the future
conformance path, **not adopted** for the reason the Alternatives table gives.

The existing gates all still run and all still narrow: **(c)** GATE 3c and
the 3d allowlist bound the types, as above; **(d)** GATE 4a: scope ⊆
subject scope; GATE 4b: `aud` ⊆ subject `aud`; the lifetime clamp; the
depth cap; rights narrowing (§5). Two new checks run after GATE 4c, on the
effective set `grantedScopes`. That set is the requested scope when the
exchange narrows, and the subject's whole scope when it omits `scope`. Both
refuse with `invalid_scope`: every granted scope ⊆ the assertion's `scope`;
and, as **GATE 4d**, every granted scope ⊆ the child type's registered
`oauth_clients.scopes`. `validateScopes`
(`apps/auth-server/src/app/helpers/client-auth.ts:484`) supplies only the
membership comparison and runs on that set, never on the raw `scope`
parameter, for which it would return an empty list. So a type registered
without `write:*` can never hold it, whatever its parent grants or its
owner approves (§14). GATE 4c gives the same floor for `agent:*` through
the type's current `max_agent_mode` (`enforceAgentScopeCap`,
`apps/auth-server/src/app/routes/oauth/token.ts:1509`), which the refresh
grant has also read since GHSA-6fcx-34r3-24v4
(`apps/auth-server/src/app/routes/oauth/token.ts:1087`).
**(e)** The requesting client is the child's agent type, authenticated with
`private_key_jwt` or a client secret the broker holds; exchange stays
confidential-only. The client credential names the type, not the instance
(§9); the instance is the process, bound by its DPoP key (§3). The minted
token: `sub` = user, `client_id` = child type, `cnf.jkt` = child key, `act`
extended (§3), `sid` inherited, new `jti`, **no refresh token** — the code's
invariant stands, so `exp(c) ≤ exp(p)` holds on the token itself. A node
renews by re-spawn under its parent's current token, with a fresh assertion
for the same key, parent before child, paced under the token endpoint's rate
limit (Decision). The root renews by its refresh token, with at most one
refresh of a root in flight. A refresh under the root's key joins the same
node (§2).

**When a renewal is refused.** A renewal is refused when QAuth answers it
with an OAuth error response (RFC 6749 §5.2, RFC 8693 §2.2.2, RFC 9449 §5).
The one exception is `use_dpop_nonce` (RFC 9449 §8): the broker retries with
the nonce. A 429 or a 5xx is not a refusal. The broker retries after
`Retry-After`, and the node runs to `exp` meanwhile (Decision; T5). The
broker never narrows on its own, and a refused renewal is never a §14
request. A refused re-spawn ends that node: the broker revokes its subtree
(§6) and stops signing for its key. A refused root refresh ends the tree: the
broker revokes the `sid`. The next login roots a new tree under the current
ceiling. Two causes are worth naming. An operator
who lowers a type's `max_agent_mode` makes the next over-cap refresh or
re-spawn fail (§6 also cuts the live over-cap nodes). And a retry after a
lost response presents a rotated token. Reuse detection revokes the family
and, by §6, the tree. Since GHSA-c2gj-r6hx-292c, so does a second concurrent
refresh of one root, which loses the compare-and-set.

**Narrow versus spawn.** A **self-narrowing** — same client _and same key_,
deriving a single-audience leaf — is `kind: narrow`: the DPoP proof under the
subject token's own key is the possession proof (actor profile §3.7.2,
presenter continuation), no assertion is needed, `act` is preserved exactly
(§3.6.3.2, so a leaf spends no depth), and a ledger row is written all the
same. **Same-type children.** Claude Code spawning a teammate is a child whose
`client_id` equals its parent's: a full hop, `iss` = `sub` in the assertion,
allowed only when the type's own `spawn_allowlist` names itself (GATE 3d) —
its `client_id` is always in `aud` for the narrow, so 3c alone would not gate
it — a new key, `act` nested one deeper, depth counted. A spawn's
`audience`/`resource` names the child's own `client_id`, the types it may
itself spawn and the resources it may reach, all ⊆ the parent's `aud` (GATE
4b). The child's effective audience is the requested `resource`/`audience`,
or the parent's whole `aud` when the spawn names none. Every agent type in it
other than the child's own `client_id` must be in the child type's
`spawn_allowlist`, else `invalid_target`. In practice every spawn names its
audience.

**An agent type mints no ID-JAG.** An ID-JAG mint is a token exchange
(`mintingIdJag`, `apps/auth-server/src/app/routes/oauth/token.ts:1343`). Its
target allowlist is the client's `audience` column (`idJagTargetAllowlist`,
`apps/auth-server/src/app/routes/oauth/token.ts:1682`). That column also gives
a root without `resource` its `aud`, and in P0 it carries an agent type's
child types (Phasing). So with the flag on, GATE 2 refuses an exchange whose
`requested_token_type` is the ID-JAG URN when the requesting client is an
agent type (§3). It answers `invalid_request`, audited, as GATE 2 already
answers an unsupported `requested_token_type`
(`apps/auth-server/src/app/routes/oauth/token.ts:1359`). No assertion is
minted and no ledger row is written. The refusal holds in every phase of this
record. P1b takes child types out of `audience`, but the column still sets a
root's `aud`, so an ID-JAG target listed there would sit in every root token.
Lifting the refusal needs a later dated change that gives ID-JAG targets a
column of their own. With the flag off the mint is today's. With it on, this
refusal spares every client that is not an agent type. That client's
assertion carries today's claims, with no `act` and no `sid` (Explicitly out
of scope). Like any other exchange, its mint writes §2's `kind: id-jag` row
from a `sid`-carrying subject, and from P1b GATE 3d and GATE 4d apply to it
(above).

### 5. Purpose — one RFC 9396 type, narrow-only

QAuth's first RAR support is one type, `https://schemas.qauth.dev/agent-task`,
carried in `authorization_details` on the authorization request (root), in
the spawn assertion (child), in the token response (RFC 9396 §7), in the JWT
filtered to the audience (§9.1) and in introspection (§9.2):

```json
{
  "type": "https://schemas.qauth.dev/agent-task",
  "purpose": "Open the release PR",
  "task": "pr-open",
  "caused_by": "<parent jti, written by QAuth>",
  "locations": ["https://github.com/qauth-labs/qauth"],
  "actions": ["contents:read", "pull_requests:write"]
}
```

`purpose` and `task` are recorded, displayed and never evaluated. Both are
client-authored at the root and model-authored at every hop, so they are
data, never markup or policy (RFC 9396 §12: the AS MUST sanitise
`authorization_details` against injection). The type bounds them: `task` ≤ 64
bytes matching `^[a-z0-9][a-z0-9-]*$`; `purpose` ≤ 200 bytes of printable
Unicode (NFC, no C0/C1 controls, no bidi overrides); anything else is a field
with an invalid value for the type and is refused with
`invalid_authorization_details` (RFC 9396 §5). Every render escapes them —
the consent page through the `html` tag that already guards the client name
and homepage (#112, `apps/auth-server/src/app/routes/ui/consent.ts:194`), the
dashboard the same way — and the consent page shows `purpose` in a box
attributed to the client ("The application says: …"), below the operator's
scope descriptions, never inline with them. Logs write both as JSON string
values, never interpolated into a line. `caused_by` is **written by QAuth**
— the parent's `jti`, absent at the root — and a client-supplied value is
rejected with `invalid_authorization_details`, so a hijacked child cannot
write a parent it likes into its own row. `locations`
and `actions` are RFC 9396 §2.2 common fields, sets of exact strings, and a
child may request only a subset of its parent's —
`invalid_authorization_details` otherwise (§6). RFC 9396 defines no comparison
algorithm (§6.1); this type defines set inclusion by exact match and nothing
cleverer. Every other `type` is rejected, not ignored —
[ADR-011](./011-enterprise-managed-authorization.md) gate 15's posture — and
the ID-JAG consume path keeps refusing `authorization_details` outright.
`authorization_details_types_supported` joins AS and resource metadata.

### 6. Revocation — by `sid` and by `jti`, cascading, with a written window

Revocation walks the ledger: revoking a `jti` marks its node and every
descendant node `revoked_at` and writes each live `jti` into the existing Redis
denylist with its remaining TTL (`revokeJti`), so the hot path — `isJtiRevoked`
on `requireJwt` (`apps/auth-server/src/app/app.ts:330`), introspection and
exchange GATE 3a (`apps/auth-server/src/app/routes/oauth/token.ts:1438`) —
stays a Redis lookup.

**The walk and a mint must not race.** A mint these rules refuse answers
`invalid_request` on the exchange (RFC 8693 §2.2.2) and `invalid_grant` on
the `authorization_code`, refresh and CIBA grants (RFC 6749 §5.2).

- A node's revocation lives on its **anchor row**, the row that minted its
  `node_id`. For the root node, that is the `kind: root` row. A node is
  revoked when its anchor carries `revoked_at`. Every row of a revoked node is
  inactive at introspection and at GATE 3d, whatever its own column says.
- A mint that starts a `sid` locks nothing, since no walk can name that `sid`
  yet. These are the `authorization_code` grant, an exchange of a sid-less
  subject (§1), and the first refresh of a NULL-`sid` family. Each still
  reads the owner's revoke-all instant and refuses what it covers (below).
  Such a refusal is audited, issues no token, and writes no `sid` and no
  ledger row.
- Every other mint runs in one transaction. It first locks, with
  `SELECT ... FOR UPDATE`, the anchor of each existing node it touches,
  parent first. Those are the parent node a spawn hangs under, and the node a
  renewal, a narrow, an elevation or a root refresh joins. It refuses when
  either is revoked, or when the tree's `kind: root` row was issued before
  the owner's revoke-all instant (below). It writes its ledger row before it
  commits.
- The walk runs in one transaction and marks top-down. For each node it
  marks the anchor first, the node's other rows in a later statement, and
  only then reads the node's children. So a mint that holds an anchor lock
  either commits before the mark, and its row is marked with its node or
  found as a child, or it reads the mark and refuses.
- **The refresh grant writes inside its rotation.** Rotation is one
  transaction, and since GHSA-c2gj-r6hx-292c it is a compare-and-set
  (`revokeIfActive`, `apps/auth-server/src/app/routes/oauth/token.ts:1151`).
  For a family that carries a `sid` the order is fixed: the root anchor lock,
  then the compare-and-set, then the writes. The writes are the new refresh
  token's `sid` and `agent_id`, and the mint's ledger row, keyed by a `jti`
  fixed before the transaction. The access token
  is signed after the commit. A ledger write failure rolls the whole rotation
  back, so the presented refresh token stays usable. A request that loses the
  compare-and-set writes no ledger row.
- Revocation by `sid`, or of the root node's `jti`, marks the root's anchor
  before it revokes the refresh family. A rotation that committed first has
  its new refresh token revoked with the family; one that waited reads the
  mark and refuses.

GATE 3a already refuses a denylisted parent at the exchange. The
`revoked_at` check GATE 3d adds (§4) and this lock are what stop a revoked
parent between the ledger commit and the denylist write, or after a failed
write.

Denylist writes run after the ledger transaction commits.
If any `revokeJti` write fails, the request answers 503 with `Retry-After`
(RFC 7009 §2.2.1: the client "must assume the token still exists and may
retry"), and a repair job replays the denylist from rows whose `revoked_at`
is set and `expires_at` is in the future; the ledger, not Redis, is the
source of truth. Introspection reports `active: false` when the row carries
`revoked_at`, whether or not the denylist has caught up. Revoking a `sid`
revokes the root, its whole tree and the refresh-token family the grant
issued. Revoking the root node's `jti` is revocation of its `sid`: the refresh
family goes with it, so the root cannot refresh into the same node. RFC 7009
§2.1 explicitly permits a policy-defined cascade to "related tokens and the
underlying authorization grant"; this is that cascade.

**The end of a root's refresh family ends its tree.** When a refresh family
that carries a `sid` is revoked, the walk revokes that `sid` too. The rule
keys on the family being revoked, not on a list of events, so a path added
later is covered. A family counts as revoked when a write leaves it with no
live refresh token, whether that write marks the whole family or one row.
The only exception is a rotation's compare-and-set, which inserts the
successor in the same transaction. Five shipped paths end such a family, and
sign-out is a sixth, within the limits that "Sign-out spares agent trees"
sets below. The shipped five:

- its own client revokes one of its refresh tokens over RFC 7009
  (`apps/auth-server/src/app/routes/oauth/revoke.ts:140`);
- the user withdraws consent at `/consents` or `/api/consents`. Since
  GHSA-6fcx-34r3-24v4 that revokes, in one transaction, every refresh token
  the user holds for that client (`revokeConsentForUser`,
  `apps/auth-server/src/app/helpers/consent-management.ts:66`). The walk runs
  inside that transaction, over every live `sid` whose `kind: root` row names
  that user and names that client as `client_id` or `origin_client_id`;
- reuse detection (`rejectRefreshTokenReplay`,
  `apps/auth-server/src/app/routes/oauth/token.ts:879`): a revoked refresh
  token presented again or, since GHSA-c2gj-r6hx-292c, a rotation that loses
  the compare-and-set. RFC 9700 §4.14.2 treats that presentation as the sign
  of a breach;
- a refresh presented after its user was disabled. The refresh grant
  revokes the presented token with reason `user_disabled`
  (`apps/auth-server/src/app/routes/oauth/token.ts:1037`). Rotation leaves
  a family at most one live token, so this single-row revoke ends it. For
  a row that carries a `sid`, that revoke and the walk run in one
  transaction, which takes the root anchor lock first, as a rotation does;
- its developer deletes the client (`DELETE /api/clients/{id}`,
  `apps/auth-server/src/app/routes/clients/index.ts:645`). The foreign keys
  then delete every refresh token and every consent of the client
  (`libs/infra/db/src/lib/schema/tokens.ts:169`,
  `libs/infra/db/src/lib/schema/consents.ts:29`). This record gives the route
  a walk of its own, keyed on the client rather than on a family's
  revocation. A DCR client registered with a developer's management token is
  developer-owned (`apps/auth-server/src/app/routes/oauth/register.ts:143`),
  and it may assert `is_agent`, so this path is reachable. A seeded agent type has no
  `developer_id`, so this path never reaches one. With the flag on, the
  route runs the ownership check, the walk and the delete in one
  transaction, the walk first. The delete withdraws every user's consent at
  once, so the walk covers every live `sid` whose `kind: root` row names that
  client as `client_id` or `origin_client_id`, for every user. It also covers
  every live node whose row names that client as `client_id`, with its
  subtree. Like revocation by `sid`, it marks each root's anchor first, so a
  racing rotation ends as it does there. A walk failure rolls the delete
  back, so the client is never gone while its trees live.

Each of these marks the ledger with the family's own reason and writes the
denylist after commit, under the 503-and-repair rule above. A client's
deletion leaves no family row to carry a reason, so its walk uses
`client_deleted`. Each emits CAEP `session-revoked`, with `initiating_entity`
`user` for consent withdrawal and for sign-out, `admin` for a client's
deletion and `system` otherwise, and a `reason_admin` naming the cause.

**Sign-out spares agent trees (decision 1).** Today `POST /auth/logout`,
which the developer portal's sign-out calls, revokes every refresh token of
the user (`apps/auth-server/src/app/routes/auth/logout.ts:79`). From P2, with
the flag on, that sweep leaves a refresh token only when its row carries a
`sid` and its client's stored `is_agent` is true. So a sign-out ends no tree
of an agent client. The record adds two limits of its own, each the
fail-closed choice rather than the maintainer's:

- a family that carries a `sid` but whose client is no longer an agent
  client (§1) is revoked as today. For such a family the sweep and the walk
  run in one transaction, which takes the root anchor lock first, as a
  rotation does. The rule above then ends its tree;
- an agent client's family with a NULL `sid` is not yet a tree (§1), and
  sign-out revokes it as today.

The exemption lands together with revoke-all, never before it. With the flag
off nothing changes.

**Revoke all.** The owner's kill switch is
`POST /api/agent-sessions/revoke-all`, an owner route (below). In one
transaction it:

1. sets the caller's `agent_trees_revoked_before` instant to now;
2. revokes every live refresh token of the caller whose row has a NULL `sid`
   and whose client's stored `is_agent` is true: a family its next refresh
   would root (§1);
3. walks, with the cascade above, every live `kind: root` row whose `user_id`
   is the caller, revoking each tree and its refresh family.

After the commit it writes the denylist and emits one CAEP `session-revoked`
per `sid`, `initiating_entity` `user`. Every mint in a tree, introspection,
the STS and the CIBA grant treat a tree whose `kind: root` row was issued
before that instant as revoked. So a mint that races the walk fails. An
agent client's code or a sid-less subject issued before the instant starts no
tree either: its mint is refused (above). Nor, by the record's own
fail-closed rule, does a NULL-`sid` family once its user has a revoke-all
instant, whenever the family was issued: its first refresh as an agent
client is refused (above). That covers a CIMD client whose document sets
`is_agent` only after the revoke-all. A new tree needs a new code grant.
Revocation only removes authority, so the method asks for no second factor
(decision 19).

**A lowered cap.** The seed tool run with `--rotate` is the only writer of
`max_agent_mode` and `is_agent` on a seeded type. When it lowers a type's
`max_agent_mode` or clears its `is_agent`, it revokes by the walk every live
node of that type whose `scope` holds a mode above the new cap. Clearing
`is_agent` counts every `agent:*` mode as above it. Each such node goes with
its subtree, and the repair job writes the denylist. A cap changed any other
way gets only the per-mint check, which ends an over-cap node at its next
renewal (§4, "When a renewal is refused"). Until then the node keeps working,
for up to one lifetime.

Who may revoke, and how: the token's own client over `POST /oauth/revoke`
(RFC 7009, unchanged, now cascading); the **session owner** (the ledger row's
`user_id`, from the portal, under the owner-route guard below) and a **live
node of the same tree** over a QAuth-defined identifier API,
`POST /api/agent-sessions/{sid}/revoke` and
`POST /api/agent-tokens/{jti}/revoke` — RFC 7009 takes the token string, not
an identifier, and a parent never holds its child's token, so no RFC 7009
request can cut a subtree. Over the identifier API a node proves its place
by authenticating as its agent type _and_ presenting one of its own
unrevoked DPoP-bound node tokens for the same `sid` with a DPoP proof; the
target must be that node or a descendant of it (`sid` revocation requires the
root node, the row whose `instance_jkt` is the root's). Client authentication
alone never suffices: a `client_id` names a type (`claude-code`) shared by
every user and every box of that type, so the rule at
`apps/auth-server/src/app/routes/oauth/revoke.ts:164` — today only the agent
named on the token can revoke it, by `client_id` — cannot be carried over to
identifier-keyed revocation without letting any instance of the type kill
any user's tree. `sid` and `jti` are public (§2) and confer nothing. Foreign
identifiers, identifiers outside the caller's subtree and a same-type tree
whose keys the caller does not hold answer 200 and revoke nothing.

**Every owner route runs the management guard.** Each owner-facing route this
record adds runs `createRequireManagementJwt`
(`apps/auth-server/src/app/helpers/management-token.ts:65`), never
`requireJwt` alone. Since GHSA-c863-7xrr-ww9v that guard
(`assertManagementToken`,
`apps/auth-server/src/app/helpers/management-token.ts:34`) admits a token
only when all three hold: its `client_id` is the system client, its `aud`
covers that client's audience, and it carries no `act`. With the flag on it
also refuses a token that carries `sid`.

Every tree token carries `sub` = the owner, so `requireJwt` alone would admit
a node. A root token fails the guard by its `client_id` and its `sid`, and a
descendant also by its `act`. Each route touches only rows whose `user_id` or
`owner_user_id` is the token's `sub`. There are two exceptions. Accepting a
transfer is authorised only by an open offer that names the token's `sub`,
and only while the offering user still owns the agent (§13). Its transaction
then writes rows that carry the previous owner, as §13 (Transfer) sets.
Removing a standing block that names an agent is authorised only by that
agent's current `owner_user_id` (§14, step 4). A foreign identifier answers
404 on a read, and 200 with nothing revoked on a revocation. The routes are:

- `GET /api/agent-sessions`, `/{sid}` and `/{sid}/events`;
- the owner leg of the two identifier routes;
- `POST /api/agent-sessions/revoke-all` and `POST /api/agents/{id}/revoke`
  (§13);
- writes to agents, bindings and `agent_transmitters`, and making,
  withdrawing and accepting a transfer offer (§7, §13);
- ending an approval window, removing a standing block, and registering
  notification channels (§14);
- `GET /scim/v2/Agents` (§13).

No tree token ever authenticates passkey registration or the approval page
(§14).

On the two identifier routes the `Authorization` scheme picks the leg.
`Bearer` is the owner leg, under the guard. `DPoP` (RFC 9449 §7.1) is the
node leg. There the node authenticates as its agent type with the credential
in the request body, because `Authorization` carries a single credential
(RFC 9110 §11.6.2), and under §3's client-assertion rule. A request that
mixes the legs is refused.

The revocation window equals the access-token lifetime, so that lifetime is a
policy parameter: a profile row consulted through `resolveEnvironmentPolicy`
(`apps/auth-server/src/app/helpers/environment-policy.ts:248`),
[ADR-008](./008-environment-aware-authorization.md) style —
`agentAccessTokenLifespan`, **300 s** in `production` and `staging`, 900 s in
`development` — applied to every token in a tree, root included, still capped
by the subject's remaining life; the 900 s `ACCESS_TOKEN_LIFESPAN` and 8 h
`DEV_ACCESS_TOKEN_LIFESPAN` are for humans' apps. A vitrin-audience leaf is
300 s in every environment, because that number is vitrin's written window.

QAuth emits CAEP `session-revoked`
(`https://schemas.openid.net/secevent/caep/event-type/session-revoked`) as an
SSF 1.0 transmitter — `/.well-known/ssf-configuration`, streams per SSF §8.1.1,
push delivery (RFC 8935) for receivers that serve an endpoint and poll
delivery (RFC 8936) for those that cannot, the broker among them — with
`event_timestamp`, `initiating_entity` (`user`
| `admin` | `system`) and `reason_admin`. For a tree the subject is an SSF §3.3
`complex` subject whose `session` member is `{ "format": "opaque", "id": "<sid>" }`
and whose `user` member is `iss_sub` — RFC 9493 §5 forbids a format from saying
what kind of thing it names; the `session` member is the registered way. For a
subtree the subject is `jwt_id` `{ iss, jti }` naming the token at the
subtree's root, a QAuth reading of the event for a partial session, stated as
such. Receivers use it to shorten the window; nothing depends on it. The
broker, a local daemon behind whatever NAT the developer box sits on, serves
no push endpoint: it polls its stream (RFC 8936) and, poll or not, learns a
revocation from its own traffic — a renewal re-spawn (§4) or a vend (§9)
refused for a revoked row — within one lifetime.

**The dead-man switch** is not QAuth's and is not a connection: no process on
the CLI leg holds one — hooks, the `gh` shim, the git helper and
`headersHelper` are one-call processes. It is a pidfd: at binding the broker
holds a `pidfd_open` on the node's pid (§12; Harness reality has each node
kind's registration). The pidfd turning readable is the node's death — exit
or kill, however delivered — on which the broker revokes the subtree (a
ledger walk, if QAuth is reachable, under the node's key or its parent's
before discarding it; if QAuth is unreachable then, the subtree runs to its
lifetime, the fail-open window already named) and, reachable or not, stops
signing for that key and deletes every GitHub installation token it cached
for the node (`DELETE /installation/token`). Same rule as vitrin's
`while_running`, on process liveness instead of a wire. Honest limit: when
the broker itself dies — crash, `kill -9`, reboot — nothing is revoked and
nothing is deleted until expiry: QAuth leaves 300 s, installation tokens the
rest of their GitHub hour. The broker keeps its live `sid`s (identifiers, not
secrets) in `$XDG_STATE_HOME/qauth-broker/sids` and names them on its next
start; with its keys gone it cannot cut them itself (type authentication
alone revokes nothing, above), so the session owner's revoke-by-`sid`, or
revoke-all, from the portal is the remedy.

### 7. Telemetry — action events into QAuth, from resources and from the agent's own side

QAuth exposes an RFC 8935 push endpoint, `POST /events/push`, accepting SETs
(RFC 8417, `typ: secevent+jwt`) signed by registered transmitters — an
mcp-guard host as a resource client, the broker as the type of the node whose
action it reports (signing with that type's registered key), a validator —
each an `oauth_clients` row whose `jwks` verifies its SETs. SSF stream
management is not required inbound in the first slice; RFC 8935 stands alone
and SSF layers on later. One event type,
`https://schemas.qauth.dev/secevent/agent-action`, with members `action`,
`resource`, `decision` and optional `tool`, `arguments_digest`, `outcome`;
`toe` and `txn` are top-level SET claims (RFC 8417 §2.2), `txn` correlating
the SETs of one tool call; the subject is `sub_id` in the `jwt_id` format
naming `iss` and `jti` (SSF 1.0 §3.5). The endpoint verifies the SET, then
looks the subject `jti` up in `agent_token_ledger`. It refuses (400, one
audit line) unless the row's `aud` contains an identifier the transmitter is
registered to report for: its own `client_id` for the broker, or, for an
mcp-guard host or a validator, a resource identifier listed in
`event_audiences` on its `oauth_clients` row. So a transmitter may report
only on tokens minted for it, and an unknown `jti` is refused the same way.
The endpoint never reads the token itself. `event_audiences` holds RFC 8707
resource identifiers in the form `AGENT_BEARER_LEAF_RESOURCES` uses. The two
lists are set independently, and a resource may report whether or not
`AGENT_BEARER_LEAF_RESOURCES` lists it. On `oauth_clients`,
`event_audiences` is seed manifest only, never DCR, CIMD or the developer
API. A database CHECK holds that line from P3. A non-empty `event_audiences`
may appear only on a row with `is_agent` false, no `dynamic_registered_at`,
no `developer_id`, and a `metadata.registrationType` that is neither
`dynamic` nor `cimd`. The rows that carry the column are resource clients,
and the broker reports only under its own `client_id`. `agent_actions` is
keyed by the SET's `jti` scoped to the transmitter (RFC 8417 §2.2: unique
within a feed; a duplicate is acknowledged and dropped), records the
transmitter (its `client_id`, or for an agent-side one its
`agent_transmitters` row, below), and is indexed by the subject `jti`; a SET
whose `iat` is older than `AGENT_EVENT_WINDOW` (default 300 s) is refused.
Emission is asynchronous and best-effort. The dashboard's tree is the ledger
joined with these rows, streamed live from the portal
(`GET /api/agent-sessions`, `GET /api/agent-sessions/{sid}` and
`/{sid}/events` over server-sent events).

**Agent-side transmitters.** The roster above is the operator's. An agent's
owner (§13) runs things beside the harness that see what the resource never
does — a loopback proxy that knows which model actually served a request, a
runtime that knows why a step was taken, a git hook that knows which commits
left the box — and QAuth takes their events on the same endpoint under the
same rule, with two additions. First, the owner, not only the operator, may
register a transmitter. It is an `agent_transmitters` row keyed by the
`agents` row it reports for. The row holds a `jwks`, the `event_audiences`
it may name and the `user_id` of the owner who registered it. That
`user_id` is never rewritten (decision 10). The row is created through the
owner's portal or the developer API, under the owner-route guard (§6). The
registering owner must have a verified address (§13), and the same
ownership check ADR-012 uses for clients applies. The owner is the
responsible party for what it sends. Second, the subject check is widened by
one hop. An agent-side SET is accepted when the subject `jti`'s ledger row
belongs to a tree whose root `agent_id` is the transmitter's agent. The
row's `user_id` must also be the transmitter row's `user_id`, so a
transmitter reports only on trees its own owner rooted. The SET is refused
(400, one audit line, nothing stored) for any other `jti`, including one in
a tree an earlier owner of the agent rooted (§13). An accepted SET is still
a claim: every member an agent-side transmitter writes lands in
`agent_actions` with `source: agent`, is shown apart from the other rows,
and is never an input to §8. `agent_actions.source` is one of `resource` (an
mcp-guard host or a validator), `broker` (the broker's vends and its push
report, §9, signed as the harness type from the operator's roster) and `agent`
(an owner-registered transmitter); the dashboard labels all three. A
`source: agent` row references the `agent_transmitters` row it came through
(`onDelete: 'restrict'`), so a transmitter row that events name is never
deleted. A transmitter row also holds `disabled_at`, NULL while it is live.
Its owner may disable it (decision 11), and a transfer disables it (§13).
Nothing clears `disabled_at`; a new transmitter is a new registration. A SET
signed by a disabled transmitter is refused (400, one audit line) and stores
nothing. The portal shows a transmitter's owner from the row's own `user_id`,
never from `agents.owner_user_id`.

Registration is by out-of-band exchange of the transmitter's
public keys and the push URL — RFC 8935 alone. SSF stream management (SSF 1.0
§7, §8) is receiver-initiated: the receiver reads the transmitter's
`/.well-known/ssf-configuration` and creates the stream there, which a
daemon on a laptop behind NAT cannot serve. A transmitter-initiated
registration and an `agent-action` event type are what QAuth would take to
the Shared Signals WG, which is extending SSF and CAEP toward agentic use
cases; until either exists the out-of-band row is the mechanism, and the
event URI stays QAuth's.

**The agent on a stored row, and the members that name a model.** Every
`agent_actions` row gains `agent_id` and `user_id` columns that QAuth fills from
the subject `jti`'s ledger row; `user_id` is the tree's owner at the time, never
rewritten by a transfer (decision 10). Neither is an event-type member, and a
SET that carries an `agent` member is refused (the `caused_by` rule, §5). Two
optional members join the event type. `model` — the model identifier the
transmitter reports for the request the action came from, a string ≤ 128
bytes matching `^[A-Za-z0-9._:/-]+$`, bounded like `task` (§5). `reason` —
the transmitter's free text for why the step was taken, bounded exactly as
`purpose` is (§5, ≤ 200 bytes of printable Unicode) and rendered exactly as
`purpose` is: escaped, in a box attributed to the transmitter, never inline.
`model` and `reason` are recorded, displayed and never evaluated (T6, T7): a
model name reaches QAuth only as a harness's or proxy's report of itself —
the harness hooks expose a model only at session start and on a switch, and
a loopback proxy sees the model on the wire — and QAuth has no way to check
it. The dashboard shows them under "reported by the agent", beside and never
inside the ledger's "verified" column, and introspection never returns them.
The one model fact QAuth does hold is which agent _type_ minted the token,
which is the `client_id` and always was.

### 8. Decision API — AuthZEN 1.0, off the hot path

QAuth exposes an OpenID AuthZEN 1.0 evaluation endpoint,
`POST /access/v1/evaluation` (and `/access/v1/evaluations` boxcar), discovered
at `/.well-known/authzen-configuration` (§9.2, §10.1), PEPs authenticated as
QAuth clients (§11.2). Requests follow the COAZ-MCP binding's default
`tools/call` mapping (§7.1): `subject` is `type: identity` with `id` the
token's `sub`, `context.agent` the token's `client_id` — the binding's §11.2
puts the agent in context so user and agent trust are evaluated independently
— and a QAuth property `context.qauth` carries `sid`, `jti`, `jkt`, `act` and
`depth`, filled from the ledger when only `jti` is supplied.

The fast path stays offline: mcp-guard, the validator and the broker decide on
claims. Where an operator configures a PDP, the broker asks at vend time,
mcp-guard optionally per tool call, and harness hooks as advice; a PDP can
only refuse what the claims would allow, never allow what they refuse —
enforced at QAuth: the evaluation endpoint first evaluates the claim ceiling
from the ledger row (`scope`, `aud`, `authorization_details`, `revoked_at`)
and answers `false` when the claims refuse, whatever the policy says, so a
PEP that forgets to check the claims cannot be widened by the PDP. PDP
unreachable ⇒ existing credentials run to expiry, new vends refuse. AuthZEN's
Access Request and Approval Profile (ARAP, Draft 1) is the shape of a requestable
denial: a `false` decision carrying `context.access_request` (§7), and an
approval that expires at `approved_until` (§12). It leaves binding an
approval to OAuth token issuance to a profile. The AuthZEN WG's Access
Request OAuth Profile (Draft 1, an unpublished editor's draft) is drafting
that profile, with three transports, and §14 follows its CIBA binding
(Alternatives, "Defer the refused exchange"). The evaluation endpoint does
not return `context.access_request` yet.

QAuth asks no PDP at the spawn: GATE 3d and 4a–4d decide it on claims. The
AuthZEN WG's token issuance profile (Draft 1, 4 September 2026) and token
exchange binding (Draft 1, 2 September 2026) now define that decision point,
with the AS as the PEP. If QAuth ever adds a PDP there, it follows that
binding:

- the PDP is asked only after QAuth's own gates;
- it can only refuse, and a denial refuses the whole spawn;
- an unreachable PDP or a malformed answer means no token.

Nothing is adopted now.

### 9. CLI — `qauth-broker` and a QAuth-side STS; the credential is the gate

`qauth-broker` is a local daemon on `$XDG_RUNTIME_DIR/qauth-broker.sock`: the
OAuth client role for the CLI leg — it holds the client credentials
(`private_key_jwt` key or secret) of every agent type that host runs and
authenticates to QAuth as the type of the node it is acting for, the
session's main-agent type at the root, the child's type on a spawn (§4(e)),
never as a client of its own; there is no broker entry in the seed manifest
— the key custodian (§3), the spawner (§4) and the credential vendor. It
attributes callers as §12 says.

- **GitHub** — installation tokens are minted by a QAuth-side STS,
  `POST /api/credentials/github`, presented with the node's DPoP-bound leaf for
  that resource and its proof (a bearer leaf until P1a). QAuth verifies the
  proof and reads the ledger row. The row must be present, not revoked, and
  not covered by the owner's revoke-all instant (§6). The row's user must be
  enabled. Every token grant that issues for a user refuses a disabled one,
  and the code grant has done so since GHSA-54c2-vvpr-33mf. The STS then
  restricts `repositories` ⊆ the token's `locations` and `permissions` ⊆ its
  `actions` — until §5 lands, ⊆ an operator-set policy per agent type in QAuth
  configuration, octo-sts-shaped — and mints with the App's private key, which
  lives in QAuth's configuration and never on the developer box; Chainguard's
  octo-sts is the prior art and an interim option. From P0 the STS accepts only
  a token whose `aud` is exactly its own identifier; the broker obtains that
  single-audience leaf by narrowing (GATE 4b). Once P1a lands it accepts
  `Authorization: DPoP` only, checks `htu`/`htm`/`ath`, and refuses to start
  if its identifier appears in `AGENT_BEARER_LEAF_RESOURCES`: the one endpoint
  that turns a 300 s sender-constrained token into an hour-long unconstrained
  one never accepts a bearer. The broker caches each node's installation token
  for its one GitHub hour and deletes it at node end and the moment it learns of
  revocation (§6), so a QAuth outage blocks new vends only; until it learns,
  GitHub's hour is the window.
- **git** — a credential helper, injected into the node's environment as
  `GIT_CONFIG_COUNT=3`, `GIT_CONFIG_KEY_0=credential.helper` /
  `GIT_CONFIG_VALUE_0=` (the empty value resets the helper list, so no
  inherited `store`, `osxkeychain` or `libsecret` helper from the user's
  system or global config ever sees the node's credentials),
  `GIT_CONFIG_KEY_1=credential.helper` /
  `GIT_CONFIG_VALUE_1=!qauth-broker git-credential`, and
  `GIT_CONFIG_KEY_2=credential.useHttpPath` / `GIT_CONFIG_VALUE_2=true`,
  answers `get` with the node's cached installation token and
  `password_expiry_utc`, so git drops it at expiry, and answers `store` and
  `erase` as no-ops: git sends `approve` to every configured helper after a
  successful push, and `password_expiry_utc` only makes `fill` skip an
  expired password — it does not stop a durable helper from persisting the
  token, so the reset is what keeps the token out of the user's credential
  store and the user's own pushes off the App identity.
- **gh** — a `gh` shim on the agent's `PATH` execs the real `gh` with
  `GH_TOKEN` and `GH_CONFIG_DIR` pointing at a fresh, empty per-node directory
  in the child's environment only (an empty _value_ is treated as unset and
  falls through to `~/.config/gh`), so the user's stored `gh` login is never
  touched. The shim sets `GH_PAGER=cat` and refuses `gh auth token` and
  `gh auth status --show-token` — UX, not custody, by this section's own
  rule: the token is still readable from the child's environment and from
  `git credential fill` (T2).
- **Precondition, not enforcement** — the shim and the credential helper are
  conveniences, not the gate: `/usr/bin/gh` by absolute path reads whatever
  login the uid holds (`gh` resolves `GH_TOKEN`, then `hosts.yml`, then the
  keyring), and a `git push` to an SSH remote never consults a credential
  helper. **The CLI gate holds only when the agent's uid carries no ambient
  credential the broker did not vend** — no `gh auth login` in
  `~/.config/gh` or the keyring, no `~/.git-credentials` or stored credential
  helper for github.com, no SSH key GitHub accepts, no `~/.pgpass`, no
  `GH_TOKEN`/`GITHUB_TOKEN` in the inherited environment — which on a
  developer box means the agent runs as its own uid or the user's login is
  removed from that uid. The broker checks for these at session binding (the
  `SessionStart` registration) and refuses to bind, with the reason logged,
  while any is present. An operator who runs agents at their own login has
  no first gate on the CLI leg.
- **Provenance** — a `prepare-commit-msg` hook and a `gh pr create`
  passthrough append `QAuth-Session: <sid>/<jti>` to commits and PR bodies: a
  pointer to the ledger row, not a proof — both identifiers are public and
  confer nothing (§6). GitHub attributes installation-token activity to the
  App's bot identity and records no token identifier, so the trailer is the
  only GitHub-side key; the proof is the STS log row it names. Where the
  tree roots in an agent principal (§13) the broker also sets
  `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL` and `GIT_COMMITTER_*` in the node's
  environment from the agent's live GitHub binding — the App's bot login
  and its `<id>+<slug>[bot]@users.noreply.github.com` address, which QAuth
  records on the binding at provisioning — so a commit the agent wrote is
  authored by the agent, and the hook adds `Model: <model>` from the node's
  reported model (§7, a report) and `Agent: <agent_id>`. The broker writes no
  `Signed-off-by`, `Reviewed-by` or `Assisted-by` line and refuses a commit
  message that carries one from the node. The first two certify a human's
  act, and only a human adds them at review or merge. The kernel's
  `Documentation/process/coding-assistants.rst` (in mainline since
  v7.0-rc1) says the same of `Signed-off-by`: an AI agent must not add it.
  Refusing `Assisted-by` is QAuth's own rule, a stated deviation from that
  document. Since v7.3-rc1 its form is `Assisted-by: LLM [TOOL1] [TOOL2]`,
  and its bug-fixing procedure (step 6) has the assistant add it to a fix it
  commits itself. Here the commit already carries the agent's part: the
  `QAuth-Session` trailer and, where the tree roots in an agent principal,
  the author identity and the `Agent:` and `Model:` trailers. A line the
  node writes about itself would add only a claim nobody checked (T7). A
  `pre-push` hook reports the pushed commit hashes to the broker, which
  emits them as one §7 SET (`action: git-push`, `resource` the repository,
  a `commits` member listing the hashes, stored as `source: broker`) so the
  owner's record can resolve
  a hash to a node; a squash- or rebase-merged hash is GitHub's, not the
  agent's, and resolves through the merged pull request instead. Every line
  of it is a claim where it lands (T7); the ledger row it points at is the
  fact.
- **psql** — libpq's built-in OAuth flow is device-code only and `psql` has no
  authdata hook, so the broker ships a preloaded library (or a thin
  `qauth-psql` wrapper) that installs `PQsetAuthDataHook` and answers
  `PQAUTHDATA_OAUTH_BEARER_TOKEN` with a single-audience leaf (`resource` = the
  database's identifier, lifetime `agentAccessTokenLifespan` per §6 — 300 s in
  production) minted by narrowing. `qauth_pg_validator`, a
  PostgreSQL 18 `oauth_validator_libraries` module, checks `iss` and `aud`
  exactly, `exp`, `typ` `at+jwt`, `token_use`, HBA `scope` ⊆ token scope,
  `locations` ∋ this database, `actions` ∋ the requested role, and maps
  `authn_id` = `sub` with `delegate_ident_mapping=1`; keys come from a cached
  JWKS, so an outage never blocks a connection whose key is known; it never
  logs a token and posts its SET from a worker, not inside `validate_cb`. It
  consults no denylist and cannot kill a live backend on revocation: a revoked
  leaf opens new connections and keeps existing ones until `exp`, and a
  retired signing key validates until the JWKS cache refreshes — the leaf's
  lifetime (§6) and a short cache TTL are the window, as PostgreSQL's own
  validator guidance says for offline validation.
- **MCP** — a proxy that attaches `Authorization: DPoP` and the per-request
  proof for MCP servers whose mcp-guard verifies DPoP, since Claude Code's MCP
  client sends Bearer only (§3). The proxy is a `stdio` MCP server
  (`qauth-broker mcp-proxy --type <agent_type> --url <upstream>`) spawned by
  the harness, so it is a child of the session process and the broker
  attributes it by `SO_PEERCRED` and ancestry like any other caller; it never
  listens on loopback. Where only a URL can be configured (an Agent SDK `http`
  server, `headersHelper` in P3), the broker listens on a random loopback port
  and requires a per-node secret in a request header that it writes into that
  node's server definition (`headers`); a request without the node's secret is
  refused. A path or a header naming the agent type is routing, never
  attribution.

**The credential is the gate; hooks are UX** (the Alternatives table;
[Harness reality](#harness-reality)). The broker **must log**, per vend:
`sid`, `jti`, `client_id`, `cnf.jkt`, pid,
uid, ancestry to the bound node (and the bound node's pidfd/start time), the
executable and subcommand (never arguments), the resource and permissions
requested, what was vended (an opaque credential id and GitHub
`installation_id`, never the credential), the PDP answer if asked, issue and
delete times, exit status, and every refusal with its reason — `purpose` and
`task` as quoted JSON strings, never interpolated (§5). Uses of a vended token
are not logged — vends, subcommands and deletions are; GitHub's audit log is
the record of use, attributed to the App. The STS logs the same, keyed by
`jti`; each vend emits the §7 SET.

### 10. Vitrin — the composition rule

The QAuth token is one `credential_type` among vitrin's peers; what QAuth
promises, proposes and must not claim is in
[Vitrin composition](#vitrin-composition).

### 11. Consent — the tree ceiling on the screen

For an agent client the consent screen states that the client is an AI agent.
When the root names an agent principal (§13), the screen names it too. It
shows the agent's `display_name`, its owner's display name and its avatar.
Both names are escaped by the same `html` tag as the client name (§5). The
avatar is served from QAuth's own origin, at the fixed path §13 gives. So the
person sees "Majordomo, owned by you" and not only "claude-code".

The screen shows the ceiling of the tree it may grow:

- the scopes with descriptions (today `agent:*` and `write:*` render raw),
  including the **union** of agent modes the tree may use, since no mode
  implies another;
- the agent types it may spawn: the client's operator-set `spawn_allowlist`,
  written into the root token's `aud` beside the requested `resource` and the
  client's own `client_id`, so that GATE 3c stays byte-identical;
- the client-attributed `purpose` from `authorization_details` (§5), in its
  own box beneath the scope descriptions.

From P2, with the flag on, the screen also shows the persistence rung: "may
keep working until you revoke it; signing out does not stop it" (decision 1).
It lands with the sign-out exemption and revoke-all (§6), never before them.
A code grant always
issues a refresh token (`apps/auth-server/src/app/routes/oauth/token.ts:625`).
The refresh grant redeems it only for a client registered for
`refresh_token` (`apps/auth-server/src/app/routes/oauth/token.ts:945`).
Decision 7 registers every seeded root type for it. A DCR or CIMD agent
client may leave it out, and then its root cannot renew. The screen shows
the rung for every agent client's code grant all the same. The refresh
grant reads the client's registration at each refresh, not at consent, and
over-warning is the fail-closed side. A root that can renew does so until
its `sid` is revoked or its refresh family ends. Either one ends the tree
(§6). A family ends at its expiry, or on any path §6 names: those under
"The end of a root's refresh family ends its tree", and the seed tool's
walk under "A lowered cap".

The screen also says, in one sentence, that the agent may delegate
downwards within this ceiling and never beyond it. `spawn_allowlist`
follows `max_agent_mode`: seed manifest only, never DCR, CIMD or the
developer API. A database CHECK holds that line from P1b. A non-empty
`spawn_allowlist` may appear only on a row with `is_agent`, no
`dynamic_registered_at`, no `developer_id`, and a `metadata.registrationType`
that is neither `dynamic` nor `cimd`.

**Enrichment** is conditional on the column. It runs only at the
`authorization_code` grant and the refreshes of that grant, for an agent
client whose `spawn_allowlist` is non-empty. It is applied to
`resolveAudience`'s result, never inside it, because `resolveAudience` also
serves `client_credentials`, jwt-bearer and the system client, which keep
today's `aud`. It adds the client's own `client_id` and its
`spawn_allowlist`.

**A refresh never widens a tree.** With the flag on, the code grant stores a
tree root's issued `aud` on its `refresh_tokens` row beside `resource`. A
refresh issues at most that set, intersected with what the current columns
give (RFC 8707 §2.2 allows the originally granted resources "or a subset
thereof"). An operator's narrowing takes effect at the next refresh. A
widening reaches no live tree without a new consent. A family with no stored
set records one at its next refresh.

**A tree of one.** A client with no allowlist keeps today's `aud`
byte-for-byte and presents that token at its resource as today. That covers
every DCR and CIMD client, every seeded type an operator has not given an
allowlist, and so every client in a default deployment. It cannot spawn from
a `cnf` subject, whatever its `aud` names, because GATE 3d reads the parent
type's `spawn_allowlist` (§4). From P1b no other client can exchange its
`sid`-carrying tokens (§4). A confidential DCR or CIMD client that
registered the exchange grant keeps its exchange of its own bearer tokens.
GATE 3c bounds it as today. From P1b, with the flag on, GATE 4d and 3d's
ledger check also run on it, as on every exchange (§4). An allowlisted
type's root always names at least itself, which is what lets it narrow, and
that root is the one the broker holds.

Why `aud`, and why a separate column: RFC 8693 §2.1 defines `audience` as
"the logical name of the target service where the client intends to use the
requested security token" and gives an OAuth client identifier as an example
value; reading `aud` ∋ `client_id` as "who may present this at the STS" is
the splicing thread's rule, not RFC text, and it is what GATE 3c already
checks (the Alternatives table, `may_act`). Resource audiences (RFC 8707)
and STS presenters (RFC 8693) are separable, so the allowed-children set is
its own operator-set column beside the `audience` allowlist
(`libs/infra/db/src/lib/schema/core.ts:163`). The enriched root token is
multi-audience, which RFC 8707 §3 reserves for parties that trust
each other highly; every member here is the operator's own resource server or
agent-type registration, and the enriched root token is held by the broker
and never presented at a resource — every resource sees a single-audience
leaf.

**The skip-consent fast path is untouched, as merged.** A stored consent can
skip the screen for an agent client as for any client (`canSkipConsent`,
`apps/auth-server/src/app/helpers/consent.ts:77`). Since GHSA-46p8-vmjm-2jpq,
the route's `prompt=none` branch
(`apps/auth-server/src/app/routes/oauth/authorize.ts:512`) consults the same
predicate. A stricter rule, no skip for an agent client under the flag, would
change what the maintainer merged. It is parked as decision 17.

With `AGENT_TREE_ENABLED` on, the Bearer path of `/oauth/authorize` refuses an
agent client with `access_denied`, audited, before any code is minted.

Each code grant mints its own `sid` (§1), per grant, not per screen. So each
code-grant root names its own agent, allowlist, purpose and persistence rung,
and the screen shows them whenever it is shown. With the flag off, and for
every other client, nothing changes.

A root that names a dangerous scope (`agent:exec`, `agent:admin`,
`agent:request` from P5, any `write:*`) costs a fresh login in `staging` and
`production`. The login is skipped when the browser session is under two
minutes old (step-up rule 3, `evaluateStepUp`,
`apps/auth-server/src/app/helpers/step-up.ts:196`). The default
`claude-code` root (decision 7) is `exec`, so each new root costs the user
one login; a root with no dangerous scope does not.

### 12. Harness — a node is a process

A node exists only where a process holds its own handle. The broker resolves a
caller by walking the `SO_PEERCRED` pid's parent chain to the first bound pid; a
chain that reaches no bound node is refused and logged — never attributed to the
session. The session node is bound like every other node: `qauth-broker login`
opens a pidfd on the session process (fallback: pid plus `/proc/<pid>/stat`
start time, field 22), and every binding — session, teammate, executor child —
is a pidfd or pid+start-time pair, so a recycled pid never inherits a node, and
the broker unbinds a node the moment its pidfd signals exit. A second
registration from a bound pid never binds a second node and changes nothing,
whatever its `session_id` (§1). An in-process sub-agent shares the session
process and so shares the session node; that is the harness limit, not a
default. Which nodes can be bound today, and which cannot, is in
[Harness reality](#harness-reality).

### 13. Agent identity — a principal with an owner, held by QAuth and asserted nowhere else

An **agent** is a new principal in the realm: neither a user nor a client
registration, but a durable record that a user owns and that a tree can root
in. It lives in a new table, `agents`: `id` (uuid), `realm_id`, `handle`
(unique within the realm, `^[a-z0-9][a-z0-9-]{1,62}$`, immutable once a
binding exists), `display_name`, `description`, `avatar` (a PNG QAuth
stores and serves at `/agents/{handle}/avatar.png` on its own origin, ≤ 512
KiB, decoded and re-encoded on upload so nothing but pixels survives — no
SVG, which can carry script, and never a URL QAuth would dereference on
render), `active`, `profile_visibility` (`public` | `private`, default
`public`), `owner_user_id` (a `users`
row, `onDelete: 'restrict'` — an agent never outlives its owner silently;
the owner deactivates or transfers it first), `created_at`, `updated_at`.
The owner is the person the SCIM Agent draft calls the responsible party,
and the only party who may edit the row, bind it to a platform, register a
transmitter for it (§7) or deactivate it.

**An owner has a verified address.** QAuth refuses, with an audit row, each
of the following unless the user's `password` credential records
`email_verified` as true, whatever `REQUIRE_EMAIL_VERIFIED` says:

- creating an agent, or accepting the transfer of one;
- binding an agent to a platform;
- registering an agent-side transmitter, an approval channel or an approval
  passkey.

The root-grant owner check below refuses the same way. An address QAuth has
not verified is only a claim, and the owner is the name on a public profile
and the party answerable for a transmitter's events. So an account that
never proved its address owns nothing this record creates. An account with
no `password` credential cannot own an agent in the first slice
(decision 20).

The harness hooks' own `agent_id` (a sub-agent instance,
[Harness reality](#harness-reality)) is a different thing with the same name
and is never written to the ledger. There is no email on an agent and none is
needed: [ADR-002](./002-identifier-abstraction.md) already made
email a credential, not an identity, and an agent has no credential of its
own — it acts through the harness types and keys this record already binds.

**Where it sits in the tree.** `sub` stays the human (§1); nothing here
touches the root invariant. The agent is named in the root grant: an agent
client that authorizes with `agent_id=<handle or uuid>` on the authorization
request roots the tree in that agent. QAuth refuses the request
(`invalid_request`, audited) unless the agent's row is active, its
`owner_user_id` is the authenticating `sub`, and that user holds a verified
address (above). The consent screen then names the agent (§11). The
ledger's `kind: root` row records `agent_id`; every descendant row inherits
it unchanged as `sid` is inherited (§2); introspection returns it in
`qauth_delegation` as `agent`. Revocation gains one more identifier,
`POST /api/agents/{id}/revoke`, which cuts every live tree of that agent by
the §6 walk. Only the agent's current `owner_user_id` may call it, under the
owner-route guard (§6); a node may not, since its reach stays its own
subtree (§6).

**Transfer** (decision 10, decided). Decision 10 settles two things: history
keeps the owner of its time, and from the transfer the agent acts under the
new owner. The rules below are this record's own, each the fail-closed way
to carry that out.

A transfer is an offer until the recipient accepts it. The current owner
makes the offer from the portal, naming one user. An agent has at most one
open offer. Until the offer is accepted nothing changes: the owner, the
public profile, the live trees, the bindings, the transmitters and the
standing blocks stay as they were. The owner may withdraw the offer until it
is accepted, and it lapses after seven days unanswered. A withdrawn or lapsed
offer can never be accepted. The offer route answers the same way whatever
the named user's state, so it reveals no account. Only the named user accepts,
from their own portal, under the owner-route guard (§6) and the
verified-address rule (above). The acceptance also re-checks that the offering
user still owns the agent. Each offer, withdrawal, lapse and acceptance writes
an audit row. The owner is the name on the profile and the party answerable
for the agent (T7). So, by this record's own rule and not in the
maintainer's words, nobody is made an agent owner without accepting.

The acceptance is the moment of transfer. Its own transaction cuts every
live tree of the agent by the §6 walk and sets `owner_user_id` to the
recipient. From then on the public profile names the new owner, and no tree
under the previous owner mints, renews or vends. What those trees already
hold runs out within §6's written revocation window. An access token lasts
to its `exp`, at most one lifetime. A vended installation token lasts until
the broker deletes it, at most its GitHub hour (§9). Each of those tokens
was minted before the transfer, and its ledger row keeps the previous owner.
So an action taken with one is pre-transfer activity. It is recorded under
the previous owner, since its row's `user_id` comes from the `jti`'s ledger
row (§7). No row is rewritten. Whether the agent should instead be frozen
until the last cut token expires is parked as decision 22.

The acceptance's transaction also disables the previous owner's
`agent_transmitters` rows for the agent, since a transmitter's owner answers
for what it sends (§7). The rows are kept, not deleted, so pre-transfer
events keep the transmitter they name. The new owner's first tree needs the
new owner's consent. Each ledger and `agent_actions` row keeps the `user_id`
of its time (§2, §7). Every display renders the owner from the row itself,
never by joining `agents.owner_user_id`.

The same transaction suspends every `agent_bindings` row of the agent. The
platform side of a binding was provisioned by the previous owner and stays
theirs on the platform: on GitHub, the STS App and its installations. So a
binding does not pass with the QAuth row. Until the new owner binds the agent
again:

- the STS refuses, audited, every vend for a tree rooted in the agent, and
  never falls back to decision 4's per-organisation App;
- the broker sets no author identity for the agent (§9);
- the public profile lists no binding.

Each suspended row is kept, not deleted and never rewritten, so
pre-transfer history keeps the binding it named. Only the new owner binds the
agent again, under the verified-address rule. That writes a new row with its
own `proof` and `bound_at`, with an audit row, even when it names the same
App. Moving the App registration on GitHub is the two owners' business,
outside this record.

The previous owner's standing blocks for the agent stay in force, since a
block only denies. The transaction rewrites none of them. Who may remove one
is set in §14, step 4.

`act` is untouched: `act.sub` remains the harness type's `client_id`. That is
the value the actor profile's client-assertion pattern yields (§6.3.1.2
step 3). Its §14.2 calls that pattern, `iss` = `sub` = `client_id`, the
conformant one. It is durable, as its §14.12 wants. The profile names another
principal as
the actor only through that principal's own actor credential, such as a
workload identity credential (§6.3.1.1). The agent is not a client and holds
no credential of its own. A grant with no `agent_id` is byte-for-byte today's
grant: the column is NULL and every consumer treats NULL as "no agent named".

**SCIM projection.** `agents` is served as the SCIM `Agent` resource of
`draft-wzdk-scim-agent-resource-00` (June 2026, individual, Informational) at
`/scim/v2/Agents`, schema `urn:ietf:params:scim:schemas:core:2.0:Agent`:
`agentUserName` ← `handle`, `displayName`, `description`, `active`, and
`owners[]` ← one value whose `value` is the owner's `users.id`, the
sub-attribute the draft makes MUST (§4.2). It carries no `$ref`, which §4.2
only RECOMMENDS: QAuth serves no SCIM `User` resource for it to point at. A
later record that serves `/scim/v2/Users` adds it. The owner value's
`displayName` sub-attribute, which §4.2 makes OPTIONAL, is left out too,
since the projection returns only the caller's own agents. The draft defines
no avatar and no platform binding, so
both go in a QAuth extension schema,
`https://schemas.qauth.dev/scim/extension/agent/1.0`, with `avatar` (a URI
on QAuth) and `bindings[]` (the agent's live bindings, below) — named as an
extension, never as a core attribute, and offered to the SCIM WG list as
feedback on the draft. The schema URI is an HTTPS URI QAuth controls, like the
record's other `https://schemas.qauth.dev/` identifiers. A `urn:qauth:` name
would be no URN, because `qauth` is not a registered namespace (RFC 8141 §1).
RFC 7643 §3.3 needs only a URI. The projection is read-only in the first
slice; the developer API and the portal write the row. QAuth has no SCIM
endpoint today, so this is the first one, scoped to this resource, `GET` only,
under the owner-route guard (§6), returning only the caller's own agents.

**Bindings.** A binding is a row in `agent_bindings`. A row is live while its
`suspended_at` is NULL. An agent has at most one live row per platform, held
by a unique index on (agent, platform) over the rows whose `suspended_at` is
NULL. Suspended rows stay beside the live one, and the STS and the broker
read only the live row. The columns are `platform` (`github` first; others
as they are provisioned), `external_id` (the platform's identifier for the
identity that acts — on GitHub the _bot user's_ numeric id from
`GET /users/{slug}[bot]`, which is what the `noreply` address carries, not the
App id), `external_app_id` (the App id, where the platform has one),
`external_login`, `external_email` (the attribution address the platform
assigns), `sts_app_ref` (the key in QAuth configuration naming the App and
private key the STS mints from for this agent, §9), `proof` (how QAuth learned
it; for GitHub, the STS App's own `GET /app` and `GET /users/{slug}[bot]`
answers at provisioning), `bound_at`, `suspended_at` (set by a transfer,
above). For GitHub the
binding _is_ the STS App of §9: the App's slug is the agent's public name on
that platform, its bot login the author of every commit and pull request the
agent makes (§9, provenance), its App page the place GitHub itself shows the
owner account as the developer. One STS App per agent, then, not one per
organisation — decision 4 is amended below — and the App's private key stays
where §9 puts it. The avatar the platform shows is the platform's; GitHub
exposes no API to set an App's logo, so the owner sets it by hand from the
same file QAuth serves, and QAuth records nothing about whether they did.

**Public profile.** `GET /agents/{handle}` on the realm's public origin serves
the profile, unauthenticated: `display_name`, `description`, avatar, the owner's
display name, the `external_login`s of bindings not suspended, `active`, and a
fixed statement of what the page attests — that this agent is a principal of
this issuer owned by this person, and nothing about any commit, message or
action that names it elsewhere (T7). The same at `Accept: application/json`.
From the moment of transfer (Transfer, above) the profile names the new
owner (decision 10).
No `sid`, `jti`, node, scope, model or event ever appears on it; those are
the owner's (§2, §6). An agent whose `profile_visibility` is `private`
answers 404, indistinguishable from a handle that does not exist.

**What QAuth does not do here.** It does not provision the platform side —
create the GitHub App, upload its logo, set a Matrix avatar — and it does not
verify what the agent says about itself on those platforms (T7). It does not
sign commits, evaluate a model name, or hold a memory, a runtime or a reason
for a step beyond the bounded `reason` member of §7. Those are the owner's
systems, recorded in the owner's own decision record; QAuth's part is the
row, the binding, the profile, the tree that roots in it and the log that
names it.

### 14. Remote approval — a refused request the owner approves out of band

The ceiling is fixed at the root, and every hop can only narrow it (the
invariant). Sometimes the owner wants to lift it for one step. An agent
needs `contents: write` on one repository, once. The owner is away from
the terminal and drives the session from a phone, through Claude Code's
Remote Control, with no shell and no SSH. This section lets the owner
approve that one step from the phone. It widens no token and no tree. It is
not Claude Code's own permission prompt: that prompt is the harness asking,
and hooks are UX (§9); this is the credential gate. It sits behind
`AGENT_TREE_ENABLED` and its own switch, `AGENT_APPROVAL_ENABLED` (default
`false`).

**Nothing that exists is widened.** A refusal stays a refusal. If the owner
approves, QAuth mints a separate token for exactly what was asked: an
**elevation leaf**. It is bound to the requesting node's key, it can
neither spawn nor narrow, and nothing below the node inherits it. The
invariant holds for every token an exchange derives, and no exchange derives
an elevation: an elevation comes only from the CIBA grant (steps 5 and 6).
It is bounded by its approval instead of a parent, and still by its type and
the node that asks (below).

**What an approval can lift.** An approval lifts only a parent bound: scope
or rights beyond what the node holds (GATE 4a, §5). It never lifts an
operator bound or the audience bound. Before it files a request or notifies
anyone, the backchannel endpoint refuses, notifying no one:

- a delta whose scope is outside the node type's registered
  `oauth_clients.scopes` or above its `max_agent_mode` (`invalid_scope`);
- a delta whose scope contains `agent:request` (`invalid_scope`), so an
  approval never grants or extends the right to ask;
- a delta whose `agent-task` entry names a resource outside the requesting
  node token's `aud` (`invalid_request`);
- a delta whose `agent-task` entry names a resource listed in
  `AGENT_BEARER_LEAF_RESOURCES` (`invalid_request`). An elevation is always
  bound to the node's key (step 5). A listed resource is a dual-scheme
  resource reached with Bearer only. RFC 9449 §7.2 makes it reject a bound
  token sent as Bearer (§3).

These are CIBA Core 1.0 §13's codes. RFC 9396 §14.6 registers
`invalid_authorization_details` for the token and authorization endpoints
only. The same checks run again at every mint of an elevation leaf (steps 5
and 6), against the type's current registration and the current
`AGENT_BEARER_LEAF_RESOURCES`. So an operator who narrows a type, or lists
the resource, ends an open window at its next renewal.

**The flow.**

1. **Refusal.** A node asks for more than its ceiling: at the token
   endpoint (`invalid_scope` from GATE 4a, `invalid_authorization_details`
   from §5's subset check), at the STS (§9), or at an mcp-guard resource
   (`403 insufficient_scope`). The broker sees the refusal. A GATE 4b, 4c or
   4d refusal is final (What an approval can lift, above). A refused renewal
   (§4) is never a request.
2. **Request.** If the node's token carries `agent:request` (below), the
   broker files an approval request: an OpenID CIBA backchannel
   authentication request (CIBA Core 1.0 §7.1), in poll mode — poll,
   because the broker sits behind NAT, the same reason §6 polls its SSF
   stream. The broker
   authenticates as the node's agent type (§3's client-assertion rule) and
   adds a DPoP proof under the node's key. It sends:
   - `login_hint_token` = the node's own DPoP-bound token. CIBA requires
     exactly one of its three hints and leaves this one's format to the
     deployment; QAuth defines it as the requesting node's token, which
     names the user, the `sid` and the node. QAuth accepts no other hint: a
     request with `login_hint` or `id_token_hint` is refused with
     `invalid_request`. CIBA leaves hint validation to the deployment (§7.2).
     QAuth checks the hint as the exchange checks a subject token
     (signature, `exp` and issuer; `token_use`; the denylist; `aud` naming
     the authenticated client), and further requires that:
     - the hint's `client_id` is the authenticated client;
     - it has a ledger row, and neither that row nor its node is revoked;
     - its `cnf.jkt` is the key of the request's DPoP proof, which passes
       RFC 9449 §4.3 with `htu` = the backchannel endpoint (DPoP at a CIBA
       endpoint is QAuth-defined).

     A failed hint is `invalid_request`, or `expired_login_hint_token` when
     its signature verifies and only `exp` has passed (CIBA §13). Nobody is
     notified.

     Using the node's token as the hint departs from the FAPI-CIBA working
     copy §4.1.1, under which an AS should not use a hint to convey
     authorization metadata. QAuth needs the request bound to one live node
     token, its `sid` and its key. The delta itself never travels in the
     hint. Not adopted: `login_hint` = the user's RFC 9493 identifier, with
     the node found by its DPoP key, because the AS could not then tell which
     of the node's tokens asked;

   - the delta asked for: `scope` and one `agent-task` entry in
     `authorization_details` (§5) naming one resource. RFC 9396 §3 lists
     CIBA requests among the places `authorization_details` may appear.
     `scope` also carries the `openid` value, which CIBA §7.1 requires in
     every request. It is not part of the delta: the page never shows it,
     and neither the `approval_receipt` nor the leaf carries it;
   - `binding_message`: a short code the broker shows in the session, which
     the approval page shows too — CIBA's own purpose for it, a visual cue
     that interlocks the two devices;
   - `requested_expiry`: at most `AGENT_APPROVAL_EXPIRY` (default 300 s);
   - `qauth_approval_duration`: `once` or `window` — what the agent asks
     for; the owner decides. CIBA lets a profile add parameters (§7.1).
3. **Notification.** QAuth notifies the session owner — the ledger row's
   `user_id`, never anyone else — through a channel the owner registered
   (decision 16): web push to the portal, or an owner-registered webhook. A
   notification carries only the request id, the agent's handle and the URL
   of QAuth's approval page. It never carries an approve action: approval
   happens only on QAuth's origin.
4. **Approval page.** QAuth renders it from the typed request, never from
   the model's text: the agent (principal and type, §13), the session, the
   node, the exact delta, the resource and the duration asked. The node's
   `purpose` appears below, in the box attributed to the client (§5). The
   `binding_message` is shown for matching. The owner answers with a
   passkey: a WebAuthn assertion with user verification, whose challenge
   QAuth binds to this request. A live browser session is not enough. The
   page recommends answering from a separate device — a phone, directly or
   through the hybrid transport — and says why (Authenticators, below). The
   choices, none preselected and Deny at least as prominent as either
   approve choice (RFC 10027 §6.1.14):
   - **Approve once** — one elevation leaf for the one resource, with the
     `agentAccessTokenLifespan` lifetime (§6), or one STS vend.
   - **Approve for a while**, or **for this session** — the owner picks the
     window: 15 minutes, one hour, or until the session's grant ends. A
     window never outlives the root's refresh family and never reaches a
     durable rung.
   - **Deny.**
   - **Deny and mute** — for this session, or for a chosen time. Further
     requests from that `sid` are refused with `access_denied` and notify no
     one.
   - **Block always** — an owner-held deny rule keyed by this agent, this
     resource and this delta; for a tree with no agent named, keyed by this
     owner's `user_id` and root agent type in place of the agent. It holds in
     every session until the owner removes it from the portal. A later
     request for that resource whose delta overlaps the blocked one is
     refused with `access_denied` and notifies no one. A block that names an
     agent matches every tree rooted in that agent, whoever rooted it. Only
     the agent's current owner (`agents.owner_user_id`) may remove it. Its
     row also keeps the `user_id` of the owner who set it, never rewritten
     and never used to authorise its removal (decision 10).
5. **Token.** After an approval, the broker's next poll at the token
   endpoint (`grant_type=urn:openid:params:grant-type:ciba` and the
   `auth_req_id`, CIBA §10.1, with a DPoP proof under the same key)
   returns the elevation leaf; until then it gets `authorization_pending`,
   and on a denial `access_denied` (CIBA §11):
   - `sub` = the user, `client_id` = the node's type, `cnf.jkt` = the
     node's key, `sid` and `act` = the node's;
   - scope and `authorization_details` = exactly the approved delta — not
     the node's scope plus the delta;
   - one audience, the resource; no refresh token; `exp` no later than the
     approval's end.

   The poll takes the §6 lock on the requesting node's anchor. It refuses
   with `invalid_grant` when the node is revoked. It refuses the same way,
   audited as `user_disabled`, when the ledger row's user is not enabled, as
   every token grant that issues for a user refuses a disabled one. The
   `auth_req_id` is redeemed once (CIBA §10.1.1).

   The success response is CIBA §10.1.1's, which is OpenID Connect Core 1.0
   §3.1.3.3's, so it also carries an ID token. That ID token holds only
   `iss`, `sub` = the user, `aud` = the node's type, `exp`, `iat`,
   `auth_time` = the time of the passkey assertion, and `token_use` `id`. It
   has no `sid` (§1), no `acr`, no `amr` (QAuth sets no `amr` today), and no
   profile or email claim. The broker discards it. The response's `scope` is
   the approved delta without `openid`.

   The ledger records it as `kind: elevation`, with `parent_jti` = the
   requesting node's token and an `approval_receipt`: the request id, the
   approved delta, the duration, the passkey's credential id and the time
   of the assertion. Any token exchange whose subject is a
   `kind: elevation` token is refused with `invalid_request` by GATE 3d's
   ledger check (§4), spawn and narrow alike: the leaf is used where it was
   approved, by the node that asked, and nowhere else.

6. **A window.** While a window is open, the broker renews the leaf with a
   new CIBA request (step 2), with the node's current token as
   `login_hint_token`.

   QAuth matches it to the open approval and resolves it at once, with no
   notification and no passkey. The owner's passkey-confirmed window is the
   authorization decision (OpenID Connect Core 1.0 §3.1.2.4, to which CIBA §8
   points). The broker redeems the new `auth_req_id` once. The renewal is a
   new `kind: elevation` row under the same approval, with `exp` clamped to
   the window's end. A renewal is not an ask: it notifies no one and does not
   count against `AGENT_APPROVAL_BUDGET` (a one-hour window at the 300 s
   lifetime takes twelve leaves).

   A request is a renewal only when it matches an open window exactly: the
   same node, key, `sid` and delta, under an approval given for a window,
   not `once`. Even then QAuth refuses it with `access_denied`, notifying no
   one, when the node's token no longer carries `agent:request`, when the
   `sid` is muted, or when a standing block matches. A revoked hint fails
   step 2's checks. Any other request is a new ask (step 2), under the
   budget, the mute and the block. The window ends at its time, when the
   node's process dies (the dead-man switch, §6), when the `sid` is revoked,
   or when the owner ends it from the portal. The §6 walk treats elevation
   rows like any other row.

**Asking is a scope of its own.** `agent:request` is the right to file an
approval request at all. It sits in the root grant like any other scope,
and the consent screen shows it (§11). An approval can never grant or
extend it, and an elevation never carries it: a delta that names it is
refused before filing (What an approval can lift, above). A child gets it
only by narrowing from a parent that holds it. A per-`sid` budget caps asking
— `AGENT_APPROVAL_BUDGET`, operator-set, default three pending and ten an hour
— and no approval raises it. A node without the scope, over its budget, muted
or blocked, or whose user is not enabled or has registered no approval passkey
(§13), gets `access_denied` (CIBA §13), and nobody is notified. A request that
no one could approve is never filed.

With the flag on, `agent:request` is reserved like the three modes. Only an
agent type — an agent client with an operator-set `max_agent_mode` — may hold
it, whatever its mode, so a read-only type may ask. Every gate that clamps
the modes refuses it otherwise with `invalid_scope`: `findExceedingAgentScopes`
(`apps/auth-server/src/app/helpers/scope-modes.ts:162`), at authorize,
consent, `client_credentials`, jwt-bearer, refresh and GATE 4c. It is also
dangerous, as `agent:exec` is, so a root that carries it costs a fresh login
in `staging` and `production` (§11).

**Why a mute only denies.** In a chat client, "don't ask again" usually
means "allow from now on". Here it means "stop asking me". If it meant
allow, one tap would become a standing grant for whatever the agent asks
next — the approval-fatigue attack of T8. Repeated identical requests are
what "approve for a while" is for: it covers the same delta for the window,
so the agent has no reason to ask again. The maintainer decided the lasting
answers on 2026-09-30 (decision 14): the two windows allow; the two mutes
and "block always" only deny. "Always allow" is parked as decision 18,
because it would be exactly that standing grant.

**Authenticators.** A passkey is the only accepted factor, in every profile
(decision 15). It is phishing-resistant and scoped to QAuth's own host:

- its RP ID is the host of QAuth's origin, the WebAuthn default — never a
  parent domain, never shared through related origins (WebAuthn Level 3 §4
  "RP ID", §5.11);
- registration and assertion run only on pages the auth server serves; the
  portal links there and never runs a ceremony itself;
- QAuth refuses client data whose `origin` is not exactly its own (§13.4.9).

So a relayed link cannot capture the passkey. A TOTP or other offline code
can be relayed by a phishing page. NIST SP 800-63B-4 §3.2.5 says manually
entered OTPs "SHALL NOT be considered phishing-resistant". An agent that
fills forms can also type one. So no profile accepts such a code. A synced
passkey is acceptable up to AAL2 (SP 800-63B-4, Appendix B).

No current standard lets the authenticator itself show the request it signs;
WebAuthn Level 1's `txAuthSimple` extension is gone from Levels 2 and 3. So
what the owner reads is the page QAuth renders, and the binding is QAuth's
own: the challenge is minted for this request and accepted for nothing else.

**A stated residual.** A platform authenticator on the machine the agent runs
on, unlocked by a PIN or a password, can be operated by a computer-use agent
there. WebAuthn cannot enforce the separate device that step 4 recommends:
hints "are not requirements, and do not bind the user-agent" (§5.8.8), and
the attachment a client reports (§5.1) is not in the signed
client data (§5.8.1). This is T8's residual. It is also a stated deviation
from RFC 10027 §5 and §6.2.2.5 (T8).

A wallet presentation bound to the request through OID4VP `transaction_data`
(OID4VP 1.0 §8.4; [ADR-004](./004-wallet-agnostic-federation.md)) comes
later, behind `WALLET_FEDERATION_ENABLED`, as a request-bound option. QAuth
has no passkey or TOTP support today (verified 2026-09-30), so a WebAuthn
credential provider is a precondition (P5).

## Alternatives considered

| Alternative                                                                                     | Why not                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Adopt draft-liu's `delegation_chain` in the token now                                           | Individual `-00`, June 2026; records of 500–1000 bytes per hop; `wit://` identifiers defined only in its own terminology; signed-field set still moving. Ledger plus `qauth_delegation` carries the same facts; revisit on the §2 trigger.                                                                                                                                                                                                                                          |
| draft-niyikiza offline attenuation (holder-derived child tokens, no AS)                         | No `sub`, so no on-behalf-of; no ledger, so no dashboard or cascade; not an access token at any RS. Its `par_hash` binding is borrowed as `ath` in the spawn assertion.                                                                                                                                                                                                                                                                                                             |
| Transaction Tokens as the session identifier                                                    | Per-invocation, minutes-scale, single trust domain, "A workload MUST NOT use a transaction token as an OAuth 2.0 Access Token" (-11 §13.13). Not a durable root.                                                                                                                                                                                                                                                                                                                    |
| One DCR client per agent instance                                                               | Anonymous DCR clients are unowned ([ADR-012](./012-dynamic-client-ownership.md)), get `NULL` `max_agent_mode` and a secret to keep; a `client_id` names a registration, not an instance. The instance is the process: its key binds the token, and its ledger node names it (§2, §3).                                                                                                                                                                                               |
| An attested instance identifier (`client_instance`, `agent_instance_id`)                        | draft-mcguinness-oauth-client-instance-id and -ai-agent-instance need an attester that assigns the identifier. QAuth has none, and attestation is out of scope. The two drafts also disagree on where it goes: a `client_instance` claim, or `act.sub` (§8 there). `node_id` names the process and `cnf.jkt` binds it; neither enters `act` (§3). Revisit with attestation.                                                                                                         |
| `may_act` as the allowed-children carrier                                                       | RFC 8693 §4.4 `may_act` is one party, a JSON object; a set of agent types is not expressible. `aud` ∋ client identifier is an example value §2.1 allows, read as "who may present this at the STS" per the splicing thread, and it is what GATE 3c already checks.                                                                                                                                                                                                                  |
| A ledger `aud_ceiling` in place of GATE 4b's subject-`aud` bound                                | Moves the on-token invariant `aud(c) ⊆ aud(p)` into a table; a resource server could no longer verify audience monotonicity from the tokens alone. Enrichment keeps 4b byte-identical.                                                                                                                                                                                                                                                                                              |
| A refresh token per spawned node                                                                | Reverses "no refresh token for a delegated token", replaces the on-token floor `exp(c) ≤ exp(p)` with a ledger check, and inherits a seven-day default; RFC 9449 §5 says a confidential client's refresh token is not DPoP-bound, so the node's key would not even protect it. Renewal is a re-spawn.                                                                                                                                                                               |
| The child's client assertion as `actor_token` (actor profile §6.3.1)                            | The conformant rebind shape, and a second URN relaxation on GATE 2; it names the child, not the parent's authorisation. Named as the future path, not adopted.                                                                                                                                                                                                                                                                                                                      |
| The spawn assertion in the `actor_token` slot                                                   | RFC 8693's `actor_token` is the acting party's own identity, and GATE 2 pins it to access tokens. A parent-signed statement about a child is a different object; a new parameter keeps the semantics honest and GATE 2 untouched.                                                                                                                                                                                                                                                   |
| mTLS instead of DPoP                                                                            | A certificate per process needs a CA on the box; DPoP needs a JWK. Vitrin's wire is bearer-shaped either way; the JWT stays the credential.                                                                                                                                                                                                                                                                                                                                         |
| A local broker that mints GitHub installation tokens itself                                     | Puts the App's long-lived private key and the vend policy on the developer box, same uid as the model's shell: the agent could widen its own ceiling by editing a file. The STS keeps both server-side; the broker forwards, caches and deletes.                                                                                                                                                                                                                                    |
| Hooks as the enforcement point                                                                  | `PreToolUse` cannot inject or remove a credential and cannot attribute an in-process sub-agent's CLI call. Hooks stay UX.                                                                                                                                                                                                                                                                                                                                                           |
| Short lifetimes only, no ledger cascade                                                         | The floor, kept. The user must be able to kill a tree from the dashboard within the window, and a refused refresh is not an audit trail.                                                                                                                                                                                                                                                                                                                                            |
| Macaroons / Biscuits                                                                            | HMAC chaining gives attenuation without proof of possession; Biscuits need a Datalog engine at every RS; neither is an OAuth token at mcp-guard, GitHub or PostgreSQL.                                                                                                                                                                                                                                                                                                              |
| The agent as a `users` row (a service account)                                                  | A user is the on-behalf-of `sub`; making the agent one would let a tree root in it with no human, which the exchange gate refuses on purpose (§1). A user also holds credentials of its own; an agent holds none (§13).                                                                                                                                                                                                                                                             |
| The agent as an `oauth_clients` row                                                             | A `client_id` names a harness type shared across users and boxes (§6, §9); one client per agent recreates the per-instance registration ADR-012 rejected, and `developer_id` is NULL for every anonymous client. A client is not owned by a user the way an agent is.                                                                                                                                                                                                               |
| Agent identity in `act` (`act.sub` = agent)                                                     | In the actor profile's client-assertion pattern, `act.sub` is the presenting client's `client_id` (its §6.3.1.1, §6.3.1.2 step 3, §14.2). Naming another principal takes that principal's own actor credential (§6.3.1.1), and an agent holds none (§13). The profile's §14.12 wants `act.sub` durable and never key-derived, and the harness type still has to be named. The agent is a ledger column and an introspection member, not an `act` member (§13).                      |
| A public per-`jti` or per-commit resolver on QAuth                                              | Puts ledger rows behind a URL anyone can enumerate from public commits; `sid` and `jti` confer nothing, but the rows are the owner's (§2, §6). The profile shows the principal and nothing below it; resolving a commit is the owner's record's job (§9, §13).                                                                                                                                                                                                                      |
| Model name as a ledger fact                                                                     | QAuth never sees the model: the harness hooks report it at session start and on a switch, a loopback proxy sees it on the wire, and neither is QAuth's own observation. A report stays a report (§7, T7).                                                                                                                                                                                                                                                                           |
| SSF stream management for agent-side transmitters                                               | Receiver-initiated by design (SSF 1.0 §7, §8): the receiver reads the transmitter's well-known configuration and creates the stream there, which a local daemon behind NAT cannot serve. RFC 8935 with an out-of-band `agent_transmitters` row now; a transmitter-initiated registration goes to the WG (§7).                                                                                                                                                                       |
| Commit signing by the broker or by QAuth                                                        | A broker-held per-node key verifies against the ledger but GitHub reports it `unknown_key` and shows every agent commit Unverified; a QAuth-side signer with a registered key shows Verified but puts the AS on every commit, against the hot-path rule. Two further routes, both untested, are named in decision 12: commits the agent's App creates through GitHub's API, and keyless gitsign with QAuth as the OIDC issuer. Parked (decision 12).                                |
| Widen the live token or tree when the owner approves                                            | Breaks the invariant: every child spawned afterwards inherits the extra right, and the root consent no longer bounds the tree. An elevation is a separate leaf for one node (§14).                                                                                                                                                                                                                                                                                                  |
| An approve button in the notification (chat bot, email)                                         | The button is not bound to a passkey on QAuth's origin: anyone who can read the channel — or the agent, if it can post there — could approve. A notification carries a link only (§14).                                                                                                                                                                                                                                                                                             |
| "Don't ask again" as an automatic approval                                                      | One tap becomes a standing grant for whatever the agent asks next; "approve for a while" or "for this session" covers repeats of the same delta. A mute or a standing block only denies; "always allow" is parked (§14; decisions 14, 18).                                                                                                                                                                                                                                          |
| A TOTP code as the approval factor                                                              | A one-time code can be relayed by a phishing page, and an agent that fills forms can type one; a passkey is bound to QAuth's origin. Accepted in no profile (decision 15, decided 2026-09-30).                                                                                                                                                                                                                                                                                      |
| Defer the refused exchange (draft-ietf-oauth-deferred-token-response) instead of a CIBA request | It defers only token-endpoint requests, and two of §14 step 1's three refusal points, the STS and an mcp-guard resource, are not token-endpoint requests. A deferred exchange also resolves with that grant's own token (§5.5.2): a node token that could spawn, carrying the node's scope plus the delta, which GATE 4a refuses. A CIBA request is a separate grant for exactly the delta. Revisit at a later DTR revision, or when the Access Request OAuth Profile is published. |
| AAuth as the agent protocol (draft-hardt-oauth-aauth-protocol-11)                               | The resource verifies an HTTP Message Signature over AAuth's own tokens (§9.4.2), not an OAuth access token at mcp-guard, GitHub or PostgreSQL; an individual draft. Its parent-mediated sub-agent tokens (§10.2.3) are the nearest outside precedent for §4. Its one-level sub-agent cap (§10.2.2), which sends deeper work through independent grants (§10.1.1), is not adopted: lead → teammate → process → tool needs depth under one consent.                                  |

## Standards position

The composition caveat is the honest headline: **RFC 9449, RFC 9396, RFC 8707
and RFC 9700 never mention token exchange, and RFC 8693 never mentions `cnf`.**
"DPoP-bound exchange", "RAR narrowing on exchange" and "`aud` subset across
hops" are QAuth rules anchored on RFC 9449 §5's "regardless of grant type" and
RFC 9396 §6.1's "fewer permissions" — composition by analogy, not text.
draft-mcguinness-oauth-token-exchange-cnf-00, an individual draft, proposes a
`cnf` exchange-response parameter.

| Piece                                                   | Position                                                                                             | Hook                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hop grammar, `act` nesting, top-level-only policy       | Covered                                                                                              | RFC 8693 §2.1, §4.1, §2.2.2 (error codes: see "Exchange error codes")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Root grant return leg                                   | Covered; the `iss` check goes beyond RFC 9700 §4.4.2 for a single-server client; IPv4 only by choice | RFC 8252 §7.3, §8.3, §8.4, §8.10, Appendix B.5 (the `SO_REUSEADDR` deviation stated in §1); RFC 9700 §2.1, §4.1.3, §4.4.2; RFC 6749 §4.1.3; RFC 9207 §2.4, §3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Who may present a token at the STS                      | Covered by analogy; list-thread guidance                                                             | RFC 8693 §2.1 (client identifier as an example `audience` value), §4.4 `may_act`; the splicing thread's `aud(N) = sub(N+1)`; GATE 3c                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Sender constraint, `cnf.jkt`, DPoP at the RS            | Covered by composition                                                                               | RFC 9449 §4.2, §5 ("regardless of grant type"), §5.2, §6, §7, §7.2; RFC 9700 §2.2.1; RFC 9449 never mentions exchange                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Client authentication of agent types                    | QAuth-defined; stricter than the drafts                                                              | draft-ietf-oauth-rfc7523bis-11 §4 item (b) (issuer as sole `aud`); `typ: client-authentication+jwt` required (departs from §4's NOT RECOMMENDED on rejecting untyped JWTs); CIBA Core 1.0 §7.1 audience list (departs); FAPI-CIBA working copy §4.1.1 note                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Audience narrowing per hop                              | Covered by analogy                                                                                   | RFC 8707 §2.2 "subset thereof" (code and refresh only), §3 multi-audience caveat; RFC 8693 §2.2.2 `invalid_target`; monotonicity across exchange is GATE 4b                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Purpose and ceilings                                    | Covered (mechanism); QAuth-defined (type)                                                            | RFC 9396 §2, §2.2, §6, §7, §9.1, §9.2, §12 (sanitise; bound by the type); RFC 9728 `authorization_details_types_supported`; the `agent-task` type and its subset rule are QAuth's, and §6.1 says no comparison is standardised; draft-hardt-oauth-aauth-protocol-11 §7.4 (agent-asserted consent text attributed to the agent); draft-mcguinness-oauth-mission-00 §5.1 (a subset rule for derived entries, individual)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `act.iss`, `sub_profile`, loose schema, preserve/extend | Proposed by draft                                                                                    | draft-mcguinness-oauth-actor-profile-00 §3.2, §3.4, §3.5, §3.6.3.1, §3.6.3.2, §3.7.1, §6.3.1.2, §14.7 (deviates), §14.12, §6.3 and §9 (deviates on error codes; see "Exchange error codes"); draft-mora-oauth-entity-profiles-01 §3.1.7, §4.2 (`ai_agent`, `sub_profile`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Presenter transition on spawn                           | QAuth-defined                                                                                        | Neither §3.7.2 continuation (that is the narrow) nor §3.7.3 rebind (no `actor_token`); §6.3.1 named as the future path                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Exchange error codes                                    | Covered; deviates from the actor profile                                                             | RFC 8693 §2.2.2 (`invalid_request` MUST for an invalid request or an invalid or unacceptable subject or actor token; `invalid_target` SHOULD for an audience or resource refusal; other codes as appropriate); RFC 6749 §5.2 (`invalid_scope` from GATE 4a, 4c, 4d and the assertion-scope check; `invalid_grant` on the code, refresh and CIBA grants); RFC 9449 §5 (`invalid_dpop_proof`); RFC 9396 §6 (`invalid_authorization_details`). draft-mcguinness-oauth-actor-profile-00 §9 agrees on `invalid_request` for a malformed `act`, a missing `act.sub` or `act.iss` and an over-deep chain, and on `invalid_scope`. It answers a token that fails validation, an untrusted issuer and an unconfirmed proof of possession with `invalid_grant` (§6.3: also an actor token carrying `act`), and an actor-policy failure with its new `actor_unauthorized`. QAuth answers both groups with RFC 8693's `invalid_request`, following the RFC's MUST as GATE 3–3c already do. So does every GATE 3d refusal: a refused spawn assertion or node, the allowlist checks the draft would call `actor_unauthorized`, and a `kind: elevation` subject. So do the §6 lock and the owner's revoke-all instant. Only a DPoP proof that fails RFC 9449 §4.3 stays `invalid_dpop_proof` |
| Spawn assertion                                         | QAuth-defined                                                                                        | Nearest: RFC 6749 §8.2 extension parameter; RFC 7521 assertion framework; draft-ietf-oauth-rfc7523bis-11 §4 item (b) `aud` rule, by analogy; RFC 8725 §3.11 explicit `typ` and §3.12 mutually exclusive validation (draft-ietf-oauth-rfc8725bis-10, in the RFC Editor queue, keeps both and adds a SHOULD to register the full media type; `spawn-assertion+jwt` is QAuth-private and unregistered, a stated deviation); draft-mcguinness-oauth-actor-proofs-00 §8 `actor_proof` (a per-hop signed JWT in the token request, but signed by the new actor, without `aud`, and optional unless policy requires it; here the parent signs, `aud` is the issuer, and it is mandatory); draft-liu §4.4 `delegator_signature` and §5.2 `delegatee_id`; draft-hardt-oauth-aauth-protocol-11 §10.2.3 (parent-mediated, child-key-bound); RFC 9449 §4.2 `ath` computation                                                                                                                                                                                                                                                                                                                                                                                                              |
| Per-hop lineage                                         | Proposed by draft (not adopted); QAuth ledger                                                        | draft-liu-oauth-chain-delegation-00 §4, §10.6 chain by reference; draft-mcguinness-oauth-actor-receipts-00 §7.2.2 (optional historical `cnf` per hop); draft-hardt-oauth-aauth-protocol-11 §10.2.3 (lineage held by the server)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Child bound to the exact parent token                   | Proposed by draft (idea reused)                                                                      | draft-niyikiza-oauth-attenuating-agent-tokens-01 §4.6 `par_hash`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Session identifier in access tokens                     | Registered claim; placement QAuth-defined                                                            | IANA JWT Claims `sid` (Front-Channel Logout 1.0 §3; Back-Channel Logout 1.0 §2.1); RFC 8417 §2.1.2 precedent; not in RFC 9068, not in the introspection registry                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Introspection members                                   | Covered / QAuth-defined                                                                              | RFC 7662 §2.2; registered `act`, `cnf`, `authorization_details`, `jti`; extension `sid`, `token_use`, `qauth_delegation` (cross-domain use would need Specification Required registration; `delegation` is OpenID Federation 1.0 §13.6)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Revocation cascade                                      | Covered (policy); QAuth-defined (API)                                                                | RFC 7009 §2.1 "related tokens and the underlying authorization grant"; RFC 9700 §4.14.2 (reuse detection; logout MAY revoke refresh tokens, and decision 1 keeps trees); revoke-by-`sid`/`jti`/agent/user endpoints are QAuth's                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Session-revoked signal                                  | Covered                                                                                              | SSF 1.0 §3.3 `complex`, §3.5 `jwt_id`, §7, §8.1.1; RFC 8935 push, RFC 8936 poll; CAEP 1.0 §3.1 (Final, 29 August 2025; approval announced 2 September 2025); RFC 9493 `opaque`, `iss_sub`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Resource-side action events                             | Covered (envelope); QAuth-defined (event type)                                                       | RFC 8417 §2.2 (`events`, `txn`, `toe`), RFC 8935 push; the `agent-action` URI is QAuth's                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Agent-side transmitters and their registration          | Covered (envelope); gap (registration); QAuth-defined (members)                                      | RFC 8935 push with out-of-band keys; SSF 1.0 §7–§8 stream management is receiver-initiated and does not fit a NAT'd transmitter; no CAEP or SSF event type describes an agent's action (CAEP 1.0 §3.1–§3.8 defines session revoked, established and presented, and token-claims, credential, assurance-level, device-compliance and risk-level changes — states of a session or subject, never an agent's act); the `model` and `reason` members and the server-written `agent_id` and `user_id` columns are QAuth's; both gaps are what QAuth takes to the Shared Signals WG (§7)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Agent identity record                                   | Proposed by draft (shape adopted); QAuth extension (avatar, bindings)                                | draft-wzdk-scim-agent-resource-00 §3, §4.1, §4.2 (`Agent` resource, `agentUserName`, `displayName`, `description`, `active`, `owners`, whose `value` §4.2 makes MUST and `$ref` RECOMMENDED; QAuth sends `value` only, and no `$ref` while it serves no SCIM `User`; no email, no avatar, no binding), RFC 7643 §3.3 extension schemas; the extension schema `https://schemas.qauth.dev/scim/extension/agent/1.0` is QAuth's, an HTTPS URI it controls (RFC 7643 §3.3 needs only a URI; an unregistered `urn:` namespace makes no URN, RFC 8141 §1); draft-ietf-wimse-aims-00 §10.3 keeps `client_id` = the acting workload, which is why the agent is not in `act` (§13)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Commit provenance                                       | Product convention; kernel process document                                                          | git author/committer identities; GitHub App bot login and `noreply` address; `Documentation/process/coding-assistants.rst` at v7.3-rc1 (only humans add `Signed-off-by`, reused; its `Assisted-by: LLM [TOOL1] [TOOL2]` is not adopted, and §9 refuses the line from the node, a stated deviation); GitHub signature verification reasons (`unknown_key`) for the parked signing question                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Out-of-band approval                                    | Covered (decoupled flow); QAuth-defined (elevation, mute, block, budget); three stated deviations    | OpenID CIBA Core 1.0 §7.1 (one hint of three, `binding_message`, `requested_expiry`, profile parameters; its client-assertion audience list not followed, §3), §7.2 (hint validation is the deployment's), §7.3 (`interval`), §8 with OpenID Connect Core 1.0 §3.1.2.4 (a window renewal resolves on the owner's standing decision), §10.1 (poll), §10.1.1 (one redemption; the OIDC Core §3.1.3.3 response with an ID token), §11, §13 (errors); RFC 9396 §3 (`authorization_details` in CIBA), §14.6; FAPI-CIBA working copy §4.1.1 (poll, `binding_message`, confidential clients, issuer as sole client-assertion audience; departs from its "should not" on authorization metadata in `login_hint_token`, §14); RFC 10027 (BCP 247) §2, §4.1.2, §4.3.9, §6.1, §6.2.2.2 (T8 is the risk assessment), and §5 and §6.2.2.5 with §2 item 3 (departs: same-device approval is discouraged, not prevented; T8); AuthZEN ARAP Draft 1 §7, §12, and the Access Request OAuth Profile (editor's draft; §14 follows its CIBA binding); draft-ietf-oauth-deferred-token-response-00 §9.1 (not chosen); draft-ietf-wimse-aims-00 §10.7; OID4VP 1.0 §8.4; WebAuthn Level 3 §4, §5.1, §5.8.8, §5.11, §13.4.9; NIST SP 800-63B-4 §3.2.5                                                 |
| Decision API                                            | Covered; WG-draft binding; QAuth context                                                             | AuthZEN 1.0 §6.1, §9.2, §10.1, §11.2 (Final, 11 January 2026); COAZ-MCP Binding §7.1, §11.2 (WG Draft 1); `context.qauth` is QAuth's; ARAP noted; AuthZEN token issuance profile (WG Draft 1, 4 September 2026) and token exchange binding (WG Draft 1, 2 September 2026) noted for a PDP at the spawn (§8)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Agent framework vocabulary                              | WG draft (Informational); §11 partly met                                                             | draft-ietf-wimse-aims-00 §8 (LLM never holds credentials), §10.3 (`client_id` = agent, `sub` = user), §10.7 (human in the loop via CIBA; local UI confirmation alone is never authorization — the basis of §14 and §9), §11 (audit minimums: six of the seven MUST fields are recorded across the ledger, `agent_actions` and the broker log, joined on `jti`; no record carries a posture or risk state, since no decision here reads one; records are durable and retained but not tamper-evident, a stated gap; draft-gilda-wimse-agent-audit-record-01 is a candidate signed export format, not adopted)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| CLI credentials                                         | Product documentation                                                                                | PostgreSQL 18 `oauth` HBA and validator API; GitHub App installation tokens; git-credential protocol; `gh` environment precedence; octo-sts                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Vitrin                                                  | Workstream prose, no decision-log id                                                                 | WS-D §7.2, §7.3, §7.5 (workstream prose) and §7.6 (the one section headed DECIDED in `docs/plan/13-workstream-agent-integration.md`); vitrin's normative entry is owed and may amend the 300 s figure                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

### Watch list

Rows go into [`docs/spec-pin-log.md`](../spec-pin-log.md) with P0, each with
a `Re-check by` date no later than its expiry — `spec-pins.test.ts` fails the
build on a past date. Dates are each draft's own header date and `Expires`
line. Where the IETF index posts a draft on a later day, the row shows both,
and the earlier expiry bounds the re-check. The one exception is a draft in
the RFC Editor queue. It does not lapse (RFC 2026 §2.2 removes only a draft
the IESG has not recommended), so its header `Expires` line does not bind.
Its `Re-check by` is its nominal expiry, 185 days after the index posted it,
and its next pin is normally the RFC.

| Document                                                                                                                                 | Revision · date                                                                                                                                                                                                                                | Expires                                                                                   | Why watched                                                                                                                                                                                                                                                                                                                                   |
| ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| draft-mcguinness-oauth-actor-profile (individual)                                                                                        | `-00` · 30 Apr 2026                                                                                                                                                                                                                            | 1 Nov 2026                                                                                | `act` shape adopted; `sub_profile` and `ai_agent` come from draft-mora-oauth-entity-profiles (next row)                                                                                                                                                                                                                                       |
| draft-mora-oauth-entity-profiles (individual)                                                                                            | `-01` · 15 Apr 2026                                                                                                                                                                                                                            | 17 Oct 2026                                                                               | defines `sub_profile` (§4.2) and the `ai_agent` value (§3.1.7) that this record's §3 sets; the actor profile depends on it normatively and outlives it; this record's §3 fallback applies if it lapses                                                                                                                                        |
| draft-mcguinness-oauth-actor-proofs / -actor-receipts / -mission / -token-exchange-cnf (individual)                                      | `-00` · 4 Jul / 4 Jul / 6 Jul / 19 Jul 2026                                                                                                                                                                                                    | 5 Jan / 5 Jan / 7 Jan / 20 Jan 2027                                                       | nearest precedent for the spawn assertion (proofs §8); optional historical per-hop `cnf` (receipts §7.2.2); a mission claim and subset rule beside `sid` and §5 (mission §5.1, §8.1); an exchange-response `cnf`                                                                                                                              |
| draft-mcguinness-oauth-client-instance-id (individual; replaces client-instance-assertion)                                               | `-00` · 28 Sep 2026                                                                                                                                                                                                                            | 1 Apr 2027                                                                                | attester-assigned instance id, never inferred from a thumbprint and never added to `act` (§5); needs an attester, not adopted                                                                                                                                                                                                                 |
| draft-mcguinness-oauth-ai-agent-instance (individual; profiles the replaced client-instance-assertion)                                   | `-00` · 4 Jul 2026 (posted 5 Jul)                                                                                                                                                                                                              | 5 Jan 2027 (index: 6 Jan)                                                                 | attested `agent_instance_id` surfaced as `act.sub` (§8), unlike client-instance-id; sub-agents by exchange (§9); local CLI agents (§12); not adopted                                                                                                                                                                                          |
| draft-liu-oauth-chain-delegation (individual)                                                                                            | `-00` · 6 Jun 2026 (posted 8 Jun)                                                                                                                                                                                                              | 8 Dec 2026 (index: 10 Dec)                                                                | `delegation_chain` trigger                                                                                                                                                                                                                                                                                                                    |
| draft-niyikiza-oauth-attenuating-agent-tokens (individual)                                                                               | `-01` · 15 Jun 2026                                                                                                                                                                                                                            | 17 Dec 2026                                                                               | attenuation invariants                                                                                                                                                                                                                                                                                                                        |
| draft-asor-wimse-agent-delegation-chain (individual)                                                                                     | `-01` · 3 Sep 2026                                                                                                                                                                                                                             | 7 Mar 2027                                                                                | an RFC 9068 profile: RAR `agent_delegation` authority, a `par_hash` commitment to the exact parent (§5), DPoP `cnf`, and an offline verifier of attenuation, depth and expiry (§4.3, §6) — part of the invariant carried on the token rather than in the ledger; no `aud` rule, no on-behalf-of; converges with draft-niyikiza; not adopted   |
| draft-ietf-wimse-aims (WG, Informational; replaces draft-klrc-aiagent-auth)                                                              | `-00` · 15 Sep 2026                                                                                                                                                                                                                            | 19 Mar 2027                                                                               | audit minimums (§11, partly met, Standards position); human in the loop (§10.7); the LLM has no access to an agent's credentials (§8)                                                                                                                                                                                                         |
| draft-ietf-oauth-transaction-tokens (WG)                                                                                                 | `-11` · 30 Jul 2026                                                                                                                                                                                                                            | 31 Jan 2027                                                                               | rejected as session id; `txn` reused                                                                                                                                                                                                                                                                                                          |
| draft-ietf-oauth-identity-assertion-authz-grant (WG)                                                                                     | `-04` · 21 May 2026                                                                                                                                                                                                                            | 22 Nov 2026                                                                               | ADR-011 pin; actor profile layers on it                                                                                                                                                                                                                                                                                                       |
| draft-ietf-oauth-client-id-metadata-document (WG)                                                                                        | `-02` · 6 Jul 2026                                                                                                                                                                                                                             | 7 Jan 2027                                                                                | agent client naming                                                                                                                                                                                                                                                                                                                           |
| draft-ietf-oauth-rfc7523bis (WG)                                                                                                         | `-11` · 26 Mar 2026 (posted 28 Apr 2026)                                                                                                                                                                                                       | header 27 Sep 2026 (does not bind: RFC Editor queue); re-check by the nominal 30 Oct 2026 | `aud` = the issuer identifier as sole value for client authentication (§4 item (b)), adopted for agent types (this record's §3) and by analogy for the spawn assertion; the next change is normally the RFC — re-pin to it                                                                                                                    |
| draft-ietf-wimse-workload-creds / -wpt (WG; s2s-protocol is dead)                                                                        | `-02` · 2 Jul / 27 Aug 2026                                                                                                                                                                                                                    | 3 Jan / 28 Feb 2027                                                                       | one identity per credential                                                                                                                                                                                                                                                                                                                   |
| draft-oauth-ai-agents-on-behalf-of-user (individual)                                                                                     | `-02` · 26 Aug 2025                                                                                                                                                                                                                            | expired 27 Feb 2026, no successor                                                         | expired; its consent-time disclosure of the acting party is the precedent for §11's allowlist line; `requested_actor` itself not adopted                                                                                                                                                                                                      |
| AuthZEN COAZ-MCP Binding / ARAP (OIDF WG drafts)                                                                                         | Draft 1 · COAZ-MCP at openid/authzen `ca92c756` (10 Sep 2026; its `date:` line still reads 13 Feb) / ARAP at `e94e0a26` (25 Aug 2026) (ARAP a WG draft since 2 Jun 2026, openid/authzen#508; the OIDF announced both as WG drafts 15 Jun 2026) | —                                                                                         | request shape; park-and-approve; open ARAP issues openid/authzen#659 and openid/authzen#662 touch the approval payload and binding rules that this record's §8 and §14 borrow                                                                                                                                                                 |
| AuthZEN Access Request OAuth Profile (OIDF editor's draft, unpublished)                                                                  | Draft 1 at openid/authzen `483abc2b` (5 Jul 2026)                                                                                                                                                                                              | —                                                                                         | the profile ARAP defers to; §14 follows its CIBA binding                                                                                                                                                                                                                                                                                      |
| draft-rosomakho-oauth-txn-challenge (individual)                                                                                         | `-00` · 25 Jun 2026                                                                                                                                                                                                                            | 27 Dec 2026                                                                               | that profile's resource-initiated transport, for the mcp-guard refusal                                                                                                                                                                                                                                                                        |
| draft-ietf-oauth-deferred-token-response (WG; replaces draft-gerber-oauth-deferred-token-response)                                       | `-00` · 16 Sep 2026                                                                                                                                                                                                                            | 20 Mar 2027                                                                               | the deferral alternative to §14's CIBA request (Alternatives); not chosen                                                                                                                                                                                                                                                                     |
| draft-ietf-oauth-rar-metadata-remediation (WG; replaces draft-zehavi-oauth-rar-metadata)                                                 | `-00` · 23 Aug 2026                                                                                                                                                                                                                            | 24 Feb 2027                                                                               | a resource refusal (401 `insufficient_authorization`) carrying the exact `agent-task` delta for §14 step 1 (§4), and an AS endpoint for each type's JSON Schema (§5); not adopted — a remediation would be a request QAuth checks, never a grant                                                                                              |
| AuthZEN Token Issuance Profile / Token Exchange Binding (OIDF WG drafts; continue draft-gazitt-oauth-authzen-issuance / -token-exchange) | Draft 1 · issuance at openid/authzen `0c0f21e3` (4 Sep 2026) / token exchange at `e52693f7` (2 Sep 2026) (I-D `-01` · 2 Sep 2026)                                                                                                              | 6 Mar 2027 (I-D)                                                                          | a PDP at the spawn exchange (§8): after the gates, refuse-only, fail-closed; not adopted                                                                                                                                                                                                                                                      |
| FAPI-CIBA (OIDF, Implementer's Draft)                                                                                                    | working copy `fapi-ciba-03` · openid/fapi `a50bb96b` (19 Aug 2026)                                                                                                                                                                             | —                                                                                         | §14 follows its poll, `binding_message`, confidential-client and sole-audience choices, and departs from its §4.1.1 "should not" on `login_hint_token` (§14)                                                                                                                                                                                  |
| MCP Authorization                                                                                                                        | 2026-07-28                                                                                                                                                                                                                                     | —                                                                                         | EMA still the only STABLE `ext-auth` extension                                                                                                                                                                                                                                                                                                |
| draft-wzdk-scim-agent-resource (individual, Informational)                                                                               | `-00` · 5 Jun 2026                                                                                                                                                                                                                             | 7 Dec 2026                                                                                | `Agent` resource shape adopted (§13). It consolidates draft-abbey-scim-agent-extension (expired 19 Apr 2026) and draft-wahl-scim-agent-schema (IETF 126 slides); the IETF 126 adoption call found no consensus, so it stays individual. Re-pin to its next revision or to a SCIM WG draft that replaces it; a rename changes §13's schema URN |
| draft-kushwaha-scim-agent-governance (individual)                                                                                        | `-00` · 26 Jul 2026 (posted 27 Jul)                                                                                                                                                                                                            | 27 Jan 2027 (index: 28 Jan)                                                               | lifecycle and autonomy extension on the same resource; not adopted, watched for the avatar/binding question                                                                                                                                                                                                                                   |
| Shared Signals WG agentic extension (OIDF)                                                                                               | announced Jul 2026, no draft yet                                                                                                                                                                                                               | —                                                                                         | where the `agent-action` event type and a transmitter-initiated registration would be proposed (§7)                                                                                                                                                                                                                                           |
| Linux `Documentation/process/coding-assistants.rst`                                                                                      | `v7.3-rc1` · 30 Aug 2026 (first in v7.0-rc1, 22 Feb 2026, as `AGENT_NAME:MODEL_VERSION`; released in v7.0, 12 Apr 2026)                                                                                                                        | —                                                                                         | §9 reuses its human-only `Signed-off-by` and refuses the `Assisted-by` line its step 6 asks an assistant to add (QAuth's rule, a stated deviation); re-pin at the v7.3 release, and re-read §9 against any change there                                                                                                                       |
| draft-hardt-oauth-aauth-protocol (individual)                                                                                            | `-11` · 25 Sep 2026                                                                                                                                                                                                                            | 29 Mar 2027                                                                               | parent-mediated sub-agent tokens bound to the child's key, lineage held by the server and absent from the tokens (§10.2.3); one level of sub-agents (§10.2.2); attributed agent-asserted consent text (§7.4); `act` removed in this revision; not adopted                                                                                     |
| draft-richer-oauth-oob-authcode (individual)                                                                                             | `-00` · 28 Sep 2026                                                                                                                                                                                                                            | 1 Apr 2027                                                                                | a code return leg without a loopback listener, for a browser on another host (§1); not adopted                                                                                                                                                                                                                                                |

## Explicitly out of scope

Machine-to-machine trees with no human root: exchange refuses a
`client_credentials` subject, and this record keeps it so. Cross-domain trees:
an ID-JAG or identity-chaining hop ends the tree at the domain boundary, and
the ID-JAG mint path of ADR-011 stays outside it — an assertion minted from a
tree token carries no `act` and no `sid`, the ledger records the mint as a
`kind: id-jag` row that can have no children, and the foreign AS's tokens are
outside the tree. This fits draft-ietf-oauth-identity-chaining-17, now in the
RFC Editor queue. Its §2.3.2 and §2.5 let the first domain's AS change or
leave out claims when it transcribes them, so an assertion with no `act` and
no `sid` conforms. With the flag on an agent type mints no ID-JAG (§4), so
such a row comes only from a client that is not an agent type. A
vitrin restore-token analogue or any durable rung: a later ADR after vitrin's
E3.7, if ever. A policy language for the PDP: AuthZEN carries the question,
not the policy. Attestation of the process that holds a key:
draft-ietf-oauth-attestation-based-client-auth is not evaluated here. Nor are
the attested instance identifiers profiled on it (Alternatives). A realm-admin
or operator role: QAuth has none ([ADR-012](./012-dynamic-client-ownership.md)
§4) and this record defines none, so every power in §13 stays the owner's
until a later record adds one.

**The agent's own systems.** Everything an agent principal (§13) does with
its identity outside QAuth is the owner's domain, recorded in the owner's own
decision record, not this one: provisioning the platform side of a binding
(creating the GitHub App, uploading its logo, setting a Matrix avatar); the
runtime, memory and planning layers that produce a `reason`; the proxy or
harness that reports a `model`; the index that resolves a commit hash to a
node (QAuth stores the pushed hashes the broker's `git-push` SET carries, §9,
and serves them to the owner — it builds no resolver, §13); the wording of a
commit message beyond the lines the broker writes or refuses (§9); commit
signing (decision 12); and any public claim made in the agent's name that
QAuth did not itself record. QAuth's rule for all of it is T7: a claim stays
a claim, the ledger row is the fact, and nothing QAuth serves blurs the two.

## Phasing

Each phase is one or two mergeable PRs with named tests; no phase loosens a
gate. The one loosening of shipped behaviour is decision 1's sign-out rule,
the maintainer's choice; it lands in P2 with revoke-all.

- **P0 — the root is observable, and answers "which agent, in which session,
  with which scopes, opened this PR".**

  **0a, server:**

  - the `AGENT_TREE_ENABLED` switch as the Decision defines it;
  - `sid` on agent tokens (code, refresh, exchange) and the `refresh_tokens.sid`
    column;
  - `agent_token_ledger` and its repository;
  - ledger writes at the three mint sites;
  - the sid-less-subject rule and the NULL-`sid` refresh rule;
  - introspection members `jti`, `sid`, `token_use`, `act`, `qauth_delegation`;
  - `GET /api/agent-sessions` and `/{sid}` under the owner-route guard (§6);
  - the consent rules for agent clients (§11);
  - the client-assertion rule for agent types (§3);
  - the root's issued `aud` stored on its refresh row (§11);
  - the refresh ledger write inside the rotation transaction (§6);
  - `sid` following the refresh row (§1);
  - each added route's rate limit (Decision);
  - the GitHub STS on an operator-set per-type policy;
  - spec-pin rows with their `Re-check by` dates.

  In P0 the STS accepts a bearer leaf whose `aud` is exactly its identifier and
  that has a live ledger row, narrowed from the node token (no proof until P1a).
  The broker's root `aud` is the seeded `audience` allowlist — own `client_id`,
  child types, the STS identifier — since the broker sends no `resource`. That
  column is P0's interim carrier of child types; P1b moves them to
  `spawn_allowlist`, leaving `audience` to name resources. `audience` is also
  the `client_credentials` resource allowlist and the ID-JAG target allowlist.
  So P0 seeds give agent types no `client_credentials` grant, and with the
  flag on GATE 2 refuses an agent type's ID-JAG mint (`invalid_request`, §4).
  A PR opened through a GitHub MCP server is outside this answer until P3.

  Tests:

  - with the flag off, every token and the exchange are byte-identical to
    today's and no ledger row exists;
  - claim presence and inheritance across code → refresh → exchange;
  - one ledger row per `sid`-carrying mint and none for `client_credentials`,
    and a failed write fails the mint;
  - a sid-less subject starts a new tree with a `kind: root` row whose `depth`
    is the minted token's `act` depth;
  - a pre-migration refresh family gains a `sid` on its next refresh;
  - the introspection schema;
  - the STS refuses a repository outside policy, against a mock GitHub;
  - with the flag on, the Bearer path of `/oauth/authorize` answers
    `access_denied` for an agent client, audited, and mints no code, `sid` or
    ledger row;
  - with the flag and `ID_JAG_ENABLED` on, an agent type's ID-JAG mint answers
    `invalid_request`, audited, and mints no assertion and writes no ledger row,
    while a `sid`-carrying ID-JAG mint by an agent client that is not an agent
    type writes one `kind: id-jag` row;
  - with the flag off, both paths of `/oauth/authorize` (the browser path and
    the Bearer path) and an agent type's ID-JAG mint are byte-identical to
    today's;
  - two concurrent refreshes of one family write one ledger row and one answers
    `invalid_grant`;
  - a ledger write failure on a refresh leaves the presented refresh token
    usable;
  - a CIMD family whose document drops `is_agent` keeps its `sid` and ledger
    rows, and one whose document gains it gets a `sid` at its next refresh;
  - a refresh never widens a root's `aud` after the operator widens `audience`;
  - the STS refuses a disabled user, a token with no ledger row, and a token
    whose `aud` is not exactly its identifier;
  - an agent type's client assertion whose `aud` is the token endpoint URL or
    holds a second value, or that has no `typ`, is `invalid_client`;
  - a root or node token is refused on `GET /api/agent-sessions`, and user A's
    management token cannot read user B's `sid`.

  **0b, broker:** `login` on an ephemeral loopback port with PKCE and the
  `state`, `iss` and redirect-URI checks (§1), one refresh of a root in flight
  (§4), git-credential `get`, the `gh` shim, the commit trailer, the log. Tests:

  - vend within policy, refusal logged, a `setsid`/double-forked descendant of a
    read-only node is refused, not attributed to the session;
  - a process that reuses an exited teammate's pid is refused;
  - installation token deleted at node end;
  - a session resumed at launch with the same `session_id` reuses its root
    while the grant's refresh token lives, and runs no new `login`;
  - a second `SessionStart` registration from a bound pid runs no `login` and
    writes no ledger row, whether or not it repeats the bound `session_id`;
  - a repeat registration from a bound teammate pid spawns no second
    teammate node;
  - a trailer resolves to a ledger row;
  - the token request repeats the authorization request's `redirect_uri`, port
    included;
  - two concurrent logins on one box both complete;
  - a response without `iss`, or with another issuer's, is refused before any
    token request;
  - `login` fails when `127.0.0.1` cannot be bound, with no fallback (the
    server-side any-port match is already tested on main, 34a0ec7c).

  **0c, agent identity:** the `agents` and `agent_bindings` tables and their
  owner writes, under the owner-route guard (§6), `agent_id` on the
  authorization request, on `refresh_tokens` and on the ledger's root row (§1,
  §2), the verified-address rule (§13) at agent creation, at binding and in the
  owner check at authorization, `qauth_delegation.agent`, the consent line
  (§11), the public profile, and the broker's author identity and
  `Agent:`/`Model:` lines from the binding (§9); revocation by agent, revoke-all
  and transfer wait for the §6 walk in P2. Tests:

  - a grant naming an agent the `sub` does not own fails `invalid_request`; a
    grant naming an inactive agent fails the same way;
  - a grant naming none is byte-identical to today's;
  - every descendant row carries the root's `agent_id`;
  - the profile of a private agent is 404 and the profile of a public one
    carries no `sid`, `jti` or scope;
  - a commit made through the broker under an agent root is authored by the
    binding's login and address;
  - a node-supplied `Signed-off-by` is refused;
  - creating an agent, binding one to a platform, or naming one in a grant
    fails, audited, for an owner whose address is not verified, with
    `REQUIRE_EMAIL_VERIFIED` at its default `false`;
  - a root, node or leaf token is refused on creating, editing, binding or
    deactivating an agent, and user A's management token cannot write user B's
    agent or binding;
  - the public profile names the current owner.

  Honest limits: the spawn proof is possession-only until P1; the MCP leg is
  still Claude Code's own non-agent DCR/CIMD client, which never sends
  `is_agent`, so it is outside the tree until P3 (Harness reality, row 8);
  same-type children are told apart by ledger rows only; and the platform side
  of a binding is provisioned by the owner, outside this record.

- **P1 — keys and the tree.**

  **1a:** DPoP at the token endpoint (`cnf.jkt`, `token_type`, nonce),
  `dpop_bound_access_tokens` in the seed manifest,
  `AGENT_BEARER_LEAF_RESOURCES`, key custody in the broker, `private_key_jwt`
  at introspection and revocation
  with their RFC 8414 §2 signing-algorithm members, the introspection member
  `cnf`, and `dpop_signing_alg_values_supported` in AS metadata (RFC 9449 §5.1).
  Until 1b lands, an exchange whose subject carries `cnf` succeeds only when its
  DPoP proof is under the subject's own `cnf.jkt` (a same-key narrow;
  `invalid_request` otherwise), so a spawn waits for 1b.

  **1b:** `spawn_assertion` and GATE 3d, GATE 4d, narrow versus spawn and node
  identity, the `act` shape and loose schema, `spawn_allowlist` and `aud`
  enrichment with the 3d allowlist check, the `spawn_allowlist` CHECK, the
  allowlist check on every exchange of a `sid`-carrying subject by another
  client (§4), enrichment only at the code and refresh grants (§11),
  `spawn_receipt`, the renewal sweep.

  Tests:

  - a proof under the wrong key fails;
  - a `cnf` subject exchanged to a new key without an assertion fails
    `invalid_request`;
  - a replayed assertion fails;
  - with the replay store unwritable, a re-spawn answers 503 with `Retry-After`,
    mints nothing and writes no ledger row, and the broker neither revokes the
    node nor stops signing for its key;
  - a root grant carrying `agent:exec agent:readonly write:foo read:foo` spawns
    a read-only child and the child's exchange for `write:foo` fails
    `invalid_scope` at 4a, and at 4d when its type is registered without it;
  - a `reviewer` seeded without an allowlist cannot spawn a `reviewer` even when
    its `aud` names it;
  - `claude-code` spawning `claude-code` fails when its allowlist omits itself;
  - a same-key narrow leaves `act` byte-identical and depth unchanged;
  - a new key nests `act` once;
  - a leaf cannot spawn;
  - a spawn that omits `scope`, from a parent holding `write:foo`, fails
    `invalid_scope` when the child type is registered without it or the
    assertion's `scope` lacks it;
  - a spawn naming no audience, from a parent whose `aud` names a type outside
    the child's allowlist, fails `invalid_target`;
  - an exchange of a `sid`-carrying bearer subject by a type outside the subject
    type's allowlist fails;
  - a spawn assertion whose `aud` is an array of two values fails;
  - writing a non-empty `spawn_allowlist` to a DCR, CIMD or developer-owned row
    fails at the database;
  - a refresh after the operator widens `spawn_allowlist` does not widen the
    live root's `aud`.

- **P2 — purpose, ceiling, revocation.** It builds:

  - the `agent-task` RAR type end to end with server-written `caused_by` and the
    introspection member `authorization_details`;
  - the consent ceiling and the persistence rung (§11), which lands with the
    sign-out exemption;
  - revocation by `sid` and `jti`, the identifier API, the cascade and ancestry
    ownership;
  - the `agentAccessTokenLifespan` row;
  - the CAEP transmitter;
  - the STS narrowed by `authorization_details`;
  - `POST /api/agents/{id}/revoke` with its owner-only rule (§13);
  - `POST /api/agent-sessions/revoke-all`, the `agent_trees_revoked_before`
    instant and the sign-out exemption for `sid`-carrying families of agent
    clients (decision 1);
  - the transfer offer, its withdrawal and lapse, and the transfer transaction
    the recipient's acceptance runs (decision 10), open only to a recipient with
    a verified address (§13);
  - the family-ends-tree rule, including the client-deletion walk, anchor rows
    and lock order (§6);
  - the seed tool's cap-lowering walk;
  - the owner-route guard on every owner revocation route and on the offer,
    withdrawal and acceptance routes.

  Not in P2: the transfer transaction's disabling of the previous owner's
  `agent_transmitters` rows. It lands with that table in P3 (§13).

  Tests:

  - widened `locations` fails `invalid_authorization_details`;
  - a client-supplied `caused_by` is rejected;
  - revoke-by-agent makes every tree rooted in the agent inactive and leaves the
    owner's other agents' trees alone, and a node, or any user who is not the
    agent's current owner, calling it revokes nothing;
  - revoke-by-`sid` makes every descendant inactive at introspection and in the
    denylist;
  - a spawn or renewal whose parent row is revoked fails `invalid_request`;
  - a denylist write failure mid-cascade answers 503 and leaves every marked row
    inactive at introspection;
  - revoke-by-`jti` leaves siblings active;
  - a revoked node is not renewed by the next sweep (the re-spawn for its key
    fails `invalid_request`);
  - a `revoked_at` subject token whose `jti` is not yet denylisted cannot spawn
    (`invalid_request`; the denylisted case is GATE 3a's, already tested);
  - revoking the root's `jti` refuses the next refresh;
  - a main-agent process's exit, with QAuth reachable, revokes its root, `sid`
    and refresh family, and a session then resumed at launch runs a new
    `login` (§1, §6);
  - the consent screen shows the union of modes, the allowlist and the
    persistence rung, and with the flag off it shows no rung;
  - each of these makes every descendant inactive at introspection and in the
    denylist, emits `session-revoked`, and makes the STS refuse the next vend:
    - RFC 7009 revocation of the root refresh token;
    - consent withdrawal through `/consents` and through `/api/consents`;
    - a replayed root refresh token;
    - a lost concurrent rotation;
    - a root refresh presented after its user is disabled;
    - the deletion of a developer-owned agent client through
      `DELETE /api/clients/{id}`;
  - that deletion emits `initiating_entity` `admin`, keeps the tree's ledger
    rows, and also ends a node of another tree whose row names the deleted
    client, with its subtree; a walk failure leaves the client undeleted; with
    the flag off, `DELETE /api/clients/{id}` runs no walk and is byte-identical
    to today's;
  - revoke-all makes every tree of the user inactive and emits one
    `session-revoked` per `sid`, and a spawn racing it fails;
  - revoke-all revokes the user's NULL-`sid` agent refresh families. After it,
    a NULL-`sid` family whose CIMD document gains `is_agent` answers
    `invalid_grant` at its next refresh and writes no `sid` or ledger row,
    whether the family was issued before or after the revoke-all;
  - an agent client's code issued before revoke-all and redeemed after it
    answers `invalid_grant`, audited, and mints no token, `sid` or ledger row;
  - a sid-less subject issued before revoke-all and exchanged after it answers
    `invalid_request`, audited, and starts no tree;
  - with the flag on a portal sign-out leaves every tree of an agent client
    active, revokes a `sid` family whose client is no longer an agent client and
    ends its tree, and revokes an agent client's NULL-`sid` family, which starts
    no tree; with it off the sign-out is byte-identical to today's;
  - a refresh racing revoke-by-`sid` leaves no live refresh token and no
    unmarked row;
  - a renewal racing revoke-by-`jti` of its own node leaves that node no live
    token;
  - lowering the root type's `max_agent_mode` through the seed tool revokes
    every over-cap node, the next unnarrowed root refresh fails, and the broker
    ends the `sid` without filing a request;
  - a root, node or leaf token is refused on every owner route, and user A's
    management token cannot read or revoke user B's `sid`, `jti` or agent, offer
    user B's agent to anyone, or accept an offer made to user B;
  - an accepted transfer cuts every live tree of the agent in the acceptance's
    own transaction, and from the acceptance `owner_user_id` and the profile
    name the new owner;
  - an action taken after the acceptance with a token a cut tree minted before
    it is recorded under the previous owner, and earlier rows keep that owner's
    `user_id`;
  - the new owner's first root is a new code grant by the new owner;
  - after a transfer the STS refuses a vend for the new owner's tree in the
    agent, with no fallback to a per-organisation App, the broker sets no author
    identity and the profile lists no suspended binding, until the new owner
    binds the agent again;
  - binding the agent again writes a new row and leaves every column of the
    suspended row as it was, no route clears `suspended_at`, and a second live
    row for one (agent, platform) is refused;
  - an offer not yet accepted, a withdrawn offer and a lapsed offer each leave
    the agent's owner, public profile, live trees and bindings as they were, and
    neither a withdrawn nor a lapsed offer can be accepted;
  - only the named user's management token accepts an offer, and a root, node or
    leaf token is refused on the offer, withdrawal and acceptance routes;
  - the offer route answers the same for a verified account, an unverified one
    and none;
  - an acceptance by a user whose address is not verified is refused, audited,
    and changes nothing.

- **P3 — observation.** It builds:

  - the RFC 8935 push endpoint and event type;
  - the `agent_actions` table;
  - the seed-only `event_audiences` column on `oauth_clients` with its CHECK
    (§7), and `AGENT_EVENT_WINDOW`;
  - mcp-guard normalises `act`/`sid`/`jti`, verifies DPoP per resource and emits
    events;
  - the broker's proxy and `headersHelper` leaves, so the MCP leg joins the
    broker's root and gains its `sid`;
  - the portal's live tree (`GET /api/agent-sessions/{sid}/events`, under the
    owner-route guard, §6);
  - the `agent_transmitters` row, registered under the owner-route guard (§6),
    and the one-hop subject rule for agent-side SETs;
  - the `disabled_at` column with its refusal (§7);
  - the P2 transfer transaction extended to disable, and keep, the previous
    owner's `agent_transmitters` rows for the agent (§13);
  - the `model` and `reason` members and the server-written `agent_id` and
    `user_id` columns, the `source` column with its three values shown apart,
    and the broker's `pre-push` SET (§7, §9);
  - the SCIM `GET /scim/v2/Agents` projection (§13).

  Tests:

  - an event by `jti` lands on the right node;
  - a revoked `sid` reaches the broker by poll, and a refused re-spawn reaches
    it with polling off; either deletes its installation tokens;
  - a foreign local process — another uid, or a container on host networking —
    cannot obtain a signed request or a DPoP proof from the proxy;
  - mcp-guard with DPoP on rejects a bound token presented as Bearer (RFC 9449
    §7.2), with DPoP off accepts it;
  - an agent-side SET for a `jti` outside the trees the transmitter's owner
    rooted in its agent is refused;
  - a transmitter-supplied `agent` member is refused and the stored row carries
    the ledger's;
  - `model` and `reason` never reach introspection or the §8 request;
  - the SCIM projection returns the owner as `owners[0]`, whose `value` is the
    owner's `users.id` and which carries no `$ref` and no `displayName`, and
    rejects writes;
  - the SCIM projection returns only the caller's own agents under the
    owner-route guard;
  - writing a non-empty `event_audiences` to a DCR, CIMD, developer-owned or
    `is_agent` `oauth_clients` row fails at the database, and a seeded non-agent
    row for an mcp-guard host or a validator accepts it;
  - an agent-side transmitter is refused for an owner without a verified
    address;
  - a root, node or leaf token is refused on transmitter registration and on
    `/{sid}/events`, and user A's management token can neither register a
    transmitter for user B's agent nor read user B's events;
  - an open transfer offer leaves the previous owner's `agent_transmitters` rows
    live. After an accepted transfer they are disabled and still present, and no
    route clears `disabled_at`. A SET signed by one of them is refused and
    stores nothing, whether its `jti` is in the new owner's tree or a
    pre-transfer one;
  - after the acceptance, a SET from a transmitter the new owner
    registered, naming a `jti` in a tree the previous owner rooted, is refused
    and stores nothing, and the same transmitter's SET for a `jti` in the new
    owner's tree is stored;
  - every pre-transfer `source: agent` row still names its transmitter row, and
    deleting a transmitter row that an `agent_actions` row names fails at the
    database;
  - `agent_actions` rows for actions before the moment of transfer keep the
    previous owner's `user_id`. So does the row that a resource-side SET for a
    pre-transfer `jti` writes after the transfer. A row for the new owner's tree
    carries the new owner's `user_id`.

- **P4 — the database, the decision API and vitrin.** `qauth_pg_validator`, the
  libpq hook library and the `psql` path; AuthZEN evaluation and metadata,
  default off; COAZ-MCP online mode in mcp-guard; the vitrin verifier
  contribution once https://github.com/vitrin-os/vitrin-os/issues/167 is
  scheduled; re-pin every watch-list row; `delegation_chain` if its trigger
  fired. Tests:

  - the validator refuses a token whose `aud` is not the database and a role
    outside `actions`;
  - the PDP can deny but never widen.

- **P5 — remote approval (after P2).** It builds:

  - a WebAuthn credential provider, which QAuth has none of today, with passkey
    registration and assertion only on pages the auth server serves on QAuth's
    origin, which the portal links to (§14);
  - passkey only, no TOTP (decision 15);
  - the CIBA backchannel endpoint in poll mode, with `login_hint_token` = the
    requesting node's token;
  - `AGENT_APPROVAL_ENABLED`, `AGENT_APPROVAL_EXPIRY` and
    `AGENT_APPROVAL_BUDGET`;
  - the `agent:request` scope, reserved and dangerous under the flag (§14);
  - the delta checks, the hint checks, the CIBA ID token and window renewal by
    CIBA (§14);
  - the `interval` and `slow_down`;
  - the `agent_approvals` table;
  - the `kind: elevation` ledger row with its `approval_receipt`;
  - GATE 3d's refusal of a `kind: elevation` subject (§4);
  - the approval page;
  - web push and the owner-registered webhook;
  - passkey and approval-channel registration under the verified-address rule
    (§13);
  - mutes and standing blocks;
  - the owner's portal routes that end a window, remove a standing block and
    register a web-push subscription or webhook, each under the owner-route
    guard (§6).

  Tests:

  - an elevation carries exactly the approved delta and one audience;
  - a `kind: elevation` subject cannot spawn or narrow;
  - a request without `agent:request`, over budget, or whose user has
    registered no approval passkey is refused and notifies no one;
  - a muted `sid` is refused and notifies no one;
  - a new approval without a fresh passkey assertion bound to the request is
    refused; a renewal inside an open window needs none;
  - the page's headline is the typed delta and `purpose` renders only in the
    attributed box;
  - revoke-by-`sid` ends an open window;
  - a window never outlives the refresh family;
  - a notification body carries only the request id, the agent's handle and the
    URL;
  - a delta outside the type's registered scopes, above its `max_agent_mode`,
    carrying `agent:request`, naming a resource outside the node token's `aud`,
    or naming a resource listed in `AGENT_BEARER_LEAF_RESOURCES` is refused and
    notifies no one, and so is a renewal after the operator narrows the type or
    lists the resource;
  - a token exchange asking for an approved delta is still refused by GATE 4a,
    4b or §5, window open or not;
  - a renewal after the window ends, after revoke-by-`sid`, from a muted or
    blocked `sid` or for another delta is not resolved silently;
  - a renewed leaf never outlives the window;
  - a second poll of a redeemed `auth_req_id` fails `invalid_grant`;
  - a revoked, expired, leaf, bearer or foreign-key hint is refused and notifies
    no one, and so is a request with `login_hint` or `id_token_hint`;
  - a disabled user's request notifies no one, and a user disabled after the
    approval gets no leaf;
  - the ID token carries no `sid`, `acr`, `amr`, profile or email claim, and
    `openid` never appears in the leaf, the receipt or the page;
  - a non-agent or uncapped client asking for `agent:request` fails
    `invalid_scope`, and a `staging` root carrying it forces a fresh login;
  - a client assertion at the backchannel endpoint whose `aud` is not the issuer
    alone, or without `typ`, is `invalid_client`;
  - a WebAuthn ceremony whose client-data `origin` is not QAuth's is refused;
  - a TOTP code is refused in every profile;
  - an owner whose address is not verified can register neither an approval
    passkey nor a web-push subscription or webhook, each refusal audited, with
    `REQUIRE_EMAIL_VERIFIED` at its default `false`;
  - a standing block refuses a matching request in a later session and notifies
    no one, and removing it restores asking;
  - a block set before a transfer still refuses a matching request. After the
    acceptance the new owner can remove it and the previous owner's management
    token cannot, and the block's row still names the owner who set it;
  - a root, node or leaf token is refused on ending a window, removing a
    standing block and registering a web-push subscription or webhook, and no
    tree token authenticates passkey registration or the approval page;
  - user A's management token can neither end user B's window, remove user B's
    block nor register a channel for user B;
  - the page preselects no choice, gives Deny at least an approve choice's
    prominence and recommends a separate device.

## Vitrin composition

Cited from the vitrin documents the Related list names (WS-D §7, the
protocol pages and the PRD). No vitrin decision-log
entry covers OAuth, QAuth or the ceiling rule; WS-D §5 says the entry is owed
and, in vitrin's own words, "needs the owner's clauses rather than a
derivation", so this record cites §7.2 and §7.6 by section and expects that
entry may amend the numbers.

**What QAuth promises.** A JWT under 32768 bytes; a single-audience leaf per
vitrin core or per MCP server fronting it, minted with RFC 8707 `resource`; a
leaf that carries `cnf.jkt` — always for a vitrin core, which is single-scheme
and DPoP-unaware and so is never listed in `AGENT_BEARER_LEAF_RESOURCES`; for
an MCP server fronting it unless that server is listed — stable across refresh
because the key does not rotate with the token; RFC 7662 introspection for the
verifier to consult
at refresh, off the hot path; a 300 s lifetime as the written window, with the
fail-open sentence beside it (§6); verb-level scopes only (`vitrin:observe`,
`vitrin:actuate`) as ceilings on what may be petitioned, never as permissions,
no scope implying another verb, and no resource-, realm-, path- or `net:`
scopes — which layer owns that narrowing is vitrin's open question WS-D
§7.7(1); issuer-policy changes (a new `iss` check, the `jti` denylist, key
rotation) announced so a long-lived agent sees a legible failure rather than
a bare 401. QAuth is a reference implementation and validation target, never
a dependency.

**What QAuth proposes** to the OIDC verifier tracked at
https://github.com/vitrin-os/vitrin-os/issues/167 (open): that the canonical
principal be **(`iss`, `client_id`, `cnf.jkt`)** — the agent instance — with
`sub` carried as the on-behalf-of human and never folded in. Vitrin's own
pages canonicalise (`iss`, `sub`, `aud`); on every QAuth agent token `sub` is
the human, so that triple would fold every agent of one person at one core
into one principal and one `busy` admission cap, which vitrin's per-agent
pillar forbids. draft-ietf-wimse-aims-00 §10.3 says resource servers MUST use
`client_id` for the agent and `sub` for the user; `client_id` names the agent
type the human sees on the consent card, `cnf.jkt` keeps one principal per
process, and a refreshed token keeps all three. The verifier ignores `act`;
the chain collapses to one principal per connection. Mid-connection
re-presentation for refresh is
https://github.com/vitrin-os/vitrin-os/issues/170 (open).

**What QAuth must not claim.** That vitrin accepts its tokens today (only the
static verifier exists, `crates/vitrin-core/src/identity.rs`); that DPoP is
verified at the `hello` handshake (the wire is bearer-shaped; sender
constraint there is the connection triple, which QAuth's binding complements,
not replaces); that revoking a token kills a connection or a grant
(revocation stops future petitions, grants a human approved run to their
expiry, and a delivered file descriptor is kernel authority —
`docs/protocol/13-vitrin_powerbox.md`); that a refresh token is a restore
token or reaches `until_revoked`/`always` (durable rungs are unreachable by
construction, `crates/vitrin-core/src/grants.rs`); that vitrin has
attenuation, sub-grants, a `revoked` push or chains deeper than one (all
unbuilt Growth seams, `docs/protocol/04-vitrin_grant.md`); that vitrin relays
`invalid_token` or `insufficient_scope` to the agent (every refusal there is
one uniform `auth_failed`); that any token claim pre-approves a petition or
skips the consent card; that a token attests a model, a prompt, an operator or
an intent; or that vitrin's §6.2 is decided — §7.3(1) offers per-agent tokens
as the answer and §5 still lists it open.

## Harness reality

From the Claude Code and Agent SDK documentation (fetched 2026-09-21): every
hook payload carries `session_id`; `SubagentStart`/`SubagentStop` carry
`agent_id` and `agent_type` and cannot block; `PreToolUse` can block and
rewrite input but cannot inject environment; the settings `env` block reaches
every Bash subprocess; sub-agents run in-process and share the session's MCP
connections and tokens unless their definition sets its own `mcpServers`;
teammates are separate processes with their own `session_id`; MCP tokens are
stored per server, not per session, and `headersHelper` re-runs on connect and
on 401; the Agent SDK passes `mcpServers` and headers per `query()`.
`SessionStart` fires at startup, on resume (`--resume`, `--continue` or
`/resume`), on `/clear`, on compaction and on a fork (hooks reference,
fetched 2026-09-30). A `/resume` inside a session waits for those hooks.

| Tree node                                     | Bindable today   | How                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --------------------------------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The session's main agent                      | yes              | The broker holds its key and tokens and a pidfd on the session process opened at `login`, when the main agent's `SessionStart` hook first registers `session_id` and pid (§1 says what a later registration from that pid does); a Bash subprocess maps to that session's root node only when its `SO_PEERCRED` parent chain reaches that pid. An orphaned descendant (`( cmd & )`, `nohup`, `setsid`, double fork — reparented to pid 1 or a subreaper) reaches no bound node and is refused; a child that must outlive its spawner is started through the executor path below, which passes a handle.                                                                                                                                                                                                                                                                                                                          |
| Executor-spawned process                      | yes              | The executor is the runtime helper: it spawns the node and registers the child's pid with the broker over the socket before exec (a pidfd passed with `SCM_RIGHTS`, so pid reuse cannot rebind it); the handle in the child's environment is a label for logs, never a binding — the broker binds by `SO_PEERCRED` and ancestry and refuses a handle whose node is not on the caller's ancestry. Full CLI and MCP attribution.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Teammate                                      | yes              | A separate process; its `SessionStart` hook registers `session_id`, pid, process start time and its lead's `session_id` (read from the team config under `~/.claude/teams/`) with the broker, which opens a pidfd on it (fallback pid + start time) and spawns the teammate node under the lead's. The ancestry check maps every call that reaches the broker from that process, or from a descendant whose chain reaches it, to the teammate node — the CLI leg from P0b, the MCP leg once its `headersHelper` reaches the broker (P3); until then its MCP calls carry Claude Code's per-server token, the same one the lead presents (row 8). The binding ends when the pidfd signals exit, not when a pid is reused. A later registration from a bound teammate pid spawns nothing, whatever its `session_id` (§12).                                                                                                          |
| Agent SDK agent                               | yes              | The application is the runtime: it obtains leaf tokens from the broker per `query()` and passes them in `mcpServers` headers; one process per agent is the application's choice.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Sub-agent with its own inline `mcpServers`    | by type          | The inline server is a `stdio` entry running the broker's proxy with the agent type as an argument; the broker attributes the child by `SO_PEERCRED` and ancestry, and `SubagentStart` says which instance of that type is live. Two concurrent sub-agents of one type share a node. Its key is created on the first `SubagentStart` of that type in the session — or, when no hook has announced the type (hooks disabled), on the proxy's first call under it — and retired on the last `SubagentStop` of that type or at session end; the start and stop events reach the broker by hooks (advice, not authority), so with hooks off the key lives until session end, and the node's dead-man switch is the session process's pidfd either way. MCP only.                                                                                                                                                                     |
| Sub-agent sharing the session's connections   | no               | Same connection, same token: the session node.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Any in-process sub-agent's CLI call           | no               | The Bash tool runs in the session process; `SO_PEERCRED` sees the session; the credential vended is the session node's. `PreToolUse` can refuse as advice; it cannot make it a different principal.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Claude Code's own per-server OAuth (DCR/CIMD) | outside the tree | A non-agent client under §1: no `sid`, no ledger row, no node. It joins the broker's root only when the server is reached through the proxy or `headersHelper` → broker (P3). An operator who seeds it as an agent client and points Claude Code at those pre-configured credentials gets a `sid` and ledger rows — but a root of its own. Its CIMD document (fetched 2026-09-30) declares `http://localhost/callback` and `http://127.0.0.1/callback` without a port. Claude Code calls back on `http://localhost:<random port>/callback`, which QAuth matches since PR #415 (§1). An operator who seeds it as an agent client registers `http://localhost/callback`, the literal it sends — QAuth never matches it against `127.0.0.1` — and needs no `--callback-port`. One release, v2.1.229, sent `127.0.0.1`; upgrade rather than widen the seed. This seed is not decision 7's broker type, which listens on `127.0.0.1`. |

The consequence is a rule, not a caveat: **a child that needs a hard read-only
gate is spawned as a process under a different uid, or in a sandbox that
denies it ptrace-read of the parent, the parent's tmux socket and every
user-writable directory on the parent's `PATH` and `HOME`** (the executor's
job — e.g. `bwrap --unshare-user` or a `DynamicUser=` unit); a process is
necessary for the gate on both legs and, until P3, sufficient on the CLI leg
only (row 8, P0's honest limits). What a same-uid child can still do to its
parent is T2's residual; a sub-agent cannot be gated at all (§12).

## Consequences

### Positive

- Provable: every property is one check at mint and holds from the token
  alone (the invariant paragraph), so a read-only child is read-only by
  credential before any judgement (T6, §4) and a resource server needs only
  the token.
- Observable: a node per process, a row per hop, a receipt per spawn, an
  event per action (§§2, 4, 7); "which agent opened this PR" is answered in
  P0 from the trailer and the two `jti`-keyed logs (§9).
- Revocable: one identifier cuts a whole tree within a written window, by the
  user or any live ancestor node, not only the agent, and one call cuts every
  tree a user has rooted (§6, decision 1).
- The CLI leg gets the MCP leg's discipline with no new token format; the App
  key never leaves the server and the type key on the box is one box's (§9).
- Attributable: a tree can root in a principal a person owns, so "whose
  agent" has one answer across sessions, platforms and time; the public
  profile states it, the consent screen names it, and a commit the agent
  wrote is authored by it rather than by a shared harness name or the
  person's own address (§9, §11, §13).
- Separable: what QAuth verified and what an agent reported about itself
  are stored, shown and served apart, so a model name or a reason can be
  logged without ever being mistaken for QAuth's word (T7, §7).
- Reachable: the owner can lift a ceiling for one step from a phone, with a
  passkey, without a shell or SSH, and without widening the tree (§14).

### Negative

- `/oauth/token` gains DPoP proof validation, two exchange gates and a ledger
  write, and introspection and revocation gain a ledger walk: the most
  branch-heavy route grows again, and with the flag on a ledger outage stops
  every agent mint (§2).
- A local daemon joins the trusted computing base on every agent host, and
  QAuth grows an STS that holds a GitHub App key; the on-box type key and root
  refresh token, and the soft same-uid isolation, are T2's residuals, and a
  hard child gate costs a uid or a sandbox per node (Harness reality).
- Revocation is fail-open for one lifetime (T5, §6); at 300 s that is one
  root-down re-spawn per node every five minutes (§4), and GitHub's hour
  shortens only by the broker's deletion (§9).
- In `staging` and `production`, one fresh login per new code-grant root that
  names a dangerous scope, unless the browser session is under two minutes old
  (§11). Every default root names one, and under decision 8's default there
  is one root per main-agent process. A resumed session reuses its root only
  while its refresh token lives, and from P2 its old process's exit ends that
  token whenever the dead-man walk reaches QAuth (§1, §6). A second process
  roots its own (§11).
- With the flag on, from P2, a sign-out no longer ends an agent client's tree
  (decision 1). An owner who wants them stopped uses revoke-all (§6), and a
  forgotten tree lives until its refresh family ends.
- Every re-spawn, vend and CIBA poll counts against per-IP limits (30 token
  requests a minute in a production realm), shared by every broker behind
  one address; the broker paces within them (Decision).
- The broker keeps one refresh of a root in flight. A lost refresh response
  ends the tree, and the next login roots a new one (§4, §6).
- Audit records are durable but not tamper-evident, though
  draft-ietf-wimse-aims-00 §11 says they MUST be (Standards position).
- Three of the shapes followed are individual drafts that may expire without
  successors (Watch list); the `act` object may need a second migration.
- The MCP leg is outside the tree until P3 (Phasing; Harness reality, row 8).
- A public profile is a new unauthenticated surface on the realm, and an
  owner-registered transmitter is a new party whose SETs QAuth stores; both
  are bounded (the profile shows the principal and nothing below it, the
  transmitter reaches only the trees its owner rooted in one agent, and its
  rows are marked as reports), but each is one more thing to enumerate and
  one more `jwks` to rotate (§7, §13).
- Every provenance line outside QAuth is forgeable, by anyone and by the
  agent itself; the record can only make its own store honest about the
  difference (T7). Commit signing, the one thing that would change that, is
  parked (decision 12).
- QAuth grows a CIBA endpoint, a WebAuthn credential provider, a
  notification path and an approvals table (§14). The owner's phone joins
  the approval path: a lost, unlocked phone with a synced passkey is a way
  in, bounded by the delta, the budget and the window. A passkey on the
  agent's own machine, and a human who approves carelessly, are T8's
  residuals.

### Neutral

- Default off in every dimension: `AGENT_TREE_ENABLED=false` runs none of it
  ([Decision](#decision)), and with it on, no agent client is DPoP-required,
  no `spawn_allowlist` exists and so no root token's `aud` is enriched, no
  lifetime row changes, no transmitter or push endpoint is configured, until
  an operator says so — and no agent, binding or agent-side transmitter
  exists until an owner creates one (§7, §13). No approval request is
  possible until an operator sets `AGENT_APPROVAL_ENABLED` and an owner
  with a verified address registers a passkey on QAuth's origin (§13, §14).
- `MAX_DELEGATION_DEPTH` stays 4; the actor profile's "at least depth 4"
  (its §3.5) is met and draft-liu's recommended 5 is not adopted. A narrowing
  spends no depth, so lead → teammate → process → tool with a leaf per level
  fits.
- ADR-007's maintainer decision stands (the invariant paragraph); nothing on
  the wire is proprietary to a standard client; `WalletProvider.verify()` is
  untouched and still throws.

## Decisions parked for the maintainer

Each question carries the default the record was written on; the record
proceeds on that default until the maintainer decides otherwise. A decided
question keeps its question, says _Decided_ with the date and, in the
maintainer's words where he gave them, carries the decision in place of the
default.

1. **Sign-out and agent trees.** _Decided 2026-09-30 (maintainer)._ Should a
   QAuth logout revoke the user's agent `sid` trees? RFC 9700 §4.14.2 leaves
   automatic refresh-token revocation on logout a MAY. The maintainer's
   words: there will be a separate method that revokes all agents; agents
   survive the browser logout. Decision: trees survive sign-out, and a
   separate kill switch, `POST /api/agent-sessions/revoke-all`, ends them.
   §6 states both ("Sign-out spares agent trees" and "Revoke all"). It also
   states what the record adds, not in his words: the `AGENT_TREE_ENABLED`
   gate, the landing in P2 together with revoke-all, the fail-closed limits
   on the exemption, and one lasting fail-closed rule: once a user has used
   revoke-all, no NULL-`sid` family of that user roots a tree, whenever it was
   issued (§1; §6, "Revoke all"). Whether revoke-all needs a step-up is
   decision 19.
2. **`purpose` and `task` provenance.** Model-authored free text, shown and
   never a policy input, or `task` restricted to operator- or executor-issued
   identifiers? Default: free text; `caused_by` server-written.
3. **GitHub attribution.** App installation tokens (attributed to the App's
   bot) or user-to-server tokens (the user's avatar with an app badge)?
   Default: installation tokens; the trailer carries the agent. _Amended
   2026-09-22:_ where the tree roots in an agent principal, the App is the
   agent's binding and its bot identity is the author (§9, §13), which
   settles this on installation tokens for that case; the user-to-server
   option remains open only for trees with no agent named.
4. **Which GitHub App and installation** the STS mints from — one App per
   organisation or one shared. Default: one per organisation, installation
   ids in QAuth configuration. _Amended 2026-09-22:_ one App per agent
   principal where one is named (§13), the App's slug being the agent's
   public name on GitHub; the per-organisation default holds for trees with
   no agent named. Installation ids stay in QAuth configuration either way.
5. **Where `qauth-broker` lives** — a TypeScript app in the Nx monorepo or a
   separate crate beside vitrin; the PostgreSQL validator is C either way.
   Default: `apps/qauth-broker` in the monorepo.
6. **Same-type teammates** as one registered type (told apart by `cnf.jkt`
   and `parent_jti`) or a distinct type per role for a separate
   `max_agent_mode` cap? Default: one type.
7. **First seed manifest** — each agent type sets:
   - `is_agent: true` and `max_agent_mode`;
   - `scopes`;
   - `grant_types`: token exchange for every type; `authorization_code` and
     `refresh_token` also for a root type; never `client_credentials` or
     jwt-bearer;
   - `token_endpoint_auth_method: private_key_jwt` with `jwks`;
   - `audience` (P0's carrier of child types; resources only from P1b);
   - `dpop_bound_access_tokens: true` (P1a; §3);
   - `spawn_allowlist` (P1b);
   - for a root type, `redirect_uris`.

   The manifest's defaults are `is_agent` false, `client_secret_basic` and
   `dpop_bound_access_tokens` false (RFC 9449 §5.2). So a missing field
   seeds a non-agent secret client that is not DPoP-required.

   Default:
   - `claude-code`: root, `exec`, an allowlist naming itself and `reviewer`,
     and one `redirect_uris` entry, the portless `http://127.0.0.1/callback`
     (§1);
   - `reviewer`: `readonly`, no `write:*`, token exchange only;
   - `executor`: `exec`, token exchange only, and named in no other type's
     allowlist, so `claude-code`'s ceiling does not grow. It becomes a root
     type only when decision 8 gives it a cadence. §1 roots a tree only on a
     main agent's `SessionStart` registration, and decision 8's note says an
     unattended runtime cannot carry a per-process root. So under decision
     8's default the seed gives it no `authorization_code`, no
     `refresh_token` and no `redirect_uris`, and the broker roots no tree
     for it. An answer that admits its root adds those three, and the same
     dated change says in §1 how that root starts and in §6 what ends it.

   One `jwks` key per box, each with a distinct `kid`.

8. **Root-grant cadence.** One root per main-agent process (§11's step-up
   login per process when the root names a dangerous scope, unless a resume
   finds its refresh token alive, §1 and §6; per-session attribution) or one
   root per broker start (at most one login, concurrent sessions share a `sid` and a node)? Default:
   per process. Decision 21 parks when a root ends.
   _Note 2026-09-22:_ an unattended runtime — a daemon with no
   `SessionStart` hook, restarted independently of the broker, started
   through the executor path — cannot carry a per-process root, since its
   every restart would cut the `sid` (§6); it needs the per-broker-start
   shape. A per-host setting choosing between the two, rather than one
   answer for every host, is the likely resolution. _Note 2026-09-30:_ until
   this is decided, decision 7's `executor` type is not a root type and roots
   nothing.
9. **Agent handle namespace.** Realm-unique (`majordomo` is one agent per
   realm) or user-scoped (`taha/majordomo`, so two owners may share a
   handle)? The SCIM draft wants `agentUserName` unique across the
   provisioning domain, which is the realm. Default: realm-unique, first
   come; the profile URL is `/agents/{handle}`.
10. **Ownership transfer.** _Decided 2026-09-30 (maintainer)._ May an owner
    hand an agent to another user, and does the agent's history (ledger rows,
    bindings, events) move with it? The maintainer's words: agent activity
    before the transfer was done under the pre-transfer owner; this history
    is not rewritten or removed at transfer; from the moment of transfer it
    continues under the new owner's name. Decision:
    - Transfer is allowed: an owner may hand an agent to another user.
    - Each ledger and `agent_actions` row keeps the owner of its time, and
      every display renders the owner from the row. Nothing is rewritten or
      removed at transfer.
    - From the transfer, the agent acts under the new owner's name.
    - The old owner's name leaves the public profile at transfer, and only
      the public profile: pre-transfer history keeps it.

    The record adds fail-closed rules of its own, not in his words; §13
    (Transfer) states them. A transfer is an offer that only the named user
    can accept, because nobody is made an agent owner without accepting. The
    acceptance is the moment of transfer. Its own transaction cuts every
    live tree of the agent and makes the recipient the owner. A token minted
    before it keeps the previous owner on its ledger row and runs out within
    §6's written revocation window, so an action taken with it is
    pre-transfer activity. So every action taken with a token minted before
    the acceptance is the previous owner's, every action taken with one
    minted after it is the new owner's, and no row is rewritten. Whether the
    agent should instead be frozen until the last cut token expires is
    decision 22.

11. **Agent-side transmitter trust.** Does an owner-registered transmitter
    (§7) need a second party's approval (QAuth has no operator role to give
    it, Explicitly out of scope) before its SETs are stored, or is the owner's
    registration enough? Default: the owner's registration is enough. An
    owner-registered transmitter's rows are already marked as reports and
    reach only the trees its owner rooted in that agent. Only its owner may
    disable a transmitter. An accepted transfer also disables the previous
    owner's transmitters for the agent (§13). No other party can. An
    operator who must stop every agent-side transmitter at once turns
    `AGENT_TREE_ENABLED` off.
12. **Commit signing.** _Still parked; restated 2026-09-30._ Leave agent
    commits unsigned, or give them an agent-specific signature? The
    maintainer asked whether the purpose is to stop a malicious force push
    that uses the agent's identity to override the agent's code. Three layers
    answer three different questions, and a signature is only one of them:
    - **Prevention** — what a branch may point to — is branch protection and
      rulesets: no force push, and signed commits required. A signature
      proves who made a commit, not what a branch points to.
    - **Detection and attribution after the fact** is the ledger. The broker
      reports every pushed hash (§9), so a commit under the agent's identity
      whose hash the owner's record does not know stands out.
    - **Offline verification by a third party** — proof of authorship
      without asking QAuth — is the one thing only a signature gives.

    Options:
    - unsigned (a pointer only);
    - the broker's per-node key, verifiable against the ledger and shown
      Unverified by GitHub as `unknown_key`;
    - a server-side key registered to a machine user, shown Verified, with
      the AS on every commit;
    - commits the agent's GitHub App creates through GitHub's API (for
      example the GraphQL `createCommitOnBranch` mutation), which GitHub
      signs and may show Verified under the App's bot. Unverified: it must be
      tested with the STS App before the record relies on it, and it replaces
      `git push` with an API call;
    - keyless `gitsign` through Sigstore, with QAuth as the OIDC issuer of
      the signing certificate, verifiable outside GitHub. Unverified:
      untested, and it needs a certificate authority that accepts QAuth as an
      issuer.

    Default: unsigned. The trigger to reopen is a requirement that
    provenance be evidence rather than a pointer.

13. **`model` on the ledger row?** Keep the reported model only in
    `agent_actions` (§7), or copy the first report onto the ledger's root
    row for the dashboard's convenience? Default: `agent_actions` only; the
    ledger holds what QAuth verified and nothing it did not.
14. **"Don't ask again": a mute or an allow?** The owner's framing
    (2026-09-23): approval fatigue is prevented by "don't ask again for this
    session" and "don't ask for a while", and asking has its own permission
    scope, which cannot be extended. _Decided 2026-09-30 (maintainer), for
    five of six answers._ His words: it can work both ways — always allow,
    allow for a while, allow for this session, always block, mute and block
    for a while, mute and block for this session. Decision:
    - **allow for a while** and **allow for this session** are the approval
      windows (§14, step 4);
    - **mute and block for a while** and **for this session** stay as
      written;
    - **always block** is a standing deny the owner sets. It lasts across
      sessions.

    **Always allow** is not decided; it is parked as decision 18.

    The record adds rules of its own for **always block**, not in his words:
    its key, the trees it matches, its overlap rule and who may remove it
    (§14, step 4).

15. **Which factors may approve?** A passkey only, or also a TOTP or other
    offline code, or a wallet presentation bound by `transaction_data`?
    _Decided 2026-09-30 (maintainer)._ His words: let us do the passkey
    first, we will do the wallet too; TOTP is dangerous, agents can fill forms
    in a system where vitrin is not used. Decision:
    - a passkey only, in every profile, `development` included;
    - a wallet presentation later, behind `WALLET_FEDERATION_ENABLED`, as a
      request-bound option (§14);
    - no TOTP anywhere.

    Stated residual: a platform authenticator on the agent's own machine,
    unlocked by a PIN or a password (T8; §14, A stated residual).

16. **Where a request reaches the owner.** Web push to the portal, email, an
    owner-registered webhook, or all three — and what happens while the
    owner does not want to be reached? Default: web push, plus an optional
    owner-registered webhook that receives only the request id, the agent's
    handle and the approval URL; no email. A request nobody answers expires
    at `requested_expiry` and counts as denied; quiet hours are the owner's
    channel's business, not QAuth's (§14).
17. **Skipping the consent screen for an agent root.** Merged §11 leaves the
    skip-consent fast path untouched, and the record keeps it until the
    maintainer decides. Should every code grant to an agent client pass the
    screen with the flag on?

    Options:
    - keep the merged fast path;
    - no skip: with the flag on, `canSkipConsent` answers false for an agent
      client ahead of every other condition, and `prompt=none` never mints a
      code for one. It answers `consent_required`, or `login_required` when
      step-up demands a fresh login first (OpenID Connect Core 1.0 §3.1.2.6);
    - skip only when a stored consent records the same agent, the same
      allowlist snapshot and the same purpose, which needs new columns on
      `oauth_consents`.

    Default: the merged fast path. The trade: no skip shows the user every
    tree's agent, allowlist, purpose and persistence, and closes T2's
    stored-consent residual. It costs one screen per new root. Under decision
    8's default that is one per main-agent process, unless a resume finds its
    refresh token alive (§1, §6). So decide it together with decisions 8 and 21.

18. **"Always allow".** The maintainer named it among the lasting answers
    (decision 14). As an approval it would be a standing grant for whatever
    matches, for as long as it stands. That is T8's attack in one tap, and it
    breaks §14's rule that an approval never reaches a durable rung and never
    widens a tree. Default: not offered on the approval page. Recommended
    form, if wanted: the owner raises the agent's default root ceiling in the
    portal, through a passkey-confirmed change, never above the type's
    registered scopes or `max_agent_mode`. No live tree changes. The next
    root takes the new ceiling only through a consent. A stored consent that
    does not cover the wider set cannot skip the screen (§11), so the owner
    sees the widening. Why: a wider ceiling then enters the one way every
    ceiling does, through a consent, and the invariant still bounds the tree
    by that consent. Decision 17 decides whether every root shows the screen.
19. **A step-up before revoke-all.** Should
    `POST /api/agent-sessions/revoke-all` (§6) also require a fresh passkey
    assertion? Default: no; the owner-route guard is enough. Why: revocation
    only removes authority. The worst misuse by someone holding the owner's
    portal session is that live trees end and must be rooted again. A kill
    switch that waits for a phone can fail to fire when
    it is needed, which is the fail-open direction for a kill switch. And
    revoke-all lands in P2, before any passkey exists (P5).
20. **Agent owners without a QAuth-verified address.** An owner needs an
    address QAuth itself verified (§13), so an account with no `password`
    credential, such as a wallet-only one, cannot own an agent. Should an
    issuer-asserted email count? Default: no, in the first slice. Why: only
    QAuth's own mailbox proof shows control of the address, and wallet
    federation is off by default. Revisit when it leaves its default-off
    flag.
21. **When a root ends.** Two merged rules meet at a resume. §1 lets a
    session resumed at launch (`--resume`/`--continue`, same `session_id`)
    reuse its root while the grant's refresh token lives. §6's dead-man
    switch revokes the root when its process exits, and with it the `sid`
    and the refresh family, whenever the walk reaches QAuth. Decision 8's
    note reads §6 the same way. So from P2 a resume reuses a root only when
    that walk did not reach QAuth. The resumed process then holds a new key
    (§3). Its refresh opens a new node under the same `sid` (§2), and that
    node cannot revoke by `sid` (§6).

    Three stricter rules are parked together. A resume would never reuse a
    root whose process exited. A root would also end when its process
    registers a new `session_id` (on `/clear`, on compaction, on a `/resume`
    inside the session, on some forks). And from P1a a family that carries a
    `sid` would refresh only under the DPoP key of its tree's root row.

    Options:
    - keep the merged rules;
    - take the three stricter rules together;
    - looser: let a root outlive its process for a resume. §6 would then
      revoke only the nodes below the root when the session process exits.
      This loosens merged §6 and decision 8's note.

    Default: the merged rules, read together. A resume reuses a root only
    when the old process's walk did not reach QAuth, and a process keeps its
    root across a new `session_id` (§1). The root refresh stays bound to
    client authentication, not to the DPoP key (RFC 9449 §5), and T2 keeps
    its written residual. The trade: the stricter option closes the residual
    that a same-uid thief of the type key and the root refresh token can
    refresh the root from another host. It costs a new root on every
    `/clear` and every compaction: in `staging` and `production` often a
    fresh login (§11), and a consent screen as well if decision 17 takes no
    skip. A resume at launch already costs a new root whenever the walk
    reached QAuth. It is linked to decisions 8 and 17, so decide the
    three together.

22. **A frozen agent during a transfer.** Should an accepted transfer also
    freeze the agent until the last token its cut trees minted has expired?
    That instant is the later of their last `expires_at` and one GitHub hour
    after their last vend. While frozen, no one could root a tree in the
    agent or change it, and the agent would pass to the new owner only at
    the end.

    Options:
    - no freeze;
    - the freeze.

    Default: no freeze. The moment of transfer is the acceptance (§13,
    decision 10). The trade: a freeze keeps the two owners' activity apart,
    since nothing could act for the new owner while a token of the previous
    owner still can. It costs a wait of up to one GitHub hour after the
    acceptance, in which neither user can use or change the agent.

## Related

- [ADR-006](./006-oauth-grants-and-audience.md) — the `aud` and
  `oauth_clients.audience` decision the root-token enrichment sits beside;
  [ADR-007](./007-mcp-first-positioning.md) — the agent-native layer this
  record extends, the independent-scope-modes decision, epic #181 and issues
  #184 and #186 as named in the code;
  [ADR-008](./008-environment-aware-authorization.md) —
  the profile resolver the lifetime row joins;
  [ADR-011](./011-enterprise-managed-authorization.md) — the exchange gate
  discipline, gate 15, `private_key_jwt`, the operator-config trust posture;
  [ADR-012](./012-dynamic-client-ownership.md) — why per-instance DCR clients
  were rejected, and the ownership check §13 reuses;
  [ADR-013](./013-same-device-return-leg.md) — the
  burn-then-bind idiom the spawn assertion's single-use `jti` follows;
  [ADR-002](./002-identifier-abstraction.md) — email as credential, not
  identity, which is why an agent has neither (§13)
- [Agent Authorization guide](https://docs.qauth.dev/integrate/agent-authorization/) —
  the shipped agent layer this record builds on;
  [`docs/spec-pin-log.md`](../spec-pin-log.md) — where the watch list will be
  pinned at P0
- Vitrin: `docs/plan/13-workstream-agent-integration.md` (WS-D §7),
  `docs/protocol/01-vitrin_handshake.md`, `docs/protocol/02-vitrin_principal.md`,
  `docs/protocol/04-vitrin_grant.md`, `docs/protocol/13-vitrin_powerbox.md`,
  `docs/protocol/19-vitrin_egress.md`, `docs/PRD.md`;
  https://github.com/vitrin-os/vitrin-os/issues/167 ·
  https://github.com/vitrin-os/vitrin-os/issues/170
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html) · [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) · [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) · [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) · [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) · [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) · [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) · [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417.html) · [RFC 8935](https://www.rfc-editor.org/rfc/rfc8935.html) · [RFC 8936](https://www.rfc-editor.org/rfc/rfc8936.html) · [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493.html) · [RFC 7521](https://www.rfc-editor.org/rfc/rfc7521.html) · [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) · [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html) · [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) · [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) · [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) · [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) · [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) · [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) · [RFC 10027 (BCP 247)](https://www.rfc-editor.org/rfc/rfc10027.html) · [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) · [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html)
- [OpenID Federation 1.0 §13.6](https://openid.net/specs/openid-federation-1_0.html) · [OIDC Back-Channel Logout 1.0 §2.1](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [draft-mcguinness-oauth-actor-profile-00](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-actor-profile-00) · [draft-liu-oauth-chain-delegation-00](https://datatracker.ietf.org/doc/html/draft-liu-oauth-chain-delegation-00) · [draft-niyikiza-oauth-attenuating-agent-tokens-01](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-01) · [draft-ietf-wimse-aims-00](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-aims-00) · [draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11) · [draft-ietf-oauth-rfc7523bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/) · [draft-oauth-ai-agents-on-behalf-of-user-02](https://datatracker.ietf.org/doc/html/draft-oauth-ai-agents-on-behalf-of-user-02) · [draft-asor-wimse-agent-delegation-chain-01](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-01) · [draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) · [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) · [draft-ietf-wimse-workload-creds](https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/) · [draft-ietf-wimse-wpt](https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/) · [draft-klrc-aiagent-auth](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) · [draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/) · [draft-mora-oauth-entity-profiles-01](https://datatracker.ietf.org/doc/html/draft-mora-oauth-entity-profiles-01) · [draft-mcguinness-oauth-actor-proofs-00](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-actor-proofs-00) · [draft-mcguinness-oauth-actor-receipts-00](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-actor-receipts-00) · [draft-mcguinness-oauth-mission-00](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-00) · [draft-mcguinness-oauth-token-exchange-cnf-00](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-token-exchange-cnf-00) · [draft-mcguinness-oauth-client-instance-id-00](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-client-instance-id-00) · [draft-mcguinness-oauth-ai-agent-instance-00](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-ai-agent-instance-00) · [draft-ietf-oauth-deferred-token-response-00](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-deferred-token-response-00) · [draft-ietf-oauth-rar-metadata-remediation-00](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-metadata-remediation-00) · [draft-rosomakho-oauth-txn-challenge-00](https://datatracker.ietf.org/doc/html/draft-rosomakho-oauth-txn-challenge-00) · [draft-hardt-oauth-aauth-protocol-11](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol-11) · [draft-richer-oauth-oob-authcode-00](https://datatracker.ietf.org/doc/html/draft-richer-oauth-oob-authcode-00) · [draft-gilda-wimse-agent-audit-record-01](https://datatracker.ietf.org/doc/html/draft-gilda-wimse-agent-audit-record-01) · [draft-gazitt-oauth-authzen-issuance-01](https://datatracker.ietf.org/doc/html/draft-gazitt-oauth-authzen-issuance-01) · [draft-gazitt-oauth-authzen-token-exchange-01](https://datatracker.ietf.org/doc/html/draft-gazitt-oauth-authzen-token-exchange-01) · [draft-ietf-oauth-identity-chaining](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/) · [draft-ietf-oauth-rfc8725bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/)
- [OAuth WG thread: Delegation Chain Splicing in RFC 8693 Token Exchange](https://mailarchive.ietf.org/arch/msg/oauth/6MHkSfhGfugVmcb2p08ocM7piqQ/)
- [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) · [COAZ-MCP Binding 1.0 (WG draft)](https://openid.github.io/authzen/authzen-coaz-mcp-binding-1_0.html) · [Access Request and Approval Profile 1.0 (WG draft)](https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html) · [OpenID Foundation announcing the ARAP and COAZ WG drafts (15 June 2026)](https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/) · [Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html) · [CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html) · [OIDC Front-Channel Logout 1.0 §3 (`sid`)](https://openid.net/specs/openid-connect-frontchannel-1_0.html) · [IANA JWT Claims registry](https://www.iana.org/assignments/jwt/jwt.xhtml) · [Token Issuance Profile (WG draft)](https://openid.github.io/authzen/authzen-oauth-token-issuance-1_0.html) · [Token Exchange Binding (WG draft)](https://openid.github.io/authzen/authzen-oauth-token-exchange-1_0.html) · [Access Request OAuth Profile (editor's draft)](https://github.com/openid/authzen/blob/483abc2b91b0984e6a47a6ec94df85c7a7c2dfd5/profiles/authzen-access-request-oauth/authzen-access-request-oauth-profile-1_0.md)
- [MCP Authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) · [PostgreSQL 18 OAuth authentication](https://www.postgresql.org/docs/18/auth-oauth.html) · [GitHub App installation access tokens](https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app) · [octo-sts](https://github.com/octo-sts/app) · [gitcredentials](https://git-scm.com/docs/gitcredentials)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks.md) · [sub-agents](https://code.claude.com/docs/en/sub-agents.md) · [agent teams](https://code.claude.com/docs/en/agent-teams.md) · [MCP](https://code.claude.com/docs/en/mcp.md) · [Agent SDK MCP](https://code.claude.com/docs/en/agent-sdk/mcp.md)
- [draft-wzdk-scim-agent-resource-00](https://datatracker.ietf.org/doc/html/draft-wzdk-scim-agent-resource-00) · [draft-abbey-scim-agent-extension (expired 19 Apr 2026; consolidated into draft-wzdk)](https://datatracker.ietf.org/doc/draft-abbey-scim-agent-extension/) · [draft-kushwaha-scim-agent-governance](https://datatracker.ietf.org/doc/draft-kushwaha-scim-agent-governance/) · [SCIM WG agentic-draft progress, IETF 125](https://datatracker.ietf.org/meeting/125/materials/slides-125-scim-scim-agentic-draft-progress-00) · [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643.html) · [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644.html) · [RFC 8141](https://www.rfc-editor.org/rfc/rfc8141.html) · [SCIM WG, AI Agent Resource Extension, IETF 126](https://datatracker.ietf.org/meeting/126/materials/slides-126-scim-scim-ai-agent-resource-01)
- [CAEP Interoperability Profile 1.0 (draft 01)](https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html) · [OpenID Foundation on SSF/CAEP and agentic use cases (July 2026)](https://openid.net/authzen-at-identiverse-2026-authorization-in-the-agent-era/)
- [OpenID CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) · [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) · [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) · [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) · [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) · [Claude Code Remote Control](https://code.claude.com/docs/en/remote-control)
- [Linux kernel: AI Coding Assistants](https://docs.kernel.org/process/coding-assistants.html) · [GitHub App visibility](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/making-a-github-app-public-or-private) · [GitHub commit signature verification reasons](https://docs.github.com/en/rest/commits/commits) · [GitHub REST: pull requests associated with a commit](https://docs.github.com/en/rest/commits/commits#list-pull-requests-associated-with-a-commit)
