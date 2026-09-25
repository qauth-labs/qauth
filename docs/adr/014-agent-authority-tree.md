# ADR-014: Agent Authority Tree — Session-Rooted, Sender-Constrained Delegation for AI Agents

**Status:** Proposed
**Date:** 2026-09-21
**Authors:** QAuth Team

> **Proposed 2026-09-21.** Nothing below is implemented. Every fork takes the
> fail-closed option, every new surface is inert until an operator provisions
> it, and the whole record sits behind `AGENT_TREE_ENABLED` (default `false`,
> [Decision](#decision)), so a default deployment's behaviour is byte-for-byte
> unchanged by this record. No existing token-exchange gate is loosened; with
> the flag on, two are added — GATE 4d on every exchange, GATE 3d on every
> exchange whose subject token carries `cnf`, with 3d's denylist and ledger
> checks on every exchange (§4). The vitrin composition is a proposal into
> vitrin's open questions, not a description of anything vitrin does today.
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
instances, spawn, or a tree. Three 2026 individual drafts partition the rest (McGuinness: actor identity and
chain shape; Liu: signed per-hop records; Niyikiza: offline attenuation); none
is adopted by a working group. QAuth defines the seams itself and says so
([Standards position](#standards-position)).

### What exists today and what this record adds

| Concern           | Today (verified 2026-09-21)                                                                                                                                                                                                                                                                                                                                                                                                                      | This record adds                                                                                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Delegation hop    | `handleTokenExchange`, `apps/auth-server/src/app/routes/oauth/token.ts:1207` — confidential-only, gates 1–4c, `act = { sub: client_id, act? }`, depth ≤ `MAX_DELEGATION_DEPTH` (`apps/auth-server/src/app/helpers/agent-audit.ts:22`), lifetime capped by the subject's remaining life, no refresh token issued                                                                                                                                  | A spawn assertion signed by the parent's key, a DPoP proof from the child, an instance thumbprint, and a ledger row per hop                                          |
| Session root      | None. `jti` is `randomUUID()` and never persisted in Postgres — no issued-token row, no parent link (`libs/server/jwt/src/lib/jwt-service.ts:80`); Redis holds it only as a TTL'd denylist key (and, with hybrid signing on, the PQC sidecar key); no `sid` in non-test code; `sessions` is the browser login session (`libs/infra/db/src/lib/schema/sessions.ts:7`)                                                                             | `sid` on every agent access token, inherited unchanged by every exchange                                                                                             |
| Instance identity | None. No `cnf`, no DPoP, no mTLS; every agent token is a plain bearer                                                                                                                                                                                                                                                                                                                                                                            | DPoP-bound agent tokens (`cnf.jkt`), key held by a local helper                                                                                                      |
| Chain record      | `audit_logs.delegation_chain` (flattened `client_id` list, `libs/infra/db/src/lib/schema/audit.ts:54`); `findByRealmAndActorClientId` has no HTTP caller (`libs/infra/db/src/lib/repositories/audit-logs.repository.ts:218`)                                                                                                                                                                                                                     | An agent-token ledger keyed by `jti` with `parent_jti` and a stable node id, served by introspection and the dashboard                                               |
| Introspection     | `POST /oauth/introspect` returns no `act`, `jti` or `token_use` (response built at `apps/auth-server/src/app/routes/oauth/introspect.ts:229`); secret-based client auth only                                                                                                                                                                                                                                                                     | `act`, `jti`, `sid`, `token_use`, `cnf`, `authorization_details`, `qauth_delegation`; `private_key_jwt` accepted                                                     |
| Revocation        | Per-`jti` Redis denylist with TTL (`revokeJti`, `apps/auth-server/src/app/helpers/token-revocation.ts:30`); ownership = `client_id` of the token (`apps/auth-server/src/app/routes/oauth/revoke.ts:164`); `family_id` cascade for refresh tokens only                                                                                                                                                                                            | Revocation by `sid` (tree) and `jti` (subtree) with cascade; the user and any live ancestor node in the tree (by its key) may revoke; CAEP `session-revoked` emitted |
| Purpose / rights  | RFC 9396 absent; the only reference rejects inbound `authorization_details` on the ID-JAG path (`apps/auth-server/src/app/helpers/id-jag.ts:433`)                                                                                                                                                                                                                                                                                                | One RAR type, narrow-only across hops, returned in introspection                                                                                                     |
| Consent           | `consentPage` has no agent input; `agent:*` renders raw (`apps/auth-server/src/app/routes/ui/consent.ts:134`, `describeScope` in `apps/auth-server/src/app/helpers/consent.ts:114`)                                                                                                                                                                                                                                                              | The tree ceiling on the consent screen                                                                                                                               |
| Resource side     | `McpGuard` validates `iss`/`aud`/`exp`/scope exactly, normalises no `act`/`jti`, emits nothing back (`libs/fastify/plugins/mcp-guard/src/lib/core.ts:60`, `ValidatedToken` in `libs/fastify/plugins/mcp-guard/src/types.ts:31`)                                                                                                                                                                                                                  | `act`/`sid`/`jti` normalised, DPoP verified per resource, optional event emission and online decisions                                                               |
| Events            | None — no SSF, SET, CAEP or webhooks                                                                                                                                                                                                                                                                                                                                                                                                             | An SSF transmitter (revocation) and an RFC 8935 push endpoint (resource-side and agent-side actions), with a registered-transmitter roster the owner can extend      |
| CLI               | Nothing                                                                                                                                                                                                                                                                                                                                                                                                                                          | `qauth-broker` (keys, spawn, `git`/`gh`/`psql` credentials), a QAuth-side GitHub STS and a PostgreSQL 18 validator module                                            |
| Agent identity    | None. `oauth_clients.is_agent` is a self-asserted flag on a client registration (`libs/infra/db/src/lib/schema/core.ts:234`); `developer_id` is the only ownership signal and is NULL for every anonymous DCR client ([ADR-012](./012-dynamic-client-ownership.md)); `logo_uri` and `client_uri` land in the `metadata` jsonb at registration (`apps/auth-server/src/app/routes/oauth/register.ts:178`) and are shown on the consent screen only | An `agents` table — a principal with an owner, a name, an avatar and per-platform bindings — served as a SCIM `Agent` resource and a public profile (§13)            |
| Human approval    | None. The only step-up is a fresh browser login during authorization (`evaluateStepUp`, `apps/auth-server/src/app/helpers/step-up.ts:196`); no passkey, TOTP or CIBA code                                                                                                                                                                                                                                                                        | A CIBA poll-mode approval request, a passkey-confirmed approval page and a separate elevation leaf for the approved step (§14)                                       |

Two facts in that table shape everything below. GATE 3c requires the subject
token's `aud` to contain the exchanging client's `client_id`
(`apps/auth-server/src/app/routes/oauth/token.ts:1354`), and `resolveAudience`
sets `aud` to the RFC 8707 `resource` when one is present, else the client's
audience allowlist, else the client's own id
(`apps/auth-server/src/app/helpers/client-auth.ts:521`) — so a child with a
distinct `client_id` can exchange only if the root token already named it, and
an MCP client that sends `resource`, as MCP 2026-07-28 requires, gets a root
token that names nobody. And exchange is confidential-only at three layers
(`allowPublic: false` at `apps/auth-server/src/app/routes/oauth/token.ts:204`,
DCR refusal at `apps/auth-server/src/app/helpers/dynamic-client-registration.ts:224`,
CIMD drop at `apps/auth-server/src/app/helpers/cimd.ts:366`) — so a child needs
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
from any host, minting DPoP-bound tokens under its own key with the same
`sid`, until the user revokes the `sid` (§6). The type key alone buys less: it
cannot spawn (GATE 3d needs the parent's DPoP key, held only in broker
memory) and cannot root a tree (a `client_credentials` token roots nothing,
§1; a root needs a browser consent the user sees). To keep such a leak to one
box, the operator registers one key per box in the type's `jwks` with a
distinct `kid`, never one key per type. **Not closed for what the broker
vends.** A GitHub installation token is a plain bearer that
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
tokens, not of the root refresh path, not of vended bearers, and not misuse
within the ceiling.

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
needs a scope of its own, which no approval can grant or extend. A per-`sid`
budget caps how often a node may ask. A mute turns further asks into silent
denials. The approval page shows the typed request from QAuth's own records;
the model's words appear only in an attributed box. And an approval covers
one delta, for one node, for a bounded time, and is never passed down. Not
closed: an owner who approves what they should not. The record can make each
approval small, specific and costly to ask for; it cannot make the owner
read it.

The invariant the record exists to make provable: for every child token `c`
with parent `p`, `scope(c) ⊆ scope(p)`, `scope(c) ⊆ registered(type(c))`,
`aud(c) ⊆ aud(p)`, `mode(c) ≤ cap(type(c))`, `exp(c) ≤ exp(p)`,
`rights(c) ⊆ rights(p)`, `depth(c) ≤ 4`, `sid(c) = sid(p)`, `cnf(c)` = the key
that presented the exchange, and the exchange was authorised by the holder of
`cnf(p)`. Each is one check at mint; by induction every leaf is bounded by the
root, and the root by the human's consent. One consequence of
[ADR-007](./007-mcp-first-positioning.md)'s maintainer decision: the modes are
independent scopes and the check is exact set inclusion, so **a parent holding
only `agent:exec` cannot hand out `agent:readonly`**. The root grant carries
the union of the modes the tree may use, each child takes a subset, and the
consent screen shows the union (§11). An elevation (§14) stands outside this
chain on purpose: no exchange derives it, a passkey-confirmed approval of one
delta bounds it instead of a parent, and it can neither spawn nor narrow — so
no child ever holds what it grants.

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
nothing unless `AGENT_TREE_ENABLED` is on.

### 1. Session root — `sid` on agent access tokens

Every access token minted to an agent client (`isAgentClient`,
`apps/auth-server/src/app/helpers/client-resolution.ts:94`) from a
human-consented grant carries `sid`: an opaque string, unique within the
issuer, of at least 128 bits from a CSPRNG (`randomUUID()`, as `jti` is),
minted once per `authorization_code` grant and bound to that grant's consent
record. It is a column on the `refresh_tokens` row, copied on rotation as
`family_id` already is (`libs/infra/db/src/lib/schema/tokens.ts:178`), so a
refreshed token keeps it; every token derived by exchange inherits it
unchanged. The agent the grant names (§13), when it names one, travels the
same way: a nullable `refresh_tokens.agent_id` beside `sid`, copied on
rotation, inherited by every exchange. The ID token issued by the same code
exchange does **not** carry
it: the registered ID-token `sid` (Front-Channel Logout 1.0 §3) identifies a
User-Agent or device session for logout, which QAuth's `sessions` row is and
this grant identifier is not, and one browser session may root several
grants. A `client_credentials` token carries none and cannot root a tree:
exchange already requires an enabled user
(`apps/auth-server/src/app/routes/oauth/token.ts:1365`), so the root of a tree
is always a human `sub`.

**One root per main-agent process.** The broker runs the `authorization_code`
grant when a main agent's `SessionStart` hook registers its harness
`session_id` and pid over the socket (the registration
[Harness reality](#harness-reality) describes for teammates), so one Claude
Code session is one `sid`, the ledger's root row records the harness
`session_id`, and the root key is the one keyed to that process. A resumed
session (`--resume`/`--continue`, same `session_id`) reuses its root while the
grant's refresh token lives; a second `claude` process is a second root with
its own `sid`. The alternative, one root per broker start, is parked as
decision 8.

The return leg is a native app's (RFC 8252 §7.3): the broker opens the user's
browser on the authorization URL with PKCE `S256` and a `state` it minted,
listens once on a loopback redirect URI — `http://127.0.0.1:<port>/callback`,
the IP literal rather than `localhost`, which §8.3 says is NOT RECOMMENDED —
receives the code there, checks `state`, closes the listener (§8.3: open the
port for the request, close it on the response) and exchanges the code as
the type's confidential `private_key_jwt` client. QAuth matches
`redirect_uri` exactly (`redirectUris`,
`apps/auth-server/src/app/routes/oauth/authorize.ts:174`) and does not
implement §7.3's "MUST allow any port" for loopback, so the port is fixed,
the URI is the one entry in the type's seeded `redirect_uris` (decision 7),
and a broker that cannot bind that port refuses `login` rather than pick
another. Plain-HTTP loopback passes the environment gate in every profile —
`development` allows it outright, `staging` and `production` because they
require PKCE (`isRedirectUriAllowedForPolicy`,
`apps/auth-server/src/app/helpers/oauth-redirect.ts:68`).

A subject token with no `sid` — a legacy token, or one issued to a non-agent
client whose `aud` happens to name the agent — is neither refused nor left
sid-less: the exchanged token **starts a new tree** with a fresh `sid`, depth
0, and a `kind: root` ledger row (§2) whose `origin_jti` and
`origin_client_id` record the subject's `jti` and `client_id`. Refusing
would break an exchange that works today; a sid-less agent token is one no
tree can revoke. The same rule covers a `refresh_tokens` row that predates
the migration and so carries a NULL `sid`: the first `refresh_token` grant on
that family mints a `sid`, writes it onto the rotated row, and writes a
`kind: root` row for the token it issues, so the family joins a tree at its
next refresh rather than staying sid-less until an exchange.

`sid` is the IANA-registered "Session ID" claim (OIDC Front-Channel Logout 1.0
§3; Back-Channel Logout 1.0 §2.4 carries it in the Logout Token; the Standards
table has the rest of its trail). No specification places it in an access
token; this record defines that placement: **the session is the human's
authorization grant to the root agent, not a browser session**. Introspection
returns it as a service-specific member (RFC 7662 §2.2).

### 2. Ledger, not wire — the agent-token ledger

Every mint of a `sid`-carrying token for an agent client — the
`authorization_code`, `refresh_token` and exchange grants; a
`client_credentials` token (§1) writes nothing — writes one row to a new
table, `agent_token_ledger`: `jti` (key),
`sid`, `realm_id`, `user_id`, `agent_id` (nullable; the principal the tree
roots in, §13, copied from the root row to every descendant), `node_id`,
`parent_node_id` and `parent_jti`
(null at the root), `kind` (`root` | `refresh` | `spawn` | `narrow` |
`id-jag` | `elevation`, §14), `origin_jti` and `origin_client_id` (set only on the `kind: root`
row a sid-less subject started, §1), `client_id`, `instance_jkt`,
`scope`, `aud`, `authorization_details`, `depth`, `spawn_receipt` (the
verified spawn assertion's claims, §4), `approval_receipt` (the owner's
approval of an elevation, §14), `issued_at`, `expires_at`,
`revoked_at`, `revoked_by`, `revoke_reason`. Only public identifiers are stored
— never a token, key or secret, the rule `audit_logs` already keeps. Rows
outlive their tokens and are purged by `AGENT_LEDGER_RETENTION_DAYS` (default
90). **A ledger write failure fails the mint**: a token the ledger does not
know is a token the tree cannot revoke.

A **node** is a process, not a token — or, for the by-type case in
[Harness reality](#harness-reality), a key the session process holds on a
sub-agent type's behalf. `node_id` is minted at the first row for a (`sid`,
`instance_jkt`) pair; every later token under that key in that
session — a renewal, a narrowing — joins it, so a 300 s renewal is a new row
under the same node, and the dashboard tree and subtree revocation key on
nodes. Until §3 lands a node is one token.

Introspection serves the row: `POST /oauth/introspect` adds `act`, `jti`,
`cnf` and `authorization_details` (registered members), the QAuth markers
`sid` and `token_use`, and one service-specific member, **`qauth_delegation`**
— `node_id`, `parent_jti`, `depth`, `revoked`, `agent` (the row's
`agent_id` handle, absent when NULL, §13) and `chain`, a root-first array
of `{ jti, client_id, issued_at }` for a resource caller; ancestors' `jkt` and
`scope` are returned only to the session owner's portal and to a node of the
same tree presenting its own DPoP-bound token (§6), which already hold them
(RFC 7662 §2.2 lets the AS answer each caller differently). The name is
vendor-prefixed on purpose: `delegation` is already a registered JWT claim
(OpenID Federation 1.0 §13.6) with unrelated semantics. RFC 8693 §4.1 forbids
using prior actors in access-control decisions; the chain is for audit and
display. Introspection and revocation also start accepting `private_key_jwt`
(`apps/auth-server/src/app/helpers/discovery.ts:147` is secret-only today).

**draft-liu's `delegation_chain` claim is not adopted** (the Alternatives
table has the size, the `wit://` scheme — WIMSE defines `wimse://` and has
asked IANA to register it, WIMSE-ID — and the moving signed-field set); its
own §10.6 names "chain by reference" — a compact token plus introspection —
as the mitigation, and that is this decision. Trigger to
revisit: working-group adoption, or a stable signed-field set. The ledger
holds every field of its record except the two detached signatures, so
emitting the claim later is a serialisation, not a migration.

### 3. Instance identity — DPoP-bound tokens, keys in a helper

Agent tokens are DPoP-bound (RFC 9449) to a per-process key: `cnf.jkt` names
the process, `token_type: DPoP`. Agent types are registered with
`dpop_bound_access_tokens: true` — operator-set, seed manifest only, like
`max_agent_mode` (`libs/infra/db/src/scripts/seed-oauth-clients.ts:102`) — so
a token request without a `DPoP` header is refused (§5.2); §5's "regardless
of grant type" makes the exchange grant carry the proof. The root client is
confidential (`private_key_jwt`), so its refresh token is sender-constrained
by client authentication, not by the key — §5 says exactly that.

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
audience alone. mcp-guard's DPoP verification is a per-resource opt-in; a
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

`act` adopts draft-mcguinness's shape — `iss`, `sub`, `sub_profile` set to
`ai_agent`, optional nested `act` — where `iss` is QAuth's issuer identifier
(the namespace of `sub`), `sub` is the actor's `client_id` — the value an
RFC 7523 client assertion presented as `actor_token` would yield (§6.3.1,
§6.3.1.2 step 3; §14.2 calls `iss` = `sub` = `client_id` the conformant
pattern); §3.2 keeps `client_id` itself an auxiliary client-identity signal,
so the draft's actor identifier is the (`act.iss`, `act.sub`) pair, durable
and never a thumbprint (§14.12) — and nested `act` is the prior chain,
preserved exactly. This deviates from §14.7's SHOULD: where one `client_id`
fronts several acting instances the draft wants `act.sub` to name the
specific instance; QAuth keeps the instance in `cnf.jkt` and the ledger node
instead, because §14.12 says `act.sub` SHOULD NOT be key-derived and this
record mints no other per-instance identifier (§2; Alternatives, "One DCR
client per agent instance"). Prior actors' thumbprints
live in the ledger, not inside `act`: RFC 8693 §4.1 makes `act` members
identity claims only, and the draft defines no per-actor confirmation. The
current presenter is the top-level `cnf` (§3.7.1). `actClaimSchema`
(`libs/server/jwt/src/lib/access-token-claims.ts:29`) becomes a loose object
requiring `sub` and admitting `iss` and `sub_profile`, so extension members
are ignored rather than stripped (§3.4).

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
  identifier (the rfc7523bis rule), `iat`, `exp` ≤ `iat` + 60 s, `jti` (single
  use), `ath` = the hash of the `subject_token` computed as RFC 9449 §4.2
  computes it for a DPoP proof (binding one token instance —
  draft-niyikiza's `par_hash` property), `cnf.jkt` = the child's key
  thumbprint, `scope` = the ceiling the parent grants, `authorization_details`
  = the child's purpose and rights (§5), optional `resource`/`audience`.

The AS adds one gate, **3d**, after GATE 3c and before the enabled-user check:
the subject token's `jti` is not in the Redis denylist (`isJtiRevoked`, which
no exchange path calls today — `verifyAccessToken` at
`apps/auth-server/src/app/routes/oauth/token.ts:1298` is signature, `exp` and
issuer only) and, when the subject has a ledger row, that row has
`revoked_at IS NULL`; `typ` exact; header `jwk` thumbprint equals the subject
token's `cnf.jkt`; signature verifies under that key; `aud` equals the issuer;
unexpired, lifetime ≤ 60 s; `jti` unseen (Redis, the `consumeIdJagJti` idiom,
`apps/auth-server/src/app/helpers/id-jag.ts:244`; store unavailable ⇒ refuse);
`ath` matches the presented `subject_token`; `sub` equals the authenticated
client; `iss` equals the subject token's `client_id`; `sub` is in the
registered `spawn_allowlist` of the `iss` type (one `oauth_clients` lookup by
the subject token's `client_id`, operator-set like `max_agent_mode`) — so the
root's `aud` bounds which types the tree may contain and each type's own
allowlist bounds what it may spawn, including itself; a same-key narrow
presents no assertion and never reaches this check; `cnf.jkt` equals the DPoP
proof's key; and when (`sid`, `cnf.jkt`) already names a node, that node has
`revoked_at IS NULL`, the same `client_id` as the assertion's `sub` and the
same parent node as the subject token's — a spawn onto a revoked or foreign
key is `invalid_grant`, so a revoked node cannot be renewed by the next sweep
and two agent types can never share one node. Any failure is `invalid_grant`,
audited (the denylist and ledger checks also run for a legacy bearer subject,
where they are the only new part of 3d; GATE 4d below runs for every subject,
bearer or bound). The DPoP key is generated per process and
is never a key registered in the type's `jwks`, so no assertion it signs can
authenticate the client; the client-assertion verifier additionally rejects
`typ: spawn-assertion+jwt` and DPoP-proof verification rejects any JWT
carrying `sub` or `cnf`, so the three JWT types the key family produces are
disjoint by `typ` and by claim set, not by `typ` alone. The verified claims
become the row's `spawn_receipt` — the post-hoc proof the OAuth-list thread
distinguishes from cross-validation, and the dashboard's "who authorised this
hop". **A subject token that carries `cnf` cannot be exchanged to a new key
without a spawn assertion**; a DPoP-bound token presented by a party that
cannot prove the holder authorised it is exactly the captured token GATE 3c
exists to stop.

This is **QAuth-defined, not draft-mcguinness's presenter rebind**: §3.7.3
installs a new presenter only through a validated `actor_token` whose own
top-level `sub` names it, and there is no `actor_token` here. The profile's
conformant shape is §6.3.1 — the child's RFC 7523 client assertion as
`actor_token` with `actor_token_type=urn:ietf:params:oauth:token-type:jwt`,
which GATE 2 refuses today
(`apps/auth-server/src/app/routes/oauth/token.ts:1282`) — the future
conformance path, **not adopted** for the reason the Alternatives table gives.

The existing gates all still run and all still narrow: **(c)** GATE 3c and
the 3d allowlist bound the types, as above; **(d)** GATE 4a scope ⊆ subject
scope, and now ⊆ the assertion's `scope`; a
new **GATE 4d**, scope ⊆ the child type's registered `oauth_clients.scopes`
(`validateScopes`, `apps/auth-server/src/app/helpers/client-auth.ts:484`, the
check `client_credentials` already runs), so a type registered without
`write:*` can never hold it whatever its parent grants — GATE 4c gives the
same floor for `agent:*` through `max_agent_mode` (`enforceAgentScopeCap`,
`apps/auth-server/src/app/routes/oauth/token.ts:1405`); GATE 4b `aud` ⊆
subject `aud`; the lifetime clamp; the depth cap; rights narrowing (§5).
**(e)** The requesting client is the child's agent type, authenticated with
`private_key_jwt` or a client secret the broker holds; exchange stays
confidential-only. The client credential names the type, not the instance
(§9); the instance is the DPoP key (§3). The minted token: `sub` = user,
`client_id` = child type, `cnf.jkt` = child key, `act` extended (§3), `sid`
inherited, new `jti`, **no refresh token** — the code's invariant stands, so
`exp(c) ≤ exp(p)` holds on the token itself. A node renews by re-spawn under
its parent's current token with a fresh assertion for the same key, root-down
in one broker sweep (the root by its refresh token); the new row joins the
same node.

**Narrow versus spawn.** A **self-narrowing** — same client _and same key_,
deriving a single-audience leaf — is `kind: narrow`: the DPoP proof under the
subject token's own key is the possession proof (draft-mcguinness §3.7.2,
presenter continuation), no assertion is needed, `act` is preserved exactly
(§3.6.3.2, so a leaf spends no depth), and a ledger row is written all the
same. **Same-type children.** Claude Code spawning a teammate is a child whose
`client_id` equals its parent's: a full hop, `iss` = `sub` in the assertion,
allowed only when the type's own `spawn_allowlist` names itself (GATE 3d) —
its `client_id` is always in `aud` for the narrow, so 3c alone would not gate
it — a new key, `act` nested one deeper, depth counted. A spawn's
`audience`/`resource` names the child's own `client_id`, the types it may
itself spawn and the resources it may reach, all ⊆ the parent's `aud` (GATE
4b) and, for the types, ⊆ the child type's allowlist (3d).

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
and homepage (#112, `apps/auth-server/src/app/routes/ui/consent.ts:190`), the
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
denylist with its remaining TTL (`revokeJti`), so the hot path —
`isJtiRevoked` on `requireJwt` (`apps/auth-server/src/app/app.ts:330`) and
introspection — stays a Redis lookup. The walk and a mint must not race. A
mint (root, spawn, narrow or renewal) inserts its row in a transaction that
first locks its parent's ledger row (`SELECT ... FOR UPDATE` on `parent_jti`)
and refuses with `invalid_grant` when that row carries `revoked_at` — the
denylist and `revoked_at` checks GATE 3d adds (§4) are new: today the
`isTokenRevoked` hook runs only inside `requireJwt`
(`libs/fastify/plugins/jwt/src/lib/fastify-plugin-jwt.ts:367`), so this is the
only thing that stops a revoked parent from renewing or spawning within its
remaining lifetime. The walk marks top-down: it updates a node's `revoked_at`
before it reads that node's children, so a mint holding the parent's lock
either commits before the mark (and is then found as a child) or reads the
mark and refuses. Denylist writes run after the ledger transaction commits.
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

Who may revoke, and how: the token's own client over `POST /oauth/revoke`
(RFC 7009, unchanged, now cascading); the **session owner** (the ledger row's
`user_id`, from the portal) and a **live node of the same tree** over a
QAuth-defined identifier API, `POST /api/agent-sessions/{sid}/revoke` and
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
alone revokes nothing, above), so the session owner's revoke-by-`sid` from
the portal is the remedy.

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
looks the subject `jti` up in `agent_token_ledger` and refuses (400, one
audit line) unless the row's `aud` contains an identifier the transmitter is
registered to report for — its own `client_id` for the broker, the resource
identifiers listed on its `oauth_clients` row (`event_audiences`,
operator-set, the same identifiers `AGENT_BEARER_LEAF_RESOURCES` names) for
an mcp-guard host or a validator — so a transmitter may report only on
tokens minted for it; an unknown `jti` is refused the same way. It never
reads the token itself. `agent_actions` is keyed by the SET's `jti` scoped to
the transmitter (RFC 8417 §2.2: unique within a feed; a duplicate is
acknowledged and dropped), records the transmitter's `client_id`, and is
indexed by the subject `jti`; a SET whose `iat` is older than
`AGENT_EVENT_WINDOW` (default 300 s) is refused. Emission is asynchronous
and best-effort. The dashboard's tree is the ledger joined with
these rows, streamed live from the portal (`GET /api/agent-sessions`,
`GET /api/agent-sessions/{sid}` and `/{sid}/events` over server-sent events).

**Agent-side transmitters.** The roster above is the operator's. An agent's
owner (§13) runs things beside the harness that see what the resource never
does — a loopback proxy that knows which model actually served a request, a
runtime that knows why a step was taken, a git hook that knows which commits
left the box — and QAuth takes their events on the same endpoint under the
same rule, with two additions. First, the owner, not only the operator, may
register a transmitter: an `agent_transmitters` row keyed by the `agents`
row it reports for, holding a `jwks` and the `event_audiences` it may name,
created through the owner's portal or the developer API with the same
ownership check ADR-012 uses for clients; the owner is the responsible party
for what it sends. Second, the subject check is widened by one hop: an
agent-side SET is accepted when the subject `jti`'s ledger row belongs to a
tree whose root `agent_id` is the transmitter's agent. It is still refused
for any `jti` outside that agent's trees, and it is still a claim: every
member an agent-side transmitter writes lands in `agent_actions` with
`source: agent`, is shown apart from the other rows, and is never an
input to §8. `agent_actions.source` is one of `resource` (an mcp-guard host
or a validator), `broker` (the broker's vends and its push report, §9,
signed as the harness type from the operator's roster) and `agent` (an
owner-registered transmitter); the dashboard labels all three. Registration is by out-of-band exchange of the transmitter's
public keys and the push URL — RFC 8935 alone. SSF stream management (SSF 1.0
§7, §8) is receiver-initiated: the receiver reads the transmitter's
`/.well-known/ssf-configuration` and creates the stream there, which a
daemon on a laptop behind NAT cannot serve. A transmitter-initiated
registration and an `agent-action` event type are what QAuth would take to
the Shared Signals WG, which is extending SSF and CAEP toward agentic use
cases; until either exists the out-of-band row is the mechanism, and the
event URI stays QAuth's.

**The agent on a stored row, and the members that name a model.** Every
`agent_actions` row gains an `agent_id` column that QAuth fills from the
subject `jti`'s ledger row; it is not an event-type member, and a SET that
carries an `agent` member is refused (the `caused_by` rule, §5). Two
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
Access Request and Approval Profile (Draft 1) is the shape of a requestable
denial: a `false` decision carrying `context.access_request` (§7), and an
approval that expires at `approved_until` (§12). It leaves binding an
approval to OAuth token issuance to a profile; §14 is that binding on
QAuth's side, with CIBA as the wire. The evaluation endpoint does not
return `context.access_request` yet.

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
  that resource and its proof (a bearer node token until P1a). QAuth verifies
  the proof, reads the ledger row (not revoked), restricts `repositories` ⊆
  the token's `locations` and `permissions` ⊆ its `actions` — until §5 lands,
  ⊆ an operator-set policy per agent type in QAuth configuration,
  octo-sts-shaped — and mints with the App's private key, which lives in
  QAuth's configuration and never on the developer box; Chainguard's octo-sts
  is the prior art and an interim option. Once P1a lands the STS accepts
  `Authorization: DPoP` only, checks `htu`/`htm`/`ath` and `aud` = its own
  identifier exactly, and refuses to start if its identifier appears in
  `AGENT_BEARER_LEAF_RESOURCES`: the one endpoint that turns a 300 s
  sender-constrained token into an hour-long unconstrained one never accepts
  a bearer. The broker caches each node's installation token for its one
  GitHub hour and deletes it at node end and the moment it learns of
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
  environment from the agent's GitHub binding — the App's bot login and its
  `<id>+<slug>[bot]@users.noreply.github.com` address, which QAuth records
  on the binding at provisioning — so a commit the agent wrote is authored
  by the agent, and the hook adds `Model: <model>` from the node's reported
  model (§7, a report) and `Agent: <agent_id>`. The broker writes no
  `Signed-off-by`, `Reviewed-by` or `Assisted-by` line and refuses a commit
  message that carries one from the node: the first two certify a human's
  act and only a human adds them at review or merge; the third means a
  human wrote the code with an agent's help, the kernel's `Assisted-by:
AGENT:MODEL` convention (`Documentation/process/coding-assistants.rst`,
  merged April 2026), and never appears on an agent-authored commit. A
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

For an agent client the consent screen states that the client is an AI agent
— and, when the root names an agent principal (§13), which one: its
`display_name` and its owner's display name, each escaped by the same
`html` tag as the client name (§5), and its avatar, served from QAuth's own
origin at the fixed path §13 gives, so the person sees "Majordomo, owned by
you" and not only "claude-code" — and shows the ceiling of the tree
it may grow: the scopes with descriptions
(today `agent:*` and `write:*` render raw), including the **union** of agent
modes the tree may use, since no mode implies another; the agent types it may
spawn — the client's operator-set `spawn_allowlist`, written into the root
token's `aud` beside the requested `resource` and the client's own `client_id`
so GATE 3c stays byte-identical; the client-attributed `purpose` from
`authorization_details` (§5), in its own box beneath the scope descriptions;
and the persistence rung, "may keep working until you revoke it" — a code
grant always issues a refresh token
(`apps/auth-server/src/app/routes/oauth/token.ts:603`), so every root can renew
until `sid` revocation or the refresh family expires. One sentence says the
agent may delegate downwards within this ceiling and never beyond it.
`spawn_allowlist` follows `max_agent_mode`: seed manifest only, never DCR,
CIMD or the developer API. Enrichment is conditional on the column:
`resolveAudience` adds the client's own `client_id` and its `spawn_allowlist`
to `aud` only for an agent client whose `spawn_allowlist` is non-empty. A
client with none — every DCR and CIMD client, every seeded type an operator
has not given an allowlist, and therefore every client in a default
deployment — keeps today's `aud` byte-for-byte, presents that token at its
resource as today, and can neither spawn nor narrow: a tree of one. An
allowlisted type's root always names at least itself, which is what lets it
narrow, and that root is the one the broker holds.

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
leaf. The skip-consent fast path is untouched, and a `sid` is minted per
grant, not per screen — but a root grant that names a dangerous scope
(`agent:exec`, `agent:admin`, any `write:*`) never takes that path in
`staging` or `production`: step-up rule 3 (`evaluateStepUp`,
`apps/auth-server/src/app/helpers/step-up.ts:196`) forces a fresh login
for the whole requested set unless the browser session is under two minutes
old, and only a `development` profile relaxes it. The default `claude-code`
root (decision 7) is `exec`, so each new root costs the user one login; a
read-only-only root does not.

### 12. Harness — a node is a process

A node exists only where a process holds its own handle. The broker resolves
a caller by walking the `SO_PEERCRED` pid's parent chain to the first bound
pid; a chain that reaches no bound node is refused and logged — never
attributed to the session. The session node is bound like every other node:
`qauth-broker login` opens a pidfd on the session process (fallback: pid plus
`/proc/<pid>/stat` start time, field 22), and every binding — session,
teammate, executor child — is a pidfd or pid+start-time pair, so a recycled
pid never inherits a node, and the broker unbinds a node the moment its pidfd
signals exit. An in-process sub-agent shares the session process and so
shares the session node; that is the harness limit, not a default. Which
nodes can be bound today, and which cannot, is in
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
transmitter for it (§7) or deactivate it. The harness hooks' own `agent_id`
(a sub-agent instance, [Harness reality](#harness-reality)) is a different
thing with the same name and is never written to the ledger. There is no email on an agent and
none is needed: [ADR-002](./002-identifier-abstraction.md) already made
email a credential, not an identity, and an agent has no credential of its
own — it acts through the harness types and keys this record already binds.

**Where it sits in the tree.** `sub` stays the human (§1); nothing here
touches the root invariant. The agent is named in the root grant: an agent
client that authorizes with `agent_id=<handle or uuid>` on the authorization
request roots the tree in that agent, and QAuth refuses the request
(`invalid_request`, audited) unless the row is active and its
`owner_user_id` is the authenticating `sub` — the consent screen then names
the agent (§11). The ledger's `kind: root` row records `agent_id`; every
descendant row inherits it unchanged as `sid` is inherited (§2); introspection
returns it in `qauth_delegation` as `agent`; revocation gains one more
identifier, `POST /api/agents/{id}/revoke`, which cuts every live tree of
that agent by the §6 walk and may be called by the agent's current
`owner_user_id` or a realm admin — not by a node, whose reach stays its own
subtree (§6). After a transfer (decision 10) the trees the previous owner
consented to keep their `user_id`, so that person can still cut them one
`sid` at a time as session owner, while the new owner cuts all of them by
agent. `act` is untouched: `act.sub` remains the harness
type's `client_id`, because draft-mcguinness's actor identifier is a client
identifier and §14.12 wants it durable, and the agent is not a client. A
grant with no `agent_id` is byte-for-byte today's grant: the column is NULL
and every consumer treats NULL as "no agent named".

**SCIM projection.** `agents` is served as the SCIM `Agent` resource of
`draft-wzdk-scim-agent-resource-00` (June 2026, individual, Informational) at
`/scim/v2/Agents`, schema `urn:ietf:params:scim:schemas:core:2.0:Agent`:
`agentUserName` ← `handle`, `displayName`, `description`, `active`, and
`owners[]` ← one value whose `$ref` is the owner's User resource. The draft
defines no avatar and no platform binding, so both go in a QAuth extension
schema, `urn:qauth:params:scim:schemas:extension:agent:1.0`, with `avatar`
(a URI on QAuth) and `bindings[]` (below) — named as an extension, never as
a core attribute, and offered to the SCIM WG list as feedback on the draft.
The projection is read-only in the first slice; the developer API and the
portal write the row. QAuth has no SCIM endpoint today, so this is the first
one, scoped to this resource, `GET` only, authenticated as the realm's
developer API is.

**Bindings.** A binding is one row per (agent, platform) in
`agent_bindings`: `platform` (`github` first; others as they are provisioned),
`external_id` (the platform's identifier for the identity that acts — on
GitHub the _bot user's_ numeric id from `GET /users/{slug}[bot]`, which is
what the `noreply` address carries, not the App id), `external_app_id` (the
App id, where the platform has one), `external_login`, `external_email`
(the attribution address the platform assigns), `sts_app_ref` (the key in
QAuth configuration naming the App and private key the STS mints from for
this agent, §9), `proof` (how QAuth learned it; for GitHub, the STS App's
own `GET /app` and `GET /users/{slug}[bot]` answers at provisioning),
`bound_at`. For GitHub the binding _is_ the STS App of §9: the App's slug
is the agent's public name on that platform, its bot login the author of
every commit and pull request the agent makes (§9, provenance), its App page
the place GitHub itself shows the owner account as the developer. One STS
App per agent, then, not one per organisation — decision 4 is amended below
— and the App's private key stays where §9 puts it. The avatar the platform
shows is the platform's; GitHub exposes no API to set an App's logo, so the
owner sets it by hand from the same file QAuth serves, and QAuth records
nothing about whether they did.

**Public profile.** `GET /agents/{handle}` on the realm's public origin
serves the profile, unauthenticated: `display_name`, `description`, avatar,
the owner's display name, the bindings' `external_login`s, `active`, and a
fixed statement of what the page attests — that this agent is a principal of
this issuer owned by this person, and nothing about any commit, message or
action that names it elsewhere (T7). The same at `Accept: application/json`.
No `sid`, `jti`, node, scope, model or event ever appears on it; those are
the owner's and the realm admin's (§2, §6). An agent whose
`profile_visibility` is `private` answers 404, indistinguishable from a
handle that does not exist.

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
invariant still holds for every token an exchange derives; an elevation is
bounded by its own approval, not by a parent.

**The flow.**

1. **Refusal.** A node asks for more than its ceiling: at the token
   endpoint (`invalid_scope` from GATE 4a or 4d,
   `invalid_authorization_details` from §5), at the STS (§9), or at an
   mcp-guard resource (`403 insufficient_scope`). The broker sees the
   refusal.
2. **Request.** If the node's token carries `agent:request` (below), the
   broker files an approval request: an OpenID CIBA backchannel
   authentication request (CIBA Core 1.0 §7.1), in poll mode — poll,
   because the broker sits behind NAT, the same reason §6 polls its SSF
   stream. The broker
   authenticates as the node's agent type and adds a DPoP proof under the
   node's key. It sends:
   - `login_hint_token` = the node's own DPoP-bound token. CIBA requires
     exactly one of its three hints and leaves this one's format to the
     deployment; QAuth defines it as the requesting node's token, which
     names the user, the `sid` and the node;
   - the delta asked for: `scope` (with the `openid` value CIBA requires)
     and one `agent-task` entry in `authorization_details` (§5) naming one
     resource — RFC 9396 §3 lists CIBA requests among the places
     `authorization_details` may appear;
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
   choices:
   - **Approve once** — one elevation leaf for the one resource, with the
     `agentAccessTokenLifespan` lifetime (§6), or one STS vend.
   - **Approve for a while** — the owner picks the window: 15 minutes, one
     hour, or until the session's grant ends. A window never outlives the
     root's refresh family and never reaches a durable rung.
   - **Deny.**
   - **Deny and mute** — for this session, or for a chosen time. Further
     requests from that `sid` are refused with `access_denied` and notify no
     one.
5. **Token.** After an approval, the broker's next poll at the token
   endpoint (`grant_type=urn:openid:params:grant-type:ciba` and the
   `auth_req_id`, CIBA §10.1, with a DPoP proof under the same key)
   returns the elevation leaf; until then it gets `authorization_pending`,
   and on a denial `access_denied` (§11):
   - `sub` = the user, `client_id` = the node's type, `cnf.jkt` = the
     node's key, `sid` and `act` = the node's;
   - scope and `authorization_details` = exactly the approved delta — not
     the node's scope plus the delta;
   - one audience, the resource; no refresh token.

   The ledger records it as `kind: elevation`, with `parent_jti` = the
   requesting node's token and an `approval_receipt`: the request id, the
   approved delta, the duration, the passkey's credential id and the time
   of the assertion. Any token exchange whose subject is a
   `kind: elevation` token is refused with `invalid_grant`, spawn and narrow
   alike: the leaf is used where it was approved, by the node that asked,
   and nowhere else.

6. **A window.** While a window is open, the node renews its elevation leaf
   with a token exchange whose subject is its current node token, naming
   the approval id, under the same key. The renewal is a new
   `kind: elevation` row under the same approval.
   The window ends at its time, when the node's process dies (the dead-man
   switch, §6), when the `sid` is revoked, or when the owner ends it from
   the portal. The §6 walk treats elevation rows like any other row.

**Asking is a scope of its own.** `agent:request` is the right to file an
approval request at all. It sits in the root grant like any other scope,
and the consent screen shows it (§11). An approval can never grant or
extend it, an elevation never carries it, and a child gets it only by
narrowing from a parent that holds it. A per-`sid` budget caps asking —
`AGENT_APPROVAL_BUDGET`, operator-set, default three pending and ten an
hour — and no approval raises it. A node without the scope, over its
budget, or muted gets `access_denied`, and nobody is notified.

**Why a mute only denies.** In a chat client, "don't ask again" usually
means "allow from now on". Here it means "stop asking me". If it meant
allow, one tap would become a standing grant for whatever the agent asks
next — the approval-fatigue attack of T8. Repeated identical requests are
what "approve for a while" is for: it covers the same delta for the window,
so the agent has no reason to ask again. Decision 14 records the owner's
framing next to this default.

**Authenticators.** A passkey is the default and, in `production` and
`staging`, the only accepted factor: it is phishing-resistant and bound to
QAuth's origin, so a relayed link cannot capture it. A TOTP or other
offline code can be relayed by a phishing page — NIST SP 800-63B-4 §3.2.5
says manually entered OTPs "SHALL NOT be considered phishing-resistant" —
so it is weaker here (decision 15). A synced passkey is acceptable up to
AAL2 (SP 800-63B-4, Appendix B). No current standard lets the
authenticator itself show the request it signs — WebAuthn Level 1's
`txAuthSimple` extension is gone from Levels 2 and 3 — so what the owner
reads is the page QAuth renders, and the binding is QAuth's own: the
challenge is minted for this request and accepted for nothing else. A
wallet presentation bound to the request through OID4VP `transaction_data`
(OID4VP 1.0 §8.4; [ADR-004](./004-wallet-agnostic-federation.md)) is a
request-bound option behind `WALLET_FEDERATION_ENABLED`, not in the first
slice. QAuth has no passkey or TOTP support today (verified 2026-09-24), so
a WebAuthn credential provider is a precondition (P5).

## Alternatives considered

| Alternative                                                             | Why not                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Adopt draft-liu's `delegation_chain` in the token now                   | Individual `-00`, June 2026; records of 500–1000 bytes per hop; `wit://` identifiers defined only in its own terminology; signed-field set still moving. Ledger plus `qauth_delegation` carries the same facts; revisit on the §2 trigger.                                                                    |
| draft-niyikiza offline attenuation (holder-derived child tokens, no AS) | No `sub`, so no on-behalf-of; no ledger, so no dashboard or cascade; not an access token at any RS. Its `par_hash` binding is borrowed as `ath` in the spawn assertion.                                                                                                                                       |
| Transaction Tokens as the session identifier                            | Per-invocation, minutes-scale, single trust domain, "MUST NOT be used as an access token" (-11 §13.13). Not a durable root.                                                                                                                                                                                   |
| One DCR client per agent instance                                       | Anonymous DCR clients are unowned ([ADR-012](./012-dynamic-client-ownership.md)), get `NULL` `max_agent_mode` and a secret to keep; a `client_id` names a registration, not an instance. The instance is the key.                                                                                             |
| `may_act` as the allowed-children carrier                               | RFC 8693 §4.4 `may_act` is one party, a JSON object; a set of agent types is not expressible. `aud` ∋ client identifier is an example value §2.1 allows, read as "who may present this at the STS" per the splicing thread, and it is what GATE 3c already checks.                                            |
| A ledger `aud_ceiling` in place of GATE 4b's subject-`aud` bound        | Moves the on-token invariant `aud(c) ⊆ aud(p)` into a table; a resource server could no longer verify audience monotonicity from the tokens alone, and the consent screen would lose the resource ceiling it shows today. Enrichment keeps 4b byte-identical.                                                 |
| A refresh token per spawned node                                        | Reverses "no refresh token for a delegated token", replaces the on-token floor `exp(c) ≤ exp(p)` with a ledger check, and inherits a seven-day default; RFC 9449 §5 says a confidential client's refresh token is not DPoP-bound, so the node's key would not even protect it. Renewal is a re-spawn.         |
| The child's client assertion as `actor_token` (draft-mcguinness §6.3.1) | The conformant rebind shape, and a second URN relaxation on GATE 2; it names the child, not the parent's authorisation. Named as the future path, not adopted.                                                                                                                                                |
| The spawn assertion in the `actor_token` slot                           | RFC 8693's `actor_token` is the acting party's own identity, and GATE 2 pins it to access tokens. A parent-signed statement about a child is a different object; a new parameter keeps the semantics honest and GATE 2 untouched.                                                                             |
| mTLS instead of DPoP                                                    | A certificate per process needs a CA on the box; DPoP needs a JWK. Vitrin's wire is bearer-shaped either way; the JWT stays the credential.                                                                                                                                                                   |
| A local broker that mints GitHub installation tokens itself             | Puts the App's long-lived private key and the vend policy on the developer box, same uid as the model's shell: the agent could widen its own ceiling by editing a file. The STS keeps both server-side; the broker forwards, caches and deletes.                                                              |
| Hooks as the enforcement point                                          | `PreToolUse` cannot inject or remove a credential and cannot attribute an in-process sub-agent's CLI call. Hooks stay UX.                                                                                                                                                                                     |
| Short lifetimes only, no ledger cascade                                 | The floor, kept. The user must be able to kill a tree from the dashboard within the window, and a refused refresh is not an audit trail.                                                                                                                                                                      |
| Macaroons / Biscuits                                                    | HMAC chaining gives attenuation without proof of possession; Biscuits need a Datalog engine at every RS; neither is an OAuth token at mcp-guard, GitHub or PostgreSQL.                                                                                                                                        |
| The agent as a `users` row (a service account)                          | A user is the on-behalf-of `sub`; making the agent one would let a tree root in it with no human, which the exchange gate refuses on purpose (§1). A user also holds credentials of its own; an agent holds none (§13).                                                                                       |
| The agent as an `oauth_clients` row                                     | A `client_id` names a harness type shared across users and boxes (§6, §9); one client per agent recreates the per-instance registration ADR-012 rejected, and `developer_id` is NULL for every anonymous client. A client is not owned by a user the way an agent is.                                         |
| Agent identity in `act` (`act.sub` = agent)                             | draft-mcguinness §3.2 makes `act.sub` a client identifier and §14.12 wants it durable and never key-derived; the agent is not a client, and the harness type still has to be named. The agent is a ledger column and an introspection member, not an `act` member (§13).                                      |
| A public per-`jti` or per-commit resolver on QAuth                      | Puts ledger rows behind a URL anyone can enumerate from public commits; `sid` and `jti` confer nothing, but the rows are the owner's (§2, §6). The profile shows the principal and nothing below it; resolving a commit is the owner's record's job (§9, §13).                                                |
| Model name as a ledger fact                                             | QAuth never sees the model: the harness hooks report it at session start and on a switch, a loopback proxy sees it on the wire, and neither is QAuth's own observation. A report stays a report (§7, T7).                                                                                                     |
| SSF stream management for agent-side transmitters                       | Receiver-initiated by design (SSF 1.0 §7, §8): the receiver reads the transmitter's well-known configuration and creates the stream there, which a local daemon behind NAT cannot serve. RFC 8935 with an out-of-band `agent_transmitters` row now; a transmitter-initiated registration goes to the WG (§7). |
| Commit signing by the broker or by QAuth                                | A broker-held per-node key verifies against the ledger but GitHub reports it `unknown_key` and shows every agent commit Unverified; a QAuth-side signer with a registered key shows Verified but puts the AS on every commit, against the hot-path rule. Parked (decision 12).                                |
| Widen the live token or tree when the owner approves                    | Breaks the invariant: every child spawned afterwards inherits the extra right, and the root consent no longer bounds the tree. An elevation is a separate leaf for one node (§14).                                                                                                                            |
| An approve button in the notification (chat bot, email)                 | The button is not bound to a passkey on QAuth's origin: anyone who can read the channel — or the agent, if it can post there — could approve. A notification carries a link only (§14).                                                                                                                       |
| "Don't ask again" as an automatic approval                              | One tap becomes a standing grant for whatever the agent asks next; "approve for a while" already covers repeats of the same delta. A mute only denies (§14, decision 14).                                                                                                                                     |
| A TOTP code as the approval factor                                      | A one-time code can be relayed by a phishing page; a passkey is bound to QAuth's origin. Parked for non-production profiles (decision 15).                                                                                                                                                                    |

## Standards position

The composition caveat is the honest headline: **RFC 9449, RFC 9396, RFC 8707
and RFC 9700 never mention token exchange, and RFC 8693 never mentions `cnf`.**
"DPoP-bound exchange", "RAR narrowing on exchange" and "`aud` subset across
hops" are QAuth rules anchored on RFC 9449 §5's "regardless of grant type" and
RFC 9396 §6.1's "fewer permissions" — composition by analogy, not text.

| Piece                                                   | Position                                                              | Hook                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hop grammar, `act` nesting, top-level-only policy       | Covered                                                               | RFC 8693 §2.1, §4.1                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Who may present a token at the STS                      | Covered by analogy; list-thread guidance                              | RFC 8693 §2.1 (client identifier as an example `audience` value), §4.4 `may_act`; the splicing thread's `aud(N) = sub(N+1)`; GATE 3c                                                                                                                                                                                                                                                                                                                                                |
| Sender constraint, `cnf.jkt`, DPoP at the RS            | Covered by composition                                                | RFC 9449 §4.2, §5 ("regardless of grant type"), §5.2, §6, §7, §7.2; RFC 9700 §2.2.1; RFC 9449 never mentions exchange                                                                                                                                                                                                                                                                                                                                                               |
| Audience narrowing per hop                              | Covered by analogy                                                    | RFC 8707 §2.2 "subset thereof" (code and refresh only), §3 multi-audience caveat; RFC 8693 §2.2.2 `invalid_target`; monotonicity across exchange is GATE 4b                                                                                                                                                                                                                                                                                                                         |
| Purpose and ceilings                                    | Covered (mechanism); QAuth-defined (type)                             | RFC 9396 §2, §2.2, §6, §7, §9.1, §9.2, §12 (sanitise; bound by the type); RFC 9728 `authorization_details_types_supported`; the `agent-task` type and its subset rule are QAuth's, and §6.1 says no comparison is standardised                                                                                                                                                                                                                                                      |
| `act.iss`, `sub_profile`, loose schema, preserve/extend | Proposed by draft                                                     | draft-mcguinness-oauth-actor-profile-00 §3.2, §3.4, §3.5, §3.6.3.1, §3.6.3.2, §3.7.1, §6.3.1.2, §14.7 (deviates), §14.12                                                                                                                                                                                                                                                                                                                                                            |
| Presenter transition on spawn                           | QAuth-defined                                                         | Neither §3.7.2 continuation (that is the narrow) nor §3.7.3 rebind (no `actor_token`); §6.3.1 named as the future path                                                                                                                                                                                                                                                                                                                                                              |
| Spawn assertion                                         | QAuth-defined                                                         | Nearest: RFC 6749 §8.2 extension parameter, RFC 7521 assertion framework, rfc7523bis `aud` rule, RFC 8725 §3.11 explicit `typ`, draft-liu §5.2 `delegatee_id`, RFC 9449 §4.2 `ath` computation                                                                                                                                                                                                                                                                                      |
| Per-hop lineage                                         | Proposed by draft (not adopted); QAuth ledger                         | draft-liu-oauth-chain-delegation-00 §4, §10.6 chain by reference                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Child bound to the exact parent token                   | Proposed by draft (idea reused)                                       | draft-niyikiza-oauth-attenuating-agent-tokens-01 §4.6 `par_hash`                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Session identifier in access tokens                     | Registered claim; placement QAuth-defined                             | IANA JWT Claims `sid` (Front-Channel Logout 1.0 §3; Back-Channel Logout 1.0 §2.1); RFC 8417 §2.1.2 precedent; not in RFC 9068, not in the introspection registry                                                                                                                                                                                                                                                                                                                    |
| Introspection members                                   | Covered / QAuth-defined                                               | RFC 7662 §2.2; registered `act`, `cnf`, `authorization_details`, `jti`; extension `sid`, `token_use`, `qauth_delegation` (cross-domain use would need Specification Required registration; `delegation` is OpenID Federation 1.0 §13.6)                                                                                                                                                                                                                                             |
| Revocation cascade                                      | Covered (policy); QAuth-defined (API)                                 | RFC 7009 §2.1 "related tokens and the underlying authorization grant"; revoke-by-`sid`/`jti` endpoints are QAuth's                                                                                                                                                                                                                                                                                                                                                                  |
| Session-revoked signal                                  | Covered                                                               | SSF 1.0 §3.3 `complex`, §3.5 `jwt_id`, §7, §8.1.1; RFC 8935 push, RFC 8936 poll; CAEP 1.0 §3.1 (Final, 29 August 2025; approval announced 2 September 2025); RFC 9493 `opaque`, `iss_sub`                                                                                                                                                                                                                                                                                           |
| Resource-side action events                             | Covered (envelope); QAuth-defined (event type)                        | RFC 8417 §2.2 (`events`, `txn`, `toe`), RFC 8935 push; the `agent-action` URI is QAuth's                                                                                                                                                                                                                                                                                                                                                                                            |
| Agent-side transmitters and their registration          | Covered (envelope); gap (registration); QAuth-defined (members)       | RFC 8935 push with out-of-band keys; SSF 1.0 §7–§8 stream management is receiver-initiated and does not fit a NAT'd transmitter; no CAEP or SSF event type describes an agent's action (CAEP 1.0 §3 defines session, token-claims, credential, assurance-level, device-compliance and risk-level changes — states, never acts); the `model` and `reason` members and the server-written `agent_id` column are QAuth's; both gaps are what QAuth takes to the Shared Signals WG (§7) |
| Agent identity record                                   | Proposed by draft (shape adopted); QAuth extension (avatar, bindings) | draft-wzdk-scim-agent-resource-00 §3, §4.1, §4.2 (`Agent` resource, `agentUserName`, `displayName`, `description`, `active`, `owners`; no email, no avatar, no binding), RFC 7643 §3.3 extension schemas; the `urn:qauth:…:extension:agent:1.0` schema is QAuth's; draft-ietf-wimse-aims-00 §10.3 keeps `client_id` = the acting workload, which is why the agent is not in `act` (§13)                                                                                             |
| Commit provenance                                       | Product convention; kernel process document                           | git author/committer identities; GitHub App bot login and `noreply` address; `Documentation/process/coding-assistants.rst` (`Assisted-by: AGENT:MODEL`, humans only add `Signed-off-by`); GitHub signature verification reasons (`unknown_key`) for the parked signing question                                                                                                                                                                                                     |
| Out-of-band approval                                    | Covered (decoupled flow); QAuth-defined (elevation, mute, budget)     | OpenID CIBA Core 1.0 §7.1 (one hint of three, `binding_message`, `requested_expiry`, profile parameters), §10.1 (poll), §11 (errors); RFC 9396 §3 (`authorization_details` in CIBA); FAPI-CIBA working copy §4.1.1 (poll, `binding_message`, confidential clients); AuthZEN AARP Draft 1 §7, §12; OID4VP 1.0 §8.4; WebAuthn Level 3; NIST SP 800-63B-4 §3.2.5                                                                                                                       |
| Decision API                                            | Covered; WG-draft binding; QAuth context                              | AuthZEN 1.0 §6.1, §9.2, §10.1, §11.2 (Final, 11 January 2026); COAZ-MCP Binding §7.1, §11.2 (WG Draft 1); `context.qauth` is QAuth's; AARP noted                                                                                                                                                                                                                                                                                                                                    |
| Agent framework vocabulary                              | WG draft (Informational)                                              | draft-ietf-wimse-aims-00 §8 (LLM never holds credentials), §10.3 (`client_id` = agent, `sub` = user), §11 (audit minimums)                                                                                                                                                                                                                                                                                                                                                          |
| CLI credentials                                         | Product documentation                                                 | PostgreSQL 18 `oauth` HBA and validator API; GitHub App installation tokens; git-credential protocol; `gh` environment precedence; octo-sts                                                                                                                                                                                                                                                                                                                                         |
| Vitrin                                                  | Workstream prose, no decision-log id                                  | WS-D §7.2, §7.3, §7.5 (workstream prose) and §7.6 (the one section headed DECIDED in `docs/plan/13-workstream-agent-integration.md`); vitrin's normative entry is owed and may amend the 300 s figure                                                                                                                                                                                                                                                                               |

### Watch list

Rows go into [`docs/spec-pin-log.md`](../spec-pin-log.md) with P0, each with
a `Re-check by` date no later than its expiry — `spec-pins.test.ts` fails the
build on a past date — so the rfc7523bis row cannot be pinned at `-11` past
27 Sep 2026: the P0 pin carries a re-check date on or before that day and is
re-pinned to the successor revision when it lands.

| Document                                                                    | Revision · date                                              | Expires                           | Why watched                                                                                                                                                  |
| --------------------------------------------------------------------------- | ------------------------------------------------------------ | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| draft-mcguinness-oauth-actor-profile (individual)                           | `-00` · 30 Apr 2026                                          | 1 Nov 2026                        | `act` shape adopted; depends on entity-profiles                                                                                                              |
| draft-liu-oauth-chain-delegation (individual)                               | `-00` · 6 Jun 2026                                           | 8 Dec 2026                        | `delegation_chain` trigger                                                                                                                                   |
| draft-niyikiza-oauth-attenuating-agent-tokens (individual)                  | `-01` · 15 Jun 2026                                          | 17 Dec 2026                       | attenuation invariants                                                                                                                                       |
| draft-asor-wimse-agent-delegation-chain (individual)                        | `-01` · 3 Sep 2026                                           | 7 Mar 2027                        | header only; open before citing                                                                                                                              |
| draft-ietf-wimse-aims (WG, Informational; replaces draft-klrc-aiagent-auth) | `-00` · 15 Sep 2026                                          | 19 Mar 2027                       | audit minimums; "LLM MUST NOT hold credentials"                                                                                                              |
| draft-ietf-oauth-transaction-tokens (WG)                                    | `-11` · 30 Jul 2026                                          | 31 Jan 2027                       | rejected as session id; `txn` reused                                                                                                                         |
| draft-ietf-oauth-identity-assertion-authz-grant (WG)                        | `-04` · 21 May 2026                                          | 22 Nov 2026                       | ADR-011 pin; actor profile layers on it                                                                                                                      |
| draft-ietf-oauth-client-id-metadata-document (WG)                           | `-02` · 6 Jul 2026                                           | 7 Jan 2027                        | agent client naming                                                                                                                                          |
| draft-ietf-oauth-rfc7523bis (WG)                                            | `-11` · 26 Mar 2026                                          | 27 Sep 2026                       | `aud` = issuer only; expires six days from now — the P0 pin needs a `Re-check by` on or before that day and a re-pin to the successor                        |
| draft-ietf-wimse-workload-creds / -wpt (WG; s2s-protocol is dead)           | `-02` · 2 Jul / 27 Aug 2026                                  | 3 Jan / 28 Feb 2027               | one identity per credential                                                                                                                                  |
| draft-oauth-ai-agents-on-behalf-of-user (individual)                        | `-02` · 26 Aug 2025                                          | expired 27 Feb 2026, no successor | expired; its consent-time disclosure of the acting party is the precedent for §11's allowlist line; `requested_actor` itself not adopted                     |
| AuthZEN COAZ-MCP Binding / AARP (OIDF WG drafts)                            | Draft 1 · 13 Feb / 17 Sep 2026 (both WG-adopted 15 Jun 2026) | —                                 | request shape; park-and-approve                                                                                                                              |
| FAPI-CIBA (OIDF, Implementer's Draft)                                       | working copy · 26 Jun 2026                                   | —                                 | §14 follows its choices: poll, `binding_message`, confidential clients                                                                                       |
| MCP Authorization                                                           | 2026-07-28                                                   | —                                 | EMA still the only STABLE `ext-auth` extension                                                                                                               |
| draft-wzdk-scim-agent-resource (individual, Informational)                  | `-00` · 5 Jun 2026                                           | 7 Dec 2026                        | `Agent` resource shape adopted (§13); the SCIM WG is consolidating it with draft-abbey-scim-agent-extension (IETF 125 slides) — re-pin to whichever survives |
| draft-kushwaha-scim-agent-governance (individual)                           | `-00` · Jul 2026                                             | —                                 | lifecycle and autonomy extension on the same resource; not adopted, watched for the avatar/binding question                                                  |
| Shared Signals WG agentic extension (OIDF)                                  | announced Jul 2026, no draft yet                             | —                                 | where the `agent-action` event type and a transmitter-initiated registration would be proposed (§7)                                                          |
| Linux `Documentation/process/coding-assistants.rst`                         | merged Apr 2026                                              | —                                 | `Assisted-by` semantics reused in §9; a change there changes the convention                                                                                  |

## Explicitly out of scope

Machine-to-machine trees with no human root: exchange refuses a
`client_credentials` subject, and this record keeps it so. Cross-domain trees:
an ID-JAG or identity-chaining hop ends the tree at the domain boundary, and
the ID-JAG mint path of ADR-011 stays outside it — an assertion minted from a
tree token carries no `act` and no `sid`, the ledger records the mint as a
`kind: id-jag` row that can have no children, and the foreign AS's tokens are
outside the tree. A vitrin restore-token
analogue or any durable rung: a later ADR after vitrin's E3.7, if ever. A
policy language for the PDP: AuthZEN carries the question, not the policy.
Attestation of the process that holds a key:
draft-ietf-oauth-attestation-based-client-auth is not evaluated here.

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
gate.

- **P0 — the root is observable, and answers "which agent, in which session,
  with which scopes, opened this PR".** **0a, server:** the
  `AGENT_TREE_ENABLED` switch as the Decision defines it; `sid` on agent
  tokens (code, refresh, exchange) and the `refresh_tokens.sid` column;
  `agent_token_ledger` and
  its repository; ledger writes at the three mint sites; the sid-less-subject
  rule and the NULL-`sid` refresh rule; introspection members `jti`, `sid`,
  `token_use`, `act`, `qauth_delegation`; `GET /api/agent-sessions` and
  `/{sid}`; the
  GitHub STS on an operator-set per-type policy; spec-pin rows with their
  `Re-check by` dates. In P0 the STS accepts the node's bearer token (no proof
  until P1a); the broker's root `aud` is the seeded `audience` allowlist —
  own `client_id`, child types, the STS resource — since the broker sends no
  `resource`; a PR opened through a GitHub MCP server is outside this answer
  until P3. Tests: with the flag off, every token and the exchange are
  byte-identical to today's and no ledger row exists; claim presence and
  inheritance across code → refresh → exchange; one ledger row per
  `sid`-carrying mint and none for `client_credentials`, and a failed write
  fails the mint; a sid-less subject starts a new tree with a `kind: root`
  row; a pre-migration refresh family gains a `sid` on its next refresh; the
  introspection schema; the STS refuses a repository outside policy, against
  a mock GitHub. **0b, broker:** `login` on the fixed loopback port with
  PKCE, git-credential `get`, the `gh`
  shim, the commit trailer, the log. Tests: vend within policy, refusal
  logged, a `setsid`/double-forked descendant of a read-only node is refused,
  not attributed to the session; a process that reuses an exited teammate's
  pid is refused; installation token deleted at node end; a trailer resolves
  to a ledger row. **0c, agent identity:** the `agents` and `agent_bindings`
  tables, `agent_id` on the authorization request, on `refresh_tokens` and on
  the ledger's root row (§1, §2), the owner check at authorization,
  `qauth_delegation.agent`, the consent line (§11), the public profile, and
  the broker's author identity and `Agent:`/`Model:` lines from the binding
  (§9); revocation by agent waits for the §6 walk in P2. Tests: a grant
  naming an agent the `sub` does not own fails `invalid_request`; a grant
  naming an inactive agent fails the same way; a grant naming none is
  byte-identical to today's; every descendant row carries the root's
  `agent_id`; the profile of a private agent is 404 and the profile of a
  public one carries no `sid`, `jti` or scope; a commit made through the
  broker under an agent root is authored by the binding's login and address;
  a node-supplied `Signed-off-by` is refused. Honest limits: the spawn proof
  is possession-only until P1; the MCP leg is still Claude Code's own
  non-agent DCR/CIMD client, which never sends `is_agent`, so it is outside
  the tree until P3 (Harness reality, row 8); same-type children are told
  apart by ledger rows only; and the platform side of a binding is
  provisioned by the owner, outside this record.
- **P1 — keys and the tree.** **1a:** DPoP at the token endpoint (`cnf.jkt`,
  `token_type`, nonce), `dpop_bound_access_tokens` in the seed manifest,
  `AGENT_BEARER_LEAF_RESOURCES`, key custody in the broker, `private_key_jwt`
  at introspection and revocation, the introspection member `cnf`. **1b:**
  `spawn_assertion` and GATE 3d,
  GATE 4d, narrow versus spawn and node identity, the `act` shape and loose
  schema, `spawn_allowlist` and `aud` enrichment with the 3d allowlist check,
  `spawn_receipt`, the renewal sweep. Tests: a proof under the wrong key
  fails; a `cnf` subject exchanged to a new key without an assertion fails
  `invalid_grant`; a replayed assertion fails; a root grant carrying
  `agent:exec agent:readonly write:foo read:foo` spawns a read-only child and
  the child's exchange for `write:foo` fails `invalid_scope` at 4a, and at 4d
  when its type is registered without it; a `reviewer` seeded without an
  allowlist cannot spawn a `reviewer` even when its `aud` names it;
  `claude-code` spawning `claude-code` fails when its allowlist omits itself;
  a same-key narrow leaves `act` byte-identical and depth unchanged; a new
  key nests `act` once; a leaf cannot spawn.
- **P2 — purpose, ceiling, revocation.** The `agent-task` RAR type end to end
  with server-written `caused_by` and the introspection member
  `authorization_details`; the consent ceiling; revocation by `sid`
  and `jti`, the identifier API, the cascade and ancestry ownership; the
  `agentAccessTokenLifespan` row; the CAEP transmitter; the STS narrowed by
  `authorization_details`; `POST /api/agents/{id}/revoke` with its
  owner-or-admin rule (§13). Tests: widened `locations` fails
  `invalid_authorization_details`; a client-supplied `caused_by` is rejected;
  revoke-by-agent makes every tree rooted in the agent inactive and leaves
  the owner's other agents' trees alone, and a node calling it is refused;
  revoke-by-`sid` makes every descendant inactive at introspection and in the
  denylist; a spawn or renewal whose parent row is revoked fails
  `invalid_grant`; a denylist write failure mid-cascade answers 503 and leaves
  every marked row inactive at introspection; revoke-by-`jti` leaves siblings
  active; a revoked node is not renewed by the next sweep (the re-spawn for
  its key fails `invalid_grant`); a denylisted or `revoked_at` subject token
  cannot spawn; revoking the root's `jti` refuses the next refresh; the
  consent screen shows the union of modes and the allowlist.
- **P3 — observation.** The RFC 8935 push endpoint and event type, the
  `agent_actions` table, the operator-set `event_audiences` column on
  `oauth_clients` and `AGENT_EVENT_WINDOW`; mcp-guard normalises
  `act`/`sid`/`jti`, verifies DPoP per resource, emits events; the
  broker's proxy and `headersHelper` leaves so the MCP leg joins the broker's
  root and gains its `sid`; the portal's live tree; the `agent_transmitters`
  row and the one-hop subject rule for agent-side SETs, the `model` and
  `reason` members and the server-written `agent_id` column, the `source`
  column with its three values shown apart, the broker's `pre-push` SET (§7,
  §9), and the SCIM `GET /scim/v2/Agents` projection (§13). Tests: an event by `jti`
  lands on the right node; a revoked `sid` reaches the broker by poll, and a
  refused re-spawn reaches it with polling off; either deletes its
  installation tokens; a foreign local process — another uid, or a container
  on host networking — cannot obtain a signed request or a DPoP proof from the
  proxy; mcp-guard with DPoP on rejects a bound token presented as Bearer
  (RFC 9449 §7.2), with DPoP off accepts it; an agent-side SET for a `jti`
  outside the transmitter's agent's trees is refused; a transmitter-supplied
  `agent` member is refused and the stored row carries the ledger's; `model`
  and `reason` never reach introspection or the §8 request; the SCIM
  projection returns the owner as `owners[0]` and rejects writes.
- **P4 — the database, the decision API and vitrin.** `qauth_pg_validator`,
  the libpq hook library and the `psql` path; AuthZEN evaluation and metadata,
  default off; COAZ-MCP online mode in mcp-guard; the vitrin verifier
  contribution once https://github.com/vitrin-os/vitrin-os/issues/167 is
  scheduled; re-pin every watch-list row; `delegation_chain` if its trigger
  fired. Tests: the validator refuses a token whose `aud` is not the database
  and a role outside `actions`; the PDP can deny but never widen.
- **P5 — remote approval (after P2).** A WebAuthn credential provider —
  passkey registration and assertion in the portal; QAuth has none today;
  the CIBA backchannel endpoint in poll mode, with `login_hint_token` = the
  requesting node's token; `AGENT_APPROVAL_ENABLED`,
  `AGENT_APPROVAL_EXPIRY` and `AGENT_APPROVAL_BUDGET`; the `agent:request`
  scope; the `agent_approvals` table; the `kind: elevation` ledger row with
  its `approval_receipt`; the approval page; web push and the
  owner-registered webhook; mutes. Tests: an elevation carries exactly the
  approved delta and one audience; a `kind: elevation` subject cannot spawn
  or narrow; a request without `agent:request`, or over budget, is refused
  and notifies no one; a muted `sid` is refused and notifies no one; an
  approval without a fresh passkey assertion bound to the request is
  refused; the page's headline is the typed delta and `purpose` renders
  only in the attributed box; revoke-by-`sid` ends an open window; a window
  never outlives the refresh family; a notification body carries only the
  request id, the agent's handle and the URL.

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

| Tree node                                     | Bindable today   | How                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| The session's main agent                      | yes              | The broker holds its key and tokens and a pidfd on the session process opened at `login`, when the main agent's `SessionStart` hook registers `session_id` and pid; a Bash subprocess maps to that session's root node only when its `SO_PEERCRED` parent chain reaches that pid. An orphaned descendant (`( cmd & )`, `nohup`, `setsid`, double fork — reparented to pid 1 or a subreaper) reaches no bound node and is refused; a child that must outlive its spawner is started through the executor path below, which passes a handle.                                                                                                                                                                                                                   |
| Executor-spawned process                      | yes              | The executor is the runtime helper: it spawns the node and registers the child's pid with the broker over the socket before exec (a pidfd passed with `SCM_RIGHTS`, so pid reuse cannot rebind it); the handle in the child's environment is a label for logs, never a binding — the broker binds by `SO_PEERCRED` and ancestry and refuses a handle whose node is not on the caller's ancestry. Full CLI and MCP attribution.                                                                                                                                                                                                                                                                                                                               |
| Teammate                                      | yes              | A separate process; its `SessionStart` hook registers `session_id`, pid, process start time and its lead's `session_id` (read from the team config under `~/.claude/teams/`) with the broker, which opens a pidfd on it (fallback pid + start time) and spawns the teammate node under the lead's. The ancestry check maps every call that reaches the broker from that process, or from a descendant whose chain reaches it, to the teammate node — the CLI leg from P0b, the MCP leg once its `headersHelper` reaches the broker (P3); until then its MCP calls carry Claude Code's per-server token, the same one the lead presents (row 8). The binding ends when the pidfd signals exit, not when a pid is reused.                                      |
| Agent SDK agent                               | yes              | The application is the runtime: it obtains leaf tokens from the broker per `query()` and passes them in `mcpServers` headers; one process per agent is the application's choice.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Sub-agent with its own inline `mcpServers`    | by type          | The inline server is a `stdio` entry running the broker's proxy with the agent type as an argument; the broker attributes the child by `SO_PEERCRED` and ancestry, and `SubagentStart` says which instance of that type is live. Two concurrent sub-agents of one type share a node. Its key is created on the first `SubagentStart` of that type in the session — or, when no hook has announced the type (hooks disabled), on the proxy's first call under it — and retired on the last `SubagentStop` of that type or at session end; the start and stop events reach the broker by hooks (advice, not authority), so with hooks off the key lives until session end, and the node's dead-man switch is the session process's pidfd either way. MCP only. |
| Sub-agent sharing the session's connections   | no               | Same connection, same token: the session node.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Any in-process sub-agent's CLI call           | no               | The Bash tool runs in the session process; `SO_PEERCRED` sees the session; the credential vended is the session node's. `PreToolUse` can refuse as advice; it cannot make it a different principal.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Claude Code's own per-server OAuth (DCR/CIMD) | outside the tree | A non-agent client under §1: no `sid`, no ledger row, no node. It joins the broker's root only when the server is reached through the proxy or `headersHelper` → broker (P3). An operator who seeds it as an agent client and points Claude Code at those pre-configured credentials gets a `sid` and ledger rows — but a root of its own.                                                                                                                                                                                                                                                                                                                                                                                                                   |

The consequence is a rule, not a caveat: **a child that needs a hard read-only
gate is spawned as a process under a different uid, or in a sandbox that
denies it ptrace-read of the parent, the parent's tmux socket and every
user-writable directory on the parent's `PATH` and `HOME`** (the executor's
job — e.g. `bwrap --unshare-user` or a `DynamicUser=` unit); a process is
necessary for the gate on both legs and, until P3, sufficient on the CLI leg
only (row 8, P0b's honest limits). What a same-uid child can still do to its
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
  user or any live ancestor node, not only the agent (§6).
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
- One browser login per new session whenever the root names a dangerous
  scope, which every default root does; resume reuses the root, a second
  process does not (§1, §11).
- Three of the shapes followed are individual drafts that may expire without
  successors (Watch list); the `act` object may need a second migration.
- The MCP leg is outside the tree until P3 (Phasing; Harness reality, row 8).
- A public profile is a new unauthenticated surface on the realm, and an
  owner-registered transmitter is a new party whose SETs QAuth stores; both
  are bounded (the profile shows the principal and nothing below it, the
  transmitter reaches one agent's trees and its rows are marked as reports),
  but each is one more thing to enumerate and one more `jwks` to rotate
  (§7, §13).
- Every provenance line outside QAuth is forgeable, by anyone and by the
  agent itself; the record can only make its own store honest about the
  difference (T7). Commit signing, the one thing that would change that, is
  parked (decision 12).
- QAuth grows a CIBA endpoint, a WebAuthn credential provider, a
  notification path and an approvals table (§14). The owner's phone joins
  the approval path: a lost, unlocked phone with a synced passkey is a way
  in, bounded by the delta, the budget and the window — and a human who
  approves carelessly is T8's residual.

### Neutral

- Default off in every dimension: `AGENT_TREE_ENABLED=false` runs none of it
  ([Decision](#decision)), and with it on, no agent client is DPoP-required,
  no `spawn_allowlist` exists and so no root token's `aud` is enriched, no
  lifetime row changes, no transmitter or push endpoint is configured, until
  an operator says so — and no agent, binding or agent-side transmitter
  exists until an owner creates one (§7, §13). No approval request is
  possible until an operator sets `AGENT_APPROVAL_ENABLED` and an owner
  registers a passkey (§14).
- `MAX_DELEGATION_DEPTH` stays 4; draft-mcguinness's "at least depth 4" is
  met and draft-liu's recommended 5 is not adopted. A narrowing spends no
  depth, so lead → teammate → process → tool with a leaf per level fits.
- ADR-007's maintainer decision stands (the invariant paragraph); nothing on
  the wire is proprietary to a standard client; `WalletProvider.verify()` is
  untouched and still throws.

## Decisions parked for the maintainer

Each question carries the default the record was written on; the record
proceeds on that default until the maintainer decides otherwise.

1. **Browser logout and agent trees.** Should a QAuth logout revoke the user's
   agent `sid` trees? RFC 9700 §4.14.2 leaves automatic refresh-token
   revocation on logout a MAY, and says nothing about the access tokens below
   it. Default: trees survive logout and die by explicit revocation or expiry.
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
7. **First seed manifest** — agent types with `max_agent_mode`, `scopes`,
   `spawn_allowlist`, `jwks` and, for a root type, `redirect_uris`. Default:
   `claude-code` (root, `exec`, allowlist naming itself and `reviewer`, one
   `redirect_uris` entry, `http://127.0.0.1:<port>/callback` on the fixed
   port the broker binds, §1), `reviewer` (`readonly`, no `write:*`),
   `executor` (`exec`); one `jwks` key per box, distinct `kid`.
8. **Root-grant cadence.** One root per main-agent process (a login per
   session, per-session attribution) or one root per broker start (one login,
   concurrent sessions share a `sid` and a node)? Default: per process.
   _Note 2026-09-22:_ an unattended runtime — a daemon with no
   `SessionStart` hook, restarted independently of the broker, started
   through the executor path — cannot carry a per-process root, since its
   every restart would cut the `sid` (§6); it needs the per-broker-start
   shape. A per-host setting choosing between the two, rather than one
   answer for every host, is the likely resolution.
9. **Agent handle namespace.** Realm-unique (`majordomo` is one agent per
   realm) or user-scoped (`taha/majordomo`, so two owners may share a
   handle)? The SCIM draft wants `agentUserName` unique across the
   provisioning domain, which is the realm. Default: realm-unique, first
   come; the profile URL is `/agents/{handle}`.
10. **Ownership transfer.** May an owner hand an agent to another user, and
    does the agent's history (ledger rows, bindings, events) move with it?
    Default: transfer allowed by the current owner through the portal,
    history stays attached to the agent, and the old owner's name leaves the
    profile at transfer.
11. **Agent-side transmitter trust.** Does an owner-registered transmitter
    (§7) need the realm admin's approval before its SETs are stored, or is
    the owner's registration enough? Default: the owner's registration is
    enough, because the rows it produces are already marked as reports and
    reach only that agent's trees; an admin may disable a transmitter.
12. **Commit signing.** Leave agent commits unsigned (pointer only), sign
    with the broker's per-node key (verifiable against the ledger, shown
    Unverified by GitHub as `unknown_key`), or sign server-side with a key
    registered to a machine user (shown Verified, the AS on every commit)?
    Default: unsigned; the trigger to reopen is a requirement that
    provenance be evidence rather than a pointer.
13. **`model` on the ledger row?** Keep the reported model only in
    `agent_actions` (§7), or copy the first report onto the ledger's root
    row for the dashboard's convenience? Default: `agent_actions` only; the
    ledger holds what QAuth verified and nothing it did not.
14. **"Don't ask again": a mute or an allow?** The owner's framing
    (2026-09-23): approval fatigue is prevented by "don't ask again for this
    session" and "don't ask for a while", and asking has its own permission
    scope, which cannot be extended. Default: both are mutes — further
    requests from that session, or in that window, are refused without a
    notification — and repeated identical requests are what "approve for a
    while" covers, on the same delta, as an explicit passkey-confirmed
    choice. The alternative, a "don't ask again" that approves the same
    delta for the rest of the session, is "approve for a while" with the
    session as the window, reached in one tap instead of one choice (§14).
15. **Which factors may approve?** A passkey only, or also a TOTP or other
    offline code, or a wallet presentation bound by `transaction_data`?
    Default: a passkey only in `production` and `staging`; a TOTP code also
    accepted in `development`; the wallet later, behind
    `WALLET_FEDERATION_ENABLED`, as a request-bound option (§14).
16. **Where a request reaches the owner.** Web push to the portal, email, an
    owner-registered webhook, or all three — and what happens while the
    owner does not want to be reached? Default: web push, plus an optional
    owner-registered webhook that receives only the request id, the agent's
    handle and the approval URL; no email. A request nobody answers expires
    at `requested_expiry` and counts as denied; quiet hours are the owner's
    channel's business, not QAuth's (§14).

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
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html) · [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) · [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) · [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) · [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) · [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) · [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) · [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417.html) · [RFC 8935](https://www.rfc-editor.org/rfc/rfc8935.html) · [RFC 8936](https://www.rfc-editor.org/rfc/rfc8936.html) · [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493.html) · [RFC 7521](https://www.rfc-editor.org/rfc/rfc7521.html) · [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) · [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html) · [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) · [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) · [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) · [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) · [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OpenID Federation 1.0 §13.6](https://openid.net/specs/openid-federation-1_0.html) · [OIDC Back-Channel Logout 1.0 §2.1](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [draft-mcguinness-oauth-actor-profile-00](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-actor-profile-00) · [draft-liu-oauth-chain-delegation-00](https://datatracker.ietf.org/doc/html/draft-liu-oauth-chain-delegation-00) · [draft-niyikiza-oauth-attenuating-agent-tokens-01](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-01) · [draft-ietf-wimse-aims-00](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-aims-00) · [draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11) · [draft-ietf-oauth-rfc7523bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/) · [draft-oauth-ai-agents-on-behalf-of-user-02](https://datatracker.ietf.org/doc/html/draft-oauth-ai-agents-on-behalf-of-user-02) · [draft-asor-wimse-agent-delegation-chain-01](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-01) · [draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) · [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) · [draft-ietf-wimse-workload-creds](https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/) · [draft-ietf-wimse-wpt](https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/) · [draft-klrc-aiagent-auth](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) · [draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)
- [OAuth WG thread: Delegation Chain Splicing in RFC 8693 Token Exchange](https://mailarchive.ietf.org/arch/msg/oauth/6MHkSfhGfugVmcb2p08ocM7piqQ/)
- [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) · [COAZ-MCP Binding 1.0 (WG draft)](https://openid.github.io/authzen/authzen-coaz-mcp-binding-1_0.html) · [Access Request and Approval Profile 1.0 (WG draft)](https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html) · [Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html) · [CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html) · [OIDC Front-Channel Logout 1.0 §3 (`sid`)](https://openid.net/specs/openid-connect-frontchannel-1_0.html) · [IANA JWT Claims registry](https://www.iana.org/assignments/jwt/jwt.xhtml)
- [MCP Authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) · [PostgreSQL 18 OAuth authentication](https://www.postgresql.org/docs/18/auth-oauth.html) · [GitHub App installation access tokens](https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app) · [octo-sts](https://github.com/octo-sts/app) · [gitcredentials](https://git-scm.com/docs/gitcredentials)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks.md) · [sub-agents](https://code.claude.com/docs/en/sub-agents.md) · [agent teams](https://code.claude.com/docs/en/agent-teams.md) · [MCP](https://code.claude.com/docs/en/mcp.md) · [Agent SDK MCP](https://code.claude.com/docs/en/agent-sdk/mcp.md)
- [draft-wzdk-scim-agent-resource-00](https://datatracker.ietf.org/doc/html/draft-wzdk-scim-agent-resource-00) · [draft-abbey-scim-agent-extension](https://datatracker.ietf.org/doc/draft-abbey-scim-agent-extension/) · [draft-kushwaha-scim-agent-governance](https://datatracker.ietf.org/doc/draft-kushwaha-scim-agent-governance/) · [SCIM WG agentic-draft progress, IETF 125](https://datatracker.ietf.org/meeting/125/materials/slides-125-scim-scim-agentic-draft-progress-00) · [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643.html) · [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644.html)
- [CAEP Interoperability Profile 1.0 (draft 01)](https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html) · [OpenID Foundation on SSF/CAEP and agentic use cases (July 2026)](https://openid.net/authzen-at-identiverse-2026-authorization-in-the-agent-era/)
- [OpenID CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) · [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) · [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) · [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) · [Claude Code Remote Control](https://code.claude.com/docs/en/remote-control)
- [Linux kernel: AI Coding Assistants](https://docs.kernel.org/process/coding-assistants.html) · [GitHub App visibility](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/making-a-github-app-public-or-private) · [GitHub commit signature verification reasons](https://docs.github.com/en/rest/commits/commits) · [GitHub REST: pull requests associated with a commit](https://docs.github.com/en/rest/commits/commits#list-pull-requests-associated-with-a-commit)
