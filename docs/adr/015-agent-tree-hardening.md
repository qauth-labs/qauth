# ADR-015: Authority Tree Hardening — Where a Tree Ends, Who May Act on It, How an Agent Changes Hands

**Status:** Accepted
**Date:** 2026-09-30
**Authors:** QAuth Team

> **Proposed 2026-09-30, accepted 2026-10-11.** Nothing below is implemented. This record builds
> on [ADR-014](./014-agent-authority-tree.md) as amended 2026-09-30 (PR #419)
> and changes none of its rules. Every rule sits behind `AUTHORITY_TREE_ENABLED`;
> the approval rules also sit behind `REMOTE_APPROVAL_ENABLED`. With the
> switches off, nothing changes. Every decision here is this record's
> proposal unless it is marked decided. Decision 9 builds on the maintainer's
> decision 10 in ADR-014.
>
> **Amended 2026-10-09** (before any implementation): the maintainer
> decided a rename on 2026-10-08. "Agent Tree" and "agent authority tree" are
> now "Authority Tree", as in ADR-014. The mechanism is generic
> machine-to-machine and process delegation; AI agents are one client class.
> Two switches are renamed with it: `AGENT_TREE_ENABLED` is now
> `AUTHORITY_TREE_ENABLED`, and `AGENT_APPROVAL_ENABLED` is now
> `REMOTE_APPROVAL_ENABLED`. The agent principal, agent types, agent
> identities and every identifier that names an agent keep their names. The
> file name is kept, so links stay stable. No rule changed.
>
> **Amended 2026-10-09, decisions** (before any implementation): the
> maintainer has answered all thirteen parked questions. Questions 6 to 9
> were answered on 2026-10-06, and question 6 is now decision 11. The rest
> were answered on 2026-10-09. Each is marked decided below, with its date.
> Where an answer changes ADR-014's text, the question names the place.
> On 2026-10-09 the maintainer decided that ADR-014, this record and ADR-016
> will be approved together, so ADR-014 was updated that day to match.
> ADR-014 §1 and §11 also carry the 2026-10-06 answers.
>
> **Amended 2026-10-10** (before any implementation): §1, §3 and §7 follow
> ADR-014's amendment of that date. A family with no `sid` gains none by
> refresh, an owner may upload a binding's upstream key, and a type's
> registered rights bound an approval as its registered scopes do. §9 now
> says what a transfer does to a binding, and question 8 notes that a resume
> rebinds its root only through the consent screen. No maintainer decision
> changed.

## Context

ADR-014 defines the authority tree: a root grant, a ledger, DPoP-bound
nodes, revocation, an agent principal with an owner (§13) and remote
approval (§14). On 2026-09-30 the maintainer decided four of its parked
questions (PR #419). The first draft of that amendment grew ADR-014 to 3308
lines, with fail-closed rules and new questions of its own. The maintainer
never approved them, and the draft was withdrawn.

This record takes each item up again, against ADR-014 as amended and the code
on main. Where it is decision-level and ADR-014 is silent, it is a decision
here. Where it would change a rule ADR-014 states, it is parked, with
ADR-014's rule as the default. Where PR #419 already says it, it is only
referred to: revoke-all and the lock between a mint and the walk are in
[ADR-014 §6](./014-agent-authority-tree.md#6-revocation--by-sid-and-by-jti-cascading-with-a-written-window).
The platform side — an agent's public identity on an external platform, its
installations and resources, the pass-through leg, `handle@issuer` and
authorship — is [ADR-016](./016-agent-platform-bindings.md)'s.

### What exists and what this record adds

Verified 2026-09-30 against the working tree at `2c901d4`.

| Concern                 | Today                                                                                                                                                                                                                  | This record adds                                            |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| End of a refresh family | Revocation by its client, consent withdrawal, reuse detection, a refresh after the user was disabled; client deletion removes the rows by cascade. None touches a tree                                                 | The tree ends with the family (decision 1)                  |
| Refresh audience        | Recomputed from the client's current `audience` column when no `resource` is bound (`apps/auth-server/src/app/routes/oauth/token.ts:1193`, `resolveAudience` at `apps/auth-server/src/app/helpers/client-auth.ts:521`) | Never wider than the code grant issued (decision 2)         |
| Owner routes            | The management guard admits only the system client's token, with its full `aud` and no `act` (`apps/auth-server/src/app/helpers/management-token.ts:34`)                                                               | Every owner route runs it; it also refuses `sid` (dec. 3)   |
| Client assertions       | `aud` may be the issuer or the token endpoint URL; no `typ` check (`apps/auth-server/src/app/helpers/client-assertion.ts:96`)                                                                                          | Issuer as sole `aud`, explicit `typ`, for agent types (d.4) |
| Rate limits             | A global 100 per 3600 s per address; `/oauth/token` 30 per 60 s per address in a production realm                                                                                                                      | Each added route names its own limit (decision 6)           |
| Owner's proof           | `email_verified` lives on the `password` credential; `REQUIRE_VERIFIED_ACCOUNT` defaults to `false`. `users` has no verified flag and no marker for a primary credential (checked 2026-10-06)                          | An agent owner needs a verified account (decision 8)        |
| Realm admin             | No role: `users` has no role column (ADR-012 §4), and no code reads the `roles` and `user_roles` tables                                                                                                                | Realm-local admins, through ADR-019 (question 10)           |

## Decision

Every rule below runs only with `AUTHORITY_TREE_ENABLED` on; rules about approval
also need `REMOTE_APPROVAL_ENABLED`. With a switch off, its paths are
byte-for-byte today's. "This family of records" means ADR-014, this record
and any record built on them.

### 1. The end of a root's grant ends its tree

_Proposal (this record)._

**When the refresh family under a tree's root ends, or the root's client is
deleted, the tree ends with it.**

- A family ends when a write leaves it with no live refresh token; a
  rotation's compare-and-set, which inserts the successor, is the exception.
  The rule keys on that write, not on a list of routes, so a later path is
  covered too.
- Four shipped paths write it: RFC 7009 revocation by its own client
  (`apps/auth-server/src/app/routes/oauth/revoke.ts:140`), consent withdrawal
  (`apps/auth-server/src/app/helpers/consent-management.ts:95`), reuse
  detection (`token.ts:879`; a lost compare-and-set too, since
  GHSA-c2gj-r6hx-292c), and a refresh after the user was disabled
  (`token.ts:1037`).
- The walk runs inside that write's transaction, under ADR-014 §6's lock.
  Denylist writes follow the commit, under §6's 503-and-repair rule.
- Deleting a client (`apps/auth-server/src/app/routes/clients/index.ts:645`)
  writes no revocation: foreign keys delete its refresh tokens and consents
  (`libs/infra/db/src/lib/schema/tokens.ts:169`,
  `libs/infra/db/src/lib/schema/consents.ts:29`). So the route walks every
  live tree and node of that client in the delete's transaction, and a failed
  walk rolls the delete back. A developer-owned DCR client may assert
  `is_agent` (`apps/auth-server/src/app/routes/oauth/register.ts:143-146`).

**At the edge of a tree.** ADR-014 decision 1 spares at sign-out only a
family that carries a `sid`, so sign-out still ends an agent client's family
whose `sid` is NULL (question 11, decided). Sign-out also ends a `sid` family
whose CIMD client has stopped declaring `is_agent` (question 1, decided).
Revoke-all also reaches what would become a tree next:

- every live refresh family of an agent client with no `sid`, which gains
  none by refresh (ADR-014 §1) but whose tokens can still start a tree by
  exchange;
- a code issued before the revoke-all: its redemption is refused
  (`invalid_grant`).

The maintainer asked for "a separate method that revokes all agents"
(ADR-014 decision 1). A family whose tokens can still start a tree by
exchange is an agent's.

**Why.** Without the walk, a tree whose grant has ended runs until the root's
last access token expires, and the ledger shows it live. A deleted client's
tokens still verify, since `requireJwt` never looks the client up. RFC 7009
§2.1 lets revocation reach "related tokens and the underlying authorization
grant"; this is that cascade, run from the grant's side.

### 2. A tree only shrinks after consent

_Proposal (this record)._

**A refresh never widens a tree, a lowered cap cuts it, and a refused
renewal ends a node instead of narrowing it.**

- **Refresh.** Today an operator who widens a client's `audience` column
  widens every live root at its next refresh; from P1b the `spawn_allowlist`
  enrichment of ADR-014 §11 would too. So the code grant stores the `aud` it
  issued on the `refresh_tokens` row. A refresh issues at most that set,
  intersected with what the columns give now. RFC 8707 §2.2 allows "the
  originally granted ... or a subset thereof". A widening waits for the next
  consent.
- **Cap.** Only the seed tool writes `max_agent_mode` and `is_agent` on a
  seeded type (`libs/infra/db/src/scripts/seed-oauth-clients.ts:311-313`). A
  run that lowers the cap, or clears `is_agent`, revokes by the §6 walk every
  live node of that type above the new cap. The per-mint check stays
  (`token.ts:1087`, `:1509`); alone, it leaves an over-cap node working for
  up to one lifetime.
- **Renewal.** A renewal is refused when QAuth answers with an OAuth error,
  except `use_dpop_nonce` (RFC 9449 §8). A 429 or a 5xx is not a refusal
  (decision 6); the node runs to `exp` while the broker retries.
- A refused re-spawn ends the node: the broker revokes its subtree and stops
  signing for its key. A refused root refresh ends the tree: the broker
  revokes the `sid`.
- The broker never retries narrower, though the refresh grant allows it
  (`token.ts:1083`). A refused renewal is never a §14 request. The next login
  roots a new tree under the current ceiling, through a consent.

**Why.** ADR-014's invariant bounds every token by the human's consent. An
operator's change after that consent is not consent, and a narrower tree is a
shape no consent screen showed. GHSA-6fcx-34r3-24v4 stopped an agent-mode
downgrade at the next mint; the walk stops it at once.

### 3. Owner routes run the management guard

_Proposal (this record)._

**Every owner-facing route in this family runs the management guard, which
refuses every tree token: root, node or leaf.**

- The guard is `createRequireManagementJwt` (`management-token.ts:65`),
  never `requireJwt` alone, which admits any live token with the owner as
  `sub`. Since GHSA-c863-7xrr-ww9v the guard admits only the system client's
  token, with that client's full audience and no `act`
  (`management-token.ts:34`). With the switch on, it also refuses `sid`.
- Each route touches only rows whose `user_id` or `owner_user_id` is the
  token's `sub`. Accepting a transfer is the one exception (decision 9).
- The routes: the session reads and events stream; the owner leg of the two
  identifier revocation routes; revoke-all and revoke-by-agent; writes to
  agents, bindings (an upstream identity's key among them, ADR-014 §13) and
  transmitters; transfer offers; ending a window,
  removing a block, registering a channel, or a passkey under ADR-017
  Decision 8's binding rule; the SCIM read; and the
  owner settings ADR-016 adds. No tree token ever authenticates the approval
  page.
- On the identifier routes the scheme picks the leg: `Bearer` is the owner
  leg, under the guard. `DPoP` is the node leg, with its client
  authentication in the body: an assertion under decision 4, never a
  secret (question 2). A request mixing the two is refused.

**Ancestors' `jkt` and `scope` reach the owner through the portal route.**
ADR-014 §2 returns them only to the owner's portal and to a node of the same
tree. The owner reads them from `GET /api/agent-sessions/{sid}`; introspection
returns them only to a node. Introspection authenticates a client by secret
(`apps/auth-server/src/app/routes/oauth/introspect.ts:101-102`) and names no
user. The portal calls `/api/*` with the owner's management token and never
introspects (`apps/developer-portal/src/server/auth-server-client.ts:446-448`).
This narrows no caller §2 names.

**Why.** A tree token is the agent's, and T6 says a model's restraint is no
gate. An agent that could list, revoke or re-register its owner's trees could
undo the owner's control from inside its own ceiling.

### 4. Agent types authenticate by a strict client assertion

_Proposal (this record)._

**An agent type's client assertion names QAuth's issuer as its sole `aud`
and carries `typ: client-authentication+jwt`.**

- An agent type is an agent client with an operator-set `max_agent_mode`,
  which only the seed manifest writes, or, once the realm file and the admin
  API carry it, a security operation (ADR-019 Decision 7). Any other
  assertion from one is
  `invalid_client`, audited.
- The rule holds at `/oauth/token`, at the node leg of the identifier API
  (§6) and at the CIBA backchannel endpoint (§14), where it binds every
  client. Other clients keep today's rule at `/oauth/token`
  (`client-assertion.ts:96`;
  [ADR-011 §7](./011-enterprise-managed-authorization.md#7-private_key_jwt-384--additive-no-flag)).
- An agent type never authenticates by client secret (question 2, decided
  2026-10-09).

**Why.** draft-ietf-oauth-rfc7523bis-11 is in the RFC Editor queue (received
2026-04-30). Its §4, item (b): for client authentication, `aud` "MUST use
the issuer identifier ... as its sole value"; the token endpoint URL "MUST
NOT be used". Two departures are deliberate:

- The same section calls rejecting untyped assertions NOT RECOMMENDED. The
  broker is an agent type's only presenter and always types, and the type
  separates the assertion from the other JWTs the box signs (ADR-014 §4).
- CIBA Core 1.0 §7.1 says the OP MUST accept its issuer, token endpoint URL
  or backchannel endpoint URL. QAuth's CIBA endpoint follows the newer rule.

### 5. A bound subject is exchanged only under its own key until GATE 3d

_Proposal (this record)._

**From P1a until P1b's GATE 3d is live, an exchange whose subject token
carries `cnf` is refused unless its DPoP proof is under that `cnf.jkt`.**

- ADR-014 §4 already says a `cnf` subject cannot be exchanged to a new key
  without a spawn assertion; GATE 3d enforces it in P1b. P1a mints `cnf`
  first, so between the phases a captured bound token could be exchanged
  under any key, or none: T1's splice.
- From P1a such an exchange is `invalid_request` (RFC 8693 §2.2.2). A
  same-key narrow still works.
- The cost is no spawn to a new key until P1b. A deployment ships 1a and 1b
  together, or runs P1a with narrows only.

### 6. Every added route names its own rate limit; a 429 is never a grant

_Proposal (this record)._

**Each route this family adds names its own limit, in the phase that lands
it. A 429 mints, grants and revokes nothing.**

- The limit is per address before authentication, plus a per-client,
  per-`sid` or per-transmitter limit where the handler knows its caller. No
  added route falls back to the global 100 per 3600 s per address
  (`libs/server/config/src/lib/schemas/rate-limit.ts:20-25`).
- `/oauth/token` keeps its 30 per 60 s per address in a production realm
  (`token.ts:113-124`), shared by every renewal, narrow and CIBA poll from one
  address. No existing limit is raised for agents.
- A 429 is not a refusal (decision 2), an approval or a revocation. The
  broker honours `Retry-After`; a revocation answered 429 is retried, within
  ADR-014's one-lifetime window.
- Revoke-all is exempt: no per-address limit, and no 429 to an owner's
  call. An emergency stop must not wait (ADR-014 decision 1).
- The CIBA acknowledgement always carries `interval`. Without it the client
  polls every 5 s (CIBA Core 1.0 §7.3), and ADR-014's three pending requests
  would poll 36 times a minute, above the token limit. A faster poll gets
  `slow_down` (§11).
- The limiter fails closed on a store outage today (`skipOnError` false,
  `apps/auth-server/src/app/helpers/pending-authorization.ts:62`), and added
  routes keep that. Per-address limits see the real caller only when
  `TRUST_PROXY` names the proxy (GHSA-4pqf-fmj4-wjgx).

**Why.** A broker that read a 429 as "revoked" would tear down live work; one
that read it as "allowed" would act without a token.

### 7. What an approval can lift

_Proposal (this record)._

**An approval never lifts the type's mode cap, the node's audience or the
bearer-leaf election.**

- ADR-014 §14 already keeps `agent:request` and the budget out of reach.
- The backchannel endpoint refuses, before filing or notifying anyone, a
  delta with an `agent:*` mode above the node type's `max_agent_mode`
  (`invalid_scope`), a resource outside the requesting node token's `aud`
  (`invalid_request`), or a resource listed in `AGENT_BEARER_LEAF_RESOURCES`
  (`invalid_request`). These are CIBA Core 1.0 §13 codes.
- An elevation is always key-bound (§14, step 5), and RFC 9449 §7.2 makes a
  listed resource reject a bound token sent as Bearer.
- The checks run again at every elevation mint, so a lowered cap ends an open
  window at its next renewal.
- §14's step 1 lists refusals by GATE 4a, §5, the STS and mcp-guard. A
  GATE 4d refusal is final (question 4). Some refusals lead to requests this
  rule refuses: a mode above the cap, which 4a refuses first, and a listed
  mcp-guard resource. Beyond `agent:request` and a type's registered scopes
  and rights, ADR-014 does not say what an approval may carry, so this is a
  new fail-closed rule. A window renews by a matched CIBA request (question
  5). What the STS lets an approval open is ADR-016's.

**Why.** The operator's mode cap is a ceiling the owner's consent sits
under, and a passkey tap is not an operator change. An elevation outside the
node's audience would reach a resource the root consent never showed.

### 8. An agent owner is a verified account

_Decided 2026-10-06 (maintainer), with question 7._

**Unless the user's account is verified, QAuth refuses, audited:**

- creating an agent, or accepting one by transfer;
- rooting a tree in an agent, at ADR-014 §13's owner check;
- binding an agent to a platform;
- registering an agent-side transmitter, an approval channel or a passkey.

**An account is verified when its primary identity is proved.** The primary
identity is the credential that created the account. An explicit marker names
it, set at account creation and not movable in 1.0 (question 13). It can be
of any type. An email address is one attribute an account may have. No
account needs one, and no address counts on its own. Each type has its own
proof, as ADR-002 and ADR-003 place it:

| Primary identity (`provider_type`)    | Proved when                                                                                                       | On main, 2026-10-06                                                   |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Password with an address (`password`) | The mailbox code for that address was entered, and `email_verified` is `true` on the credential                   | Yes. `/auth/verify` sets it                                           |
| Passkey (`webauthn`)                  | The registration ceremony finished, and QAuth checked the user-verification flag in the signed authenticator data | No. ADR-017 specifies the provider                                    |
| Wallet presentation (`wallet`)        | QAuth's own verifier accepted the presentation                                                                    | Behind `WALLET_FEDERATION_ENABLED`, on its own seam                   |
| Upstream OIDC (`oidc_*`)              | An upstream issuer says so; QAuth proves nothing itself                                                           | Not built. It does not count in the first slice (decided, question 7) |

The rule asks that the identity is proved, not how strongly. Assurance
(`acr`) is another question: the password credential stays `low` (ADR-003),
and this rule does not change that. Only the primary identity counts. If a
later credential could make an account verified, someone who registers an
address they do not control could add a key of their own and pass the check
(question 13).

The rule holds whatever `REQUIRE_VERIFIED_ACCOUNT` says. That flag defaults to
`false` (`libs/server/config/src/lib/schemas/auth.ts:75`) and governs sign-in
for password accounts, not the ownership of an agent. How a later wallet
presentation finds the same account is ADR-009's question, and this record
does not change it.

**Why.** The owner is the name on a public profile and the party answerable
for a transmitter's events (ADR-014 §7, §13, T7). An identity nobody proved is
a claim. A password account can be registered by anyone for an address they do
not control, and an offer to that account would reach the squatter. A passkey
or wallet account has no such gap: creating it already proves control of the
key or of the presentation.

### 9. A transfer is an offer the named user accepts

_Proposal (this record), on top of ADR-014 decision 10, which the maintainer
decided on 2026-09-30._

The maintainer's decision: activity before the transfer stays under the
previous owner, and that history is neither rewritten nor removed; from the
transfer, the agent continues under the new owner's name. PR #419 adds that
the transfer revokes the agent's live trees by the §6 walk. The maintainer
did not decide how the moment of transfer is fixed. The rules below are this
record's, not the maintainer's.

**A transfer is an offer until the named user accepts it. The acceptance is
the moment of transfer.**

- The current owner offers the agent, from the portal, to one named user. An
  agent has at most one open offer, and nothing changes until acceptance.
- The owner may withdraw the offer. An unanswered offer lapses; seven days is
  proposed. A withdrawn or lapsed offer can never be accepted. The offer
  route answers the same whatever the named user's state.
- Only the named user accepts, under the guard, as a verified account
  (decisions 3, 8). The acceptance re-checks that the offerer still owns the
  agent.
- The acceptance's own transaction sets `owner_user_id` and cuts every live
  tree of the agent by the §6 walk. What those trees already hold runs out
  within §6's window, as pre-transfer activity under the previous owner.
- The same transaction disables, and keeps, the previous owner's agent-side
  transmitters: a transmitter's owner answers for what it sends (ADR-014 §7).
  Standing blocks stay, since a block only denies.
- Every step is audited. A binding whose `adapter_ref` is not assigned to
  the new owner vends nothing until one assigned to them replaces it
  (ADR-014 §13).

**Why.** The owner is the name on the profile and answers for the agent (T7),
so nobody should become one without accepting. One transaction makes the
moment exact: no tree of the previous owner mints after it, and none of the
new owner's roots before it. There is no freeze (question 9, decided
2026-10-06).

### 10. Approve from a separate device

_Proposal (this record). It began as a Claude reply in the 2026-09-30 review;
the maintainer decided only that a passkey is the one factor (ADR-014
decision 15)._

**The approval page recommends answering from a separate device, and says
why. The same-machine case is a stated residual under T8.**

- The page recommends a phone, directly or through WebAuthn's `hybrid`
  transport (WebAuthn Level 3 §5.8.4). It explains that a platform
  authenticator on the agent's machine is often unlocked by a PIN or a
  password, which a computer-use agent there can type.
- WebAuthn cannot enforce it. Hints "are not requirements, and do not bind
  the user-agent" (§5.8.8), and the reported `authenticatorAttachment` (§5.1)
  is not in the signed client data (§5.8.1).
- RFC 10027 (BCP 247) says cross-device protocols SHOULD NOT be used for
  same-device scenarios (§5), and CIBA not at all (§6.2.2.5). Its §5 lets a
  server block such use when detected; QAuth cannot detect it. A same-device
  approval is a stated deviation.

**Why.** The maintainer rejected TOTP because an agent can fill in a form. A
PIN typed into an operating-system prompt on the agent's machine is the same
weakness. The recommendation is the most the protocol allows.

### 11. No consent skip for an agent root

_Decided 2026-10-06 (maintainer), question 6._

**Every new agent root shows the consent screen.**

- The fast path (`canSkipConsent`,
  `apps/auth-server/src/app/helpers/consent.ts:77`) never applies to an
  agent root, even when a stored consent covers the request.
- `prompt=none` for an agent root answers `consent_required`. Today it asks
  the same `canSkipConsent` question
  (`apps/auth-server/src/app/routes/oauth/authorize.ts:509-515`).
- ADR-014 §11 already says so.

**Why.** The screen shows each tree's agent, allowlist, purpose and
persistence. A stored consent does not show them again.

## Threats

Only threats this record adds or changes. T-numbers are ADR-014's.

| Threat                                                                     | Control                                                   | Residual                                                                 |
| -------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------ |
| A tree outlives its root's grant: consent withdrawn, reuse, client deleted | Decision 1: the walk runs with the write that ends it     | A resource that verifies offline accepts a token to `exp`, §6's window   |
| A tree grows after consent through an operator change                      | Decision 2: stored `aud`, cap walk, no narrower retry     | A cap changed outside the seed tool waits for the next mint              |
| A tree token acts as its owner                                             | Decision 3: the guard on every owner route; `sid` refused | A stolen portal session is the owner, as today                           |
| An agent type's assertion accepted at an audience it was not minted for    | Decision 4: issuer as sole `aud`, explicit `typ`          | The type's assertion key on the box stays T2's residual, one key per box |
| A captured bound token spliced between P1a and P1b (T1)                    | Decision 5                                                | No spawn to a new key until P1b                                          |
| A 429 read as a grant, or a revocation dropped on a 429                    | Decision 6                                                | Every broker behind one address shares the token limit                   |
| An approval lifts an operator's ceiling (T8)                               | Decision 7                                                | None new: a GATE 4d refusal is final (question 4)                        |
| An agent owned through an identity nobody proved                           | Decision 8                                                | A control lost after the proof (a mailbox, a device) goes unnoticed      |
| An agent handed to a person who never agreed                               | Decision 9                                                | The previous owner's cut tokens run to `exp` after the acceptance        |
| A computer-use agent approves on its own machine with an OS PIN (T8)       | Decision 10: the page recommends a separate device        | Not closed: WebAuthn cannot enforce it                                   |

## Alternatives considered

| Alternative                                                          | Why not                                                                                                 |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Grow ADR-014 again with these rules, as the withdrawn draft did      | 3308 lines of spec-level text; the decisions get lost in it                                             |
| End a tree on a named list of paths                                  | A path added later escapes; keying on "no live refresh token left" covers it                            |
| Leave a lowered cap to the per-mint check                            | The over-cap node keeps working for up to one lifetime after the operator acted                         |
| Let the broker narrow a refused renewal                              | The tree then runs in a shape no consent screen showed                                                  |
| Serve the owner ancestors' `jkt` and `scope` through introspection   | Introspection authenticates a client and names no user                                                  |
| Accept untyped agent-type assertions, as rfc7523bis recommends       | The broker is the only presenter and always types; the type separates the three JWT kinds the box signs |
| A transfer that takes effect when the owner clicks                   | It names a person as an agent's owner without their consent                                             |
| Enforce the separate device by WebAuthn hints or reported attachment | Hints bind nothing, and the reported attachment is not signed                                           |

## Phasing

Each rule lands in the ADR-014 phase that builds what it needs, with the one
test that proves it.

- **1 — P2:** withdrawing consent, replaying a refresh token and deleting the
  client each leave the whole tree inactive at introspection.
- **2 — P0a** (stored `aud`): an audience added after consent is absent from
  the next refresh. **P2** (cap walk): a lowered cap makes over-cap nodes
  inactive before their next renewal. **P1b** (renewal): a re-spawn answered
  `invalid_scope` revokes its subtree.
- **3 — P0a**, then each phase that adds an owner route: a root, a node and a
  leaf token each get 401 on `GET /api/agent-sessions/{sid}`.
- **4 — P0a** at `/oauth/token`, P2 at the node leg, P5 at CIBA: an agent
  type's assertion naming the token endpoint URL, a second audience or no
  `typ` is `invalid_client`.
- **5 — P1a:** a `cnf` subject exchanged without a proof, or under another
  key, fails `invalid_request`.
- **6 — every phase:** each added route but revoke-all has its own limit,
  and a renewal answered 429 mints nothing and ends no node.
- **7 — P5:** a delta above the mode cap, outside the node's `aud` or naming
  a bearer-leaf resource is refused and notifies no one.
- **8 — P0c**, then P3 and P5: whatever `REQUIRE_VERIFIED_ACCOUNT` says, an
  account whose primary identity is not proved cannot create an agent. One
  case per row of decision 8's table that exists, and one for an account with
  no email address.
- **9 — P2:** an unaccepted offer changes nothing, and an acceptance cuts
  every live tree in its own transaction.
- **10 — P5:** the approval page carries the separate-device notice.
- **11 — P2:** a stored consent does not skip the screen for an agent root,
  and `prompt=none` answers `consent_required`.

## Consequences

### Positive

- A tree follows its grant, and the ledger stops showing dead trees as live.
- Nothing an operator does after consent widens a live tree, and no tree
  token acts as its owner on any route this family adds.
- The kill switch reaches agent families with no `sid`, whose tokens can
  still start a tree by exchange, and a neighbour cannot rate-limit it away.
- Every agent owner has a proved primary identity and agreed to the role.

### Negative

- Four shipped paths, the client delete route and the seed tool each gain a
  ledger walk.
- Between P1a and P1b a deployment can narrow but not spawn to a new key.
- An account whose primary identity is an upstream OIDC login cannot own an
  agent in the first slice, and a transfer takes two people and two steps.
- The separate device is advice; an owner can still approve on the agent's
  own machine.

### Neutral

- With the switches off, nothing here runs. Every other client keeps today's
  client-assertion rule, and no existing rate limit is raised.
- ADR-014 was updated on 2026-10-09 to match questions 1 to 5 and 12. Its
  §1 and §11 also carry the 2026-10-06 answers. Thirteen questions were
  parked below, and the maintainer has decided all of them.

## Decisions parked for the maintainer

Each question carries the default this record proceeds on until the
maintainer decides. As of 2026-10-09 the maintainer has decided every
question below.

1. **Sign-out and a `sid` family whose client is no longer an agent.** A
   CIMD client's `is_agent` follows its document at every re-resolution
   (`apps/auth-server/src/app/helpers/client-resolution.ts:134`). Options:
   spare every `sid` family; end such a family, and so its tree.
   **Default:** spare it, as ADR-014 decision 1 said; the option would change
   that decision's text. Why ask: the maintainer's words spare agents, and
   this client is no longer one. _Decided 2026-10-09 (maintainer): end it._
   Sign-out ends a `sid` family whose CIMD client has stopped declaring
   `is_agent`, and so its tree. ADR-014 decision 1 was updated to match on
   2026-10-09.
2. **Client assertion only for agent types.** Options: an assertion or a
   secret, as ADR-014 §4(e), §9 and T2 allowed; an assertion only. The code
   already refuses a secret from a `private_key_jwt` client
   (`client-auth.ts:183`), so the option is a registration rule.
   **Default:** either; the option would change those three places. Why
   ask: a secret is shared and on disk; an assertion key can be one per box.
   _Decided 2026-10-09 (maintainer): an assertion only._ Agent types
   authenticate by `private_key_jwt`, never by a client secret. ADR-014
   §4(e), §9 and T2 were updated to match on 2026-10-09.
3. **An ID-JAG minted by an agent type.** Its targets are the client's
   `audience` column (`token.ts:1682`), which also sets a root's `aud`
   without `resource`; it carries no `cnf` or `sid`. Options: allow; refuse
   at GATE 2 for an agent type. **Default:** allow, as ADR-014's
   [Explicitly out of scope](./014-agent-authority-tree.md#explicitly-out-of-scope)
   said: a `kind: id-jag` row, and the tree ends at the domain boundary. The
   option would change that paragraph. Why ask: a listed target sits in every
   root token, and the assertion leaves the key binding and the walk behind.
   _Decided 2026-10-09 (maintainer): refuse._ In 1.0 an agent type cannot
   mint an ID-JAG; GATE 2 refuses the request. That paragraph was updated to
   match on 2026-10-09.
4. **May an approval lift a type's registered scopes?** ADR-014 §14 step 1
   listed a GATE 4d refusal among those that may lead to a request. Options:
   keep that; make a 4d refusal final. **Default:** step 1 as written; the
   option would change it. Why ask: the registration is the operator's
   ceiling, and the invariant bounds every derived token by it. _Decided
   2026-10-09 (maintainer): a 4d refusal is final._ No approval lifts a
   type's registered scopes. The owner's route to more is ADR-014 decision
   17: raising the agent's root ceiling with a passkey. Step 1 was updated
   to match on 2026-10-09.
5. **How an approval window renews.** §14 step 6 renewed the elevation by a
   token exchange, yet the invariant paragraph says "no exchange derives" an
   elevation, and GATE 4a would refuse the delta. Options: step 6, with the
   renewal a named exception to 4a; a new CIBA request that QAuth matches to
   the open window and resolves with no notification or passkey.
   **Default:** step 6 as written; the option would change it. Why ask:
   every elevation would then come from CIBA. _Decided 2026-10-09
   (maintainer): the CIBA option._ The node renews an open window's
   elevation leaf by a new CIBA request. QAuth matches it to the open window
   and resolves it silently, with no notification or passkey. GATE 4a has no
   exception. The match may reuse the canonical-request hash of ADR-019.
   Step 6 was updated to match on 2026-10-09.
   A matched renewal does not count against `REMOTE_APPROVAL_BUDGET`, and
   QAuth accepts one only in the last 60 seconds of the live leaf (decided
   2026-10-09).
6. **Skipping the consent screen for an agent root.** ADR-014 §11 keeps the
   fast path (`canSkipConsent`,
   `apps/auth-server/src/app/helpers/consent.ts:77`), which `prompt=none`
   also consults since GHSA-46p8-vmjm-2jpq. Options: keep it; no skip for an
   agent client; skip only when a stored consent records the same agent,
   allowlist and purpose. _Decided 2026-10-06 (maintainer): no skip for an
   agent client._ The consent screen always shows when an agent root starts.
   It is now decision 11, and ADR-014 §11 says so (2026-10-09). The default
   was to keep the fast path. Why ask: the screen shows each tree's agent,
   allowlist, purpose and persistence. Decided with 8.
7. **Which proofs count for a verified account.** Options: only a proof
   QAuth performs itself, for the types in decision 8's table; also an
   identity an external issuer asserts, as an upstream OIDC provider would.
   **Default:** QAuth's own only, in the first slice. _Decided 2026-10-06
   (maintainer): the default stands, with the maintainer's rule that an
   account is verified when its primary identity is proved securely, of
   whatever type;
   an email address is an attribute, never the default proof._ Why: an
   assertion shows what the issuer says, not that QAuth saw control, and an
   upstream provider is not built.
8. **When a root ends.** ADR-014 §1 lets a resume (same `session_id`; for
   example, Claude Code's `--resume` and `--continue`) reuse its root while
   the refresh token lives. §6's
   dead-man switch revokes the root, its `sid` and its refresh family when
   the process exits, whenever the walk reaches QAuth. So a resume reuses a
   root only when that walk failed. Options: keep both, read together;
   stricter — never reuse an exited root, end a root on a new `session_id`,
   and from P1a refresh it only under its own DPoP key; looser — a root
   outlives its process. **Default:** keep the merged rules; either option
   changes §1 or §6. _Decided 2026-10-06 (maintainer): keep the merged
   rules._ Why ask: the stricter option closes T2's residual of a
   root refreshed from another host, at a new root on every session reset
   (for example, Claude Code's `/clear`). ADR-014 decision 8, the root-grant
   cadence, was decided there on 2026-10-09: a per-host setting. As input,
   a daemon host has no session start: there the broker's process is the
   root, so a runtime restart keeps it, which asks for a per-host cadence.
   _Amended 2026-10-10:_ a resumed process binds to the reused root only
   after the person approves that root's consent screen again (ADR-014 §1);
   the root, its `sid` and its refresh family are still reused. The decision
   is unchanged.
9. **Freezing an agent during a transfer.** Options: no freeze; freeze the
   agent after the acceptance until its cut trees' last token expires,
   including the vended credential's lifetime after their last vend (an hour
   on one git host, as an example). **Default:** no freeze;
   the moment is the acceptance. _Decided 2026-10-06 (maintainer): no
   freeze._ Why ask: a freeze keeps the two owners'
   activity apart, at up to that lifetime in which neither can use the agent.
10. **Realm-admin powers.** ADR-014 gives a realm admin revoke-by-agent (§13,
    P2), the view the public profile withholds (§13), and disabling a
    transmitter (decision 11). QAuth has no such role: `users` has no role
    column
    ([ADR-012 §4](./012-dynamic-client-ownership.md#4-the-developer-scoped-predicate-is-never-widened)),
    and no code reads the `roles` and `user_roles` tables
    (`libs/infra/db/src/lib/schema/roles.ts:18`, `:45`). Options: these
    powers for a future role; the owner's alone for good. **Default:**
    ADR-014's text stands, but no route checks for an admin until a role
    exists, so each power is the owner's alone. Why: a power with no holder
    is a check nobody can pass. _Decided 2026-10-09 (maintainer):_ the
    powers go to realm-local admins, through the permission catalog of
    ADR-019. Revoke-by-agent and disabling a
    transmitter need `admin:security` and a passkey approval per operation.
    The view the public profile withholds needs `admin:read`.
11. **Sign-out and an agent client's family with no `sid` yet.** Options:
    end it, as ADR-014 decision 1's text does; spare it, as "agents survive
    the browser logout" reads. **Default:** end it; the option would change
    that text. Why ask: decision 1 here treats that family as an agent's.
    _Decided 2026-10-09 (maintainer): end it, the default._ Sign-out ends an
    agent client's refresh family that has no `sid`, as ADR-014 decision 1's
    text already says.
12. **Revoke-all and a sid-less subject issued before it.** Options: keep
    ADR-014 §1, where the exchange starts a new tree; refuse the exchange.
    **Default:** §1 as written; the option would change it. Why ask:
    revoke-all cannot reach such a token, which has no ledger row.
    _Decided 2026-10-09 (maintainer): refuse._ A sid-less subject token whose
    `iat` is earlier than the user's last revoke-all is refused. That time is
    a per-user timestamp in Postgres, cached in Redis. ADR-014 §1 was
    updated to match on 2026-10-09.
13. **Which credential is the primary identity.** Decision 8 took the
    credential that created the account, the user's oldest
    `user_credentials` row, and added no column. Options: that; an explicit
    marker the user may move to another proved credential; any proved
    credential makes the account verified. **Default:** the oldest row, no
    marker. Why ask: an explicit marker needs a migration and a rule for
    moving it. The last option lets someone who registers an address they
    do not control add a key of their own and pass the check. _Decided
    2026-10-09 (maintainer): an explicit marker._ It is set at account
    creation and cannot move in 1.0. Decision 8 says so.

## Related

- [ADR-014](./014-agent-authority-tree.md) as amended 2026-09-30 (PR #419);
  [ADR-016](./016-agent-platform-bindings.md), the platform side;
  [ADR-012](./012-dynamic-client-ownership.md), developer-owned clients and
  the missing operator role; [ADR-011](./011-enterprise-managed-authorization.md),
  ID-JAG and `private_key_jwt`; [ADR-002](./002-identifier-abstraction.md),
  email as a credential.
- Published advisories: GHSA-c863-7xrr-ww9v, GHSA-c2gj-r6hx-292c,
  GHSA-6fcx-34r3-24v4, GHSA-46p8-vmjm-2jpq, GHSA-4pqf-fmj4-wjgx.
- [draft-ietf-oauth-rfc7523bis-11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11)
  · [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html)
  · [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)
  · [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)
  · [RFC 10027](https://www.rfc-editor.org/rfc/rfc10027.html)
  · [CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
  · [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
