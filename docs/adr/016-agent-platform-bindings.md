# ADR-016: Agent Platform Bindings — Public Identities, Approval-Only Resources and Pass-Through Legs

**Status:** Proposed
**Date:** 2026-09-30
**Authors:** QAuth Team

> **Proposed 2026-09-30.** Nothing below is implemented. This record builds
> on [ADR-014](./014-agent-authority-tree.md) as amended 2026-09-30 (PR #419).
> It records what the maintainer decided that day about how an agent's identity
> on an external platform is made, limited and approved. Every rule sits behind
> `AUTHORITY_TREE_ENABLED`; the approval path also needs `REMOTE_APPROVAL_ENABLED`.
> With the switches off, nothing changes.
>
> **The rules are platform-agnostic.** A git host is the worked example,
> because ADR-014 §9 and §13 use one. No rule depends on it. GitHub and
> Bitbucket Cloud appear only as labelled examples, and in the links of
> Related.
>
> **Amended 2026-10-09** (before any implementation): the maintainer
> decided a rename on 2026-10-08. ADR-014's "Agent Authority Tree" is now
> "Authority Tree". The mechanism is generic machine-to-machine and process
> delegation; AI agents are one client class. Two switches are renamed with
> it: `AGENT_TREE_ENABLED` is now `AUTHORITY_TREE_ENABLED`, and
> `AGENT_APPROVAL_ENABLED` is now `REMOTE_APPROVAL_ENABLED`. This record's
> title names agent identities, not the tree, so it is kept. So is every
> identifier that names an agent. File names are kept, so links stay stable.
> No rule changed.
>
> **Amended 2026-10-09, decisions** (before any implementation): the
> maintainer answered parked questions 2 to 5, and ADR-019 (proposed in a
> separate PR) closes question 1. Each is marked decided below. The account
> allowlist is a per-binding list the owner edits (§2). The pass-through
> token rests QAuth-side under a per-realm key, the leg has an end date, and
> it is experimental in 1.0 (§4). The maintainer also chose that an
> approval-only resource may be opened for a window, not only once (§3).
> Unsigned commits are confirmed with ADR-014 decision 12 (§6). The
> maintainer approved ADR-014, ADR-015 and this record together on
> 2026-10-09, and ADR-014 §9 was updated that day to match question 5. The
> maintainer also renamed the pass-through leg's switch that day:
> `AGENT_OWNER_TOKEN_LEG_ENABLED` is now `PASS_THROUGH_LEG_ENABLED` (§4). The
> leg stays experimental in 1.0.

## Context

ADR-014 gives an agent principal one binding per platform
([§13](./014-agent-authority-tree.md#13-agent-identity--a-principal-with-an-owner-held-by-qauth-and-asserted-nowhere-else)).
On a git host the binding is the STS App of
[§9](./014-agent-authority-tree.md#9-cli--qauth-broker-and-a-qauth-side-sts-the-credential-is-the-gate).
The STS mints installation tokens with the App's key, narrowed to the node's
`locations` and `actions`. Six questions around that were open, or answered
on a wrong assumption; the table below names each.

The maintainer decided five of the six on 2026-09-30. The sixth, handle scope,
the maintainer raised; this record proposes its answer (§5).

A rule marked "Decided" with a date and "(maintainer)" rests on the
maintainer's decision; the maintainer's words are quoted in English.
Everything else is this record's proposal. Here §1 to §6 are
this record's decisions. §7 to §14, T-numbers and "decision N" are
ADR-014's, and its first six sections are written "ADR-014 §N".
[ADR-015](./015-agent-tree-hardening.md) holds the tree's own hardening;
this record holds the platform side.

### What exists and what this record adds

Verified 2026-09-30 against ADR-014 as amended and the working tree.

| Concern           | ADR-014 as amended, or the code today                                                                                    | This record adds                                                                                   |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| Platform identity | One STS App per agent principal (§13); decision 4's note makes its slug the agent's public name on the platform          | A public identity on the owner's personal account, free to carry another name (§1)                 |
| Installations     | Installation ids in QAuth configuration (decision 4)                                                                     | An allowlist of accounts; foreign installations removed by the STS (§2)                            |
| Resource reach    | The STS narrows to `locations` and `actions`, or to an operator policy until ADR-014 §5 lands (§9)                       | An owner setting, "approval-only", opened by one §14 approval at a time (§3)                       |
| Pass-through leg  | Nothing                                                                                                                  | A temporary vendor kind that hands out the owner's own token (§4)                                  |
| Handle            | Realm-unique, first come (decision 9); one `JWT_ISSUER` per deployment (`libs/server/config/src/lib/schemas/jwt.ts:124`) | `handle@issuer-host` outside the issuer; the profile URL as the anchor (§5)                        |
| Authorship        | Unsigned (decision 12, decided 2026-10-09)                                                                               | The binding's identity is the author; unsigned, as the maintainer decided again on 2026-10-09 (§6) |

## Decision

Every rule below runs only with `AUTHORITY_TREE_ENABLED` on (ADR-014,
[Decision](./014-agent-authority-tree.md#decision)). The approval path
of §3 also needs `REMOTE_APPROVAL_ENABLED`. The pass-through leg of §4 has its
own operator switch, `PASS_THROUGH_LEG_ENABLED`, default `false`. It does
nothing unless `AUTHORITY_TREE_ENABLED` is on. With the switches off, the STS
and the broker behave as ADR-014 says.

### 1. A public platform identity per agent, on the owner's own account

**The agent's identity on a platform is public and free to carry a name other
than the agent's handle.** Decided 2026-09-30 (maintainer).

- One platform identity per agent principal and platform, as §13 already
  says. On this record's reading, the owner's personal account on that
  platform owns it. §13's page "shows the owner account as the developer".
- It is public where the platform otherwise confines it. Example: a private
  GitHub App owned by a personal account can only be installed on that
  account (GitHub docs, checked 2026-09-30). The agent's resources can span
  the owner's account and an organisation's.
- Its name need not equal the handle. Every platform keeps its own
  namespace. Example: GitHub refuses an App name equal to an existing
  account's login, unless the account is your own (GitHub docs, checked
  2026-09-30). Where another account holds the handle on a platform, the
  handle stays as it is, and the platform identity carries another name of
  the owner's choosing.

This record's rule ties the two names together. The QAuth profile names the
platform identity, and the platform identity's website points at the profile.
The profile already lists the binding's `external_login` (§13). Example: the
GitHub App's "Homepage URL", which the owner sets by hand, like the logo.

**No correction to ADR-014 is needed.** Decision 4's note and §13 call the
App's slug the agent's public name on the platform. Neither ties it to the
handle. By the maintainer's choice the two may differ. The binding still
records the bot's numeric id, login and address from the platform's own
answers.

**Why.** The binding must reach every resource the agent works in, and a
private identity cannot always. A name clash is the platform's rule, so the
anchor has to be the profile, which QAuth serves.

### 2. Foreign installations are removed; the allowlist is by account

**The STS vends only for installations on allowlisted accounts, and removes
every other installation of the agent's platform identity.** Decided
2026-09-30 (maintainer). The maintainer's words: "we will block other people's
install requests". The maintainer's decision put the allowlist on accounts,
not installation ids. The mechanism below is this record's proposal. The
endpoints named are GitHub's, as the example.

- A public identity cannot refuse an install; any user can install it
  (GitHub docs). Blocking therefore means removing after the fact.
- The gate is the vend. At every vend the STS reads the resource's
  installation from the platform (GitHub:
  `GET /repos/{owner}/{repo}/installation`, under the App JWT). It refuses
  unless that installation's account is listed.
- The allowlist names accounts by the platform's stable numeric account id.
  The login is kept for display only. A stranger who later takes a freed
  login gains nothing.
- Removal is cleanup. On the platform's notice that an unlisted account
  created an installation (GitHub: an `installation` webhook with action
  `created`), the STS deletes it (GitHub:
  `DELETE /app/installations/{installation_id}`, under the App JWT). Until a
  webhook endpoint exists, a periodic sweep of the platform's installation
  list does the same (GitHub: `GET /app/installations`).
- The webhook is a trigger, never evidence. The STS checks its signature
  (GitHub: `X-Hub-Signature-256`), then re-reads the installation from the
  platform. It never deletes one on an allowlisted account.
- Every removal is audited: account id and login, installation id, and
  whether the webhook or the sweep found it. A failed removal is retried by
  the next sweep; it changes no vend.
- For a tree with no agent named, decision 4's per-organisation App is
  untouched. Its installation ids stay in configuration.

**This changes decision 4.** Decision 4 says "installation ids stay in
QAuth configuration either way". For the agent's identity that no longer
holds. The binding's allowlist names accounts, and the STS reads
installation ids from the platform. The change is the maintainer's decision.
The allowlist is a per-binding list in the transactional store. The owner
edits it through an owner route, under ADR-015 §3's guard, with a passkey
approval per operation. An operator may cap it in configuration (question 2,
decided 2026-10-09).

**Why.** An installation id is a fact about one install. An account is whom
the owner trusts, and a reinstall on it needs no configuration change. The
account check also closes a path out: a stranger installs the public
identity, and a prompt-injected node asks to push to the stranger's
repository. The STS refuses, because the account is not listed. (Endpoints,
webhook action and signature header checked against GitHub's documentation,
2026-09-30.)

### 3. Resource reach, and approval-only resources

**The identity is installed wherever the tree reaches; a resource the owner
marks approval-only stays closed to agents until a §14 passkey approval
opens it, once or for a window.** Decided 2026-09-30 (maintainer); the
window was added on 2026-10-09 (maintainer). The maintainer
decided that the identity is installed on every resource the agent's tree can
touch, including one the owner keeps closed to agents, so that an emergency
path exists. The generalisation below is this record's proposal. On a git
host a resource is a repository.

- **Reach.** The identity is installed on every resource on an allowlisted
  account that the agent's tree reaches. The node's ceiling still narrows
  every vend (§9).
- **An explicit list, always.** The STS never mints an installation token
  without a resource list. Without one, GitHub grants every repository of the
  installation (GitHub docs, checked 2026-09-30), closed ones included.
- **Approval-only is an owner setting per agent × resource.** The owner
  sets and clears it through an owner route (ADR-015). No node can.
- **Closed at the STS.** An approval-only resource is outside every node's
  ceiling at the STS, whatever the root's consent named. A vend for it is
  refused. That refusal is §14's step 1, as written.
- **One way in.** The only opening is a §14 approval with a passkey
  assertion. "Approve once" buys one elevation leaf and one STS vend. "Approve
  for a while" opens a window. Each renewal inside it goes through the
  matched CIBA request of ADR-015 question 5, and each may buy a new vend.
- **Gone with the leaf.** The broker deletes that installation token (GitHub:
  `DELETE /installation/token`) when the elevation leaf that bought it
  expires. ADR-014 §6's other deletion triggers still apply. No lasting
  path exists.
- **Always block is different.** §14's "always block" is a standing deny
  that no approval lifts. Approval-only is a standing "closed until
  approved". Precedence: always block, then approval-only, then the tree's
  ceiling.
- **Approval off means closed.** With `REMOTE_APPROVAL_ENABLED` off, an
  approval-only resource simply stays closed.

An approval-only resource is one an agent might change but the owner does not
want changed as a rule. Example: the repository that holds the rules of an
OS-level authority manager. vitrin is one such project, and it is not the
only one. Such a resource is not the actuation gate of ADR-014 §10.

**It fits §14 as written.** Approval-only is the one owner-set
bound an approval lifts; ADR-015 §7 leaves it to this record. Step 1 already
lists a refusal at the STS. Step 4's "approve once" already means one
elevation leaf or one STS vend. Step 5's leaf carries exactly the approved
delta. For these resources the page offers every choice of step 4, the
window included. _Decided 2026-10-09 (maintainer):_ this reverses the
record's earlier reading, which offered "approve once" only.

**Why.** Some resources the owner does not touch as a hard gate, but might in
an emergency. With the identity left off the resource, the emergency path
would be the owner's own credential, outside the tree and its log. Installed
but closed, the path exists, costs a passkey per approval and is logged.
"Always block" would close it for good. The setting binds the STS, not the
platform; its residual is in the Threats table.

### 4. The pass-through leg — temporary, and weaker by design

**Work on a platform that cannot issue a narrowed credential stays inside the
tree: the broker vends the owner's own token, and the platform's record there
is the owner's, carrying `Agent:` and `QAuth-Session:`.** Decided 2026-09-30
(maintainer). The maintainer's words: "for now only carry the QAuth sessions,
under my name". The maintainer decided that this work "will not stay outside
the tree". The broker holds the owner's personal token and vends it. The
decision was recorded with its weakness: no narrowing, and the token is
readable. The fail-closed parts below are this record's proposal. Bitbucket
Cloud is the example throughout.

**What the leg is.**

- It serves a platform that gives the owner a personal API token but no
  per-resource narrowing. It is meant to end. Each leg names the condition
  that removes it, such as the work moving to a platform that can narrow a
  credential.
- It has a mandatory end date, no later than the token's own expiry and at
  most 90 days away. The owner renews it with a passkey (question 4, decided
  2026-10-09).
- It is experimental in 1.0, outside the stability promise (ADR-018,
  proposed in a separate PR; decided 2026-10-09).
- The credential is the owner's personal API token, used for git over HTTPS.
  Example: an Atlassian API token for Bitbucket Cloud, limited by scopes and
  by an expiry of one day to one year. Its documentation offers no
  per-repository limit (both checked 2026-09-30). Between vends it rests
  QAuth-side, encrypted under a per-realm key used only for this purpose. The
  broker holds it in memory only (question 3, decided 2026-10-09).
- It is a vendor kind, not a binding. The acting identity is the owner, so
  no `agent_bindings` row exists and the profile lists nothing for it.
- The broker's hook writes `Agent:` and `QAuth-Session:`, the two lines the
  maintainer's decision names, and no `Model:` line. The `pre-push` hook
  reports pushed hashes as §9 says.

**Its weaknesses, stated plainly.**

- No narrowing. Whoever holds the token has the owner's full rights on the
  platform, within its scopes, until it is rotated or expires. T4's "derived
  by QAuth from the caller's token" is false on this leg.
- The token is readable by the process that receives it, and replayable
  from any host (T2).
- Nothing deletes it at node end. The dead-man switch (ADR-014 §6) stops the
  broker's use of it, not the token.
- §9's gate does not hold on this leg. Only detection remains: the ledger's
  hash match (T7). A commit carrying `Agent:` whose hash the ledger never
  recorded is a forgery or an unlogged push.
- The platform shows the owner as author. The trailers are claims (T7).

**The fail-closed parts (proposal).**

- One vendor interface on the STS, one kind per platform: `github` (§9) and,
  for this leg, the platform's own kind, `bitbucket` as the example. Every
  vend names its kind.
- The STS vends the owner's token only to a node whose token carries the
  leg's own scope. Working name: `<kind>:owner-token`, as
  `bitbucket:owner-token`.
- The consent screen describes that scope as acting on the platform with the
  owner's full rights (§11). A child gets it only by narrowing. No approval
  grants it, as with `agent:request`.
- Once ADR-014 §5 lands, the node's `locations` must also name the resource
  on the platform. That narrows who receives the token, not what the token
  can do.
- Every vend is logged as §9 logs a git-host vend: keyed by `jti`, with the
  leg's kind, never the token. Each vend emits the §7 SET.
- §9's precondition extends to the platform's host while the leg is on
  (bitbucket.org, as the example). The agent's uid holds no stored credential
  or SSH key that the platform accepts. Otherwise the vend decision is moot.
- The leg is removed when its end condition is met: the kind, the switch, the
  scope and the stored token.

**This narrows §9's author rule, by the maintainer's decision.** §9 sets a
node's author from the git-host binding under an agent root. For a resource
on a pass-through platform the broker sets the owner's identity instead and
writes no `Model:` line. On a git host with a binding, `Agent:` goes on
commits the binding's bot authors (§9). §9 says nothing about `Agent:` on a
human-authored commit. The pass-through leg is the one place a human-authored
commit carries `Agent:`. It is an exception for this leg, not a rule of the
binding. An owner's own repository check may refuse `Agent:` on
human-authored commits; that check has to allow this leg's exception.

**Why.** The maintainer's decision keeps that work inside the tree and its
log, rather than in the owner's own session. The price is written above. The
leg is temporary by design.

### 5. `handle@issuer`

**A handle is unique within its realm (decision 9), and today an issuer's
agents live in one realm. Outside the issuer it is always shown as
`handle@issuer-host`. The profile URL on the issuer's domain is the trust
anchor.** Proposed. The maintainer raised the question: QAuth is open
source, so anyone can self-host it and take the same handle again. The rules
are this record's.

- Identity is the pair (issuer, handle). Two deployments may each have an
  agent called `builder`. They are different agents.
- Inside its own deployment the bare handle is shown. That covers the
  portal, the consent screen, the approval page and what QAuth sends the
  owner.
- Anywhere else the canonical form is `handle@issuer-host`, where the host
  is `JWT_ISSUER`'s. The profile's JSON form carries it, so a copied name
  keeps its issuer.
- The profile, `https://<issuer-host>/agents/{handle}`, is the anchor. It
  names the bindings (§13). Each platform identity points back at it (§1).
  A reader checks both directions.
- Platform names are a separate race, first come on each platform: a git
  host's App name, a chat bot's name. QAuth cannot settle it. §1 is the
  example.

**Checked against the code and decision 9 (2026-09-30).** Decision 9's
default is realm-unique handles.

- A deployment has one `JWT_ISSUER`
  (`libs/server/config/src/lib/schemas/jwt.ts:124`).
- The `realms` table has no issuer column
  (`libs/infra/db/src/lib/schema/core.ts:58`). So one issuer can hold
  several realms. Registration already accepts a `realmId`
  (`apps/auth-server/src/app/routes/auth/register.ts:57`).
- The authorization endpoint serves only the default realm
  (`apps/auth-server/src/app/routes/oauth/authorize.ts:151`). So today every
  tree, and every agent a tree roots in, lives in one realm per issuer.

In such a single-realm deployment, uniqueness within the issuer and decision
9's realm-unique rule are one rule. This record adds only the display form.
ADR-019 gives each realm its own host and issuer, so a realm-unique handle is
also issuer-unique. That closes question 1 (2026-10-09).

**Why.** An email address has the same shape and the same answer: the
domain is the namespace. A global registry of handles would need an
authority that no open-source server can run.

### 6. Authorship and signing, with a git commit as the example

**Where a platform keeps an authored record, the binding's identity is the
author, whoever pushes it, and the record stays unsigned. On GitHub an
agent's commit is authored by the App's bot; per-agent email aliases are
dropped.** Decided 2026-09-30 (maintainer); unsigned confirmed 2026-10-09
(maintainer, with ADR-014 decision 12).

- **Author.** As §9 says, the broker sets the author from the binding: the
  bot's login and `<bot-id>+<app-slug>[bot]@users.noreply.github.com`. This
  record restates it and changes nothing.
- **No per-agent aliases.** The maintainer considered an address per agent, shaped like
  `<owner>+<handle>@example.com`, and dropped it. The maintainer's words:
  verifying hundreds of addresses "is not effective".
- **No machine account.** The maintainer also weighed a separate account for an avatar
  and a name. After the bot address was explained, the maintainer's words: "OK, the bot
  continues then".
- **Unsigned.** The maintainer wrote: "it won't be signed anyway;
  that was the decision too". _Decided 2026-10-09 (maintainer):_ unsigned,
  confirmed with ADR-014 decision 12.
- **The reopen trigger stays:** a requirement that provenance be evidence
  rather than a pointer. The purpose stays in the three layers PR #419 wrote:
  a ruleset prevents, the ledger detects, a signature lets a third party
  verify offline. Unsigned gives up only the third.

Two later options, both unverified — to be tested if decision 12 reopens:

- **App-made commits through GraphQL `createCommitOnBranch`.** GitHub's
  documentation says a bot's commit verifies only without custom author or
  committer information (checked 2026-09-30). Whether this mutation shows
  Verified under the App's bot is unverified. GitHub would also choose the
  hash, so the ledger would learn it from GitHub, not the `pre-push` hook.
- **Keyless gitsign with QAuth as the OIDC issuer.** GitHub's verification
  covers GPG, SSH and S/MIME (checked 2026-09-30). How GitHub shows a gitsign
  signature is unverified. So is whether a Fulcio instance would accept QAuth
  as an issuer.

**Why.** The noreply address already names the agent. The attack the maintainer asked
about, a force push under the agent's name, is prevented by a ruleset and
detected by the hash match; nothing yet needs offline verification.

## Threats

Only threats this record adds or changes. T-numbers are ADR-014's
([Threat model](./014-agent-authority-tree.md#threat-model)).

| Threat                                                                                              | Control                                                                                                                 | Residual                                                                                                                         |
| --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| A stranger installs the public identity, and an injected node (T6) asks to push to their repository | Vend only for installations on allowlisted account ids (§2)                                                             | Allowlisted resources within the ceiling (T6)                                                                                    |
| A stranger takes a freed login that the allowlist once named                                        | Numeric account ids, never logins (§2)                                                                                  | None new                                                                                                                         |
| A forged or replayed installation webhook                                                           | Signature check; the payload is a trigger only; re-read from the platform; allowlisted installations never deleted (§2) | Request volume; rate limits are ADR-015's                                                                                        |
| A node's ceiling names an approval-only resource                                                    | Approval-only at the STS; one vend per approval or window renewal; token deleted with the leaf (§3)                     | A vended token is readable while it lives (T2); the identity's key or an ambient credential bypasses the STS (§9's precondition) |
| Approval fatigue on an approval-only resource (T8)                                                  | §14's scope, budget and mute; a passkey per approval (§3)                                                               | An owner who taps yes                                                                                                            |
| The pass-through token leaks from a node (T2)                                                       | The leg's scope; `locations` once ADR-014 §5 lands; every vend logged; the owner's token scopes and expiry (§4)         | The owner's full rights on the platform until rotation or expiry; T4 does not hold                                               |
| A forged `Agent:` line on a commit of the pass-through leg (T7)                                     | The ledger's hash match (§4)                                                                                            | Detection only                                                                                                                   |
| A self-hosted deployment registers the same handle                                                  | `handle@issuer-host` outside the issuer; the profile as anchor; two-way links (§5)                                      | Platform names stay first come; a reader who ignores the host                                                                    |

## Alternatives considered

| Alternative                                         | Why not                                                                                                                   |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| A private platform identity                         | Can install only on its owner's account; the agent's resources can span an organisation too (§1)                          |
| One private identity per account                    | Two bot identities for one agent; §13 has one binding per platform                                                        |
| Name the identity after the handle                  | A platform may refuse a name equal to another account's login (§1)                                                        |
| Allowlist by installation id (decision 4)           | Changes on every reinstall and says nothing about whose account it is; the maintainer chose accounts (§2)                 |
| Leave foreign installations inert                   | The maintainer chose removal; an inert install still holds a grant on a stranger's resources                              |
| Suspend rather than delete                          | GitHub's `PUT /app/installations/{installation_id}/suspended` keeps a row the sweep must revisit; deletion leaves nothing |
| Leave the identity off an approval-only resource    | The emergency path would be the owner's own credential, outside the tree and its log (§3)                                 |
| "Always block" on that resource                     | No approval lifts it, so no emergency path remains (§3)                                                                   |
| Park the pass-through platform until the work moves | The maintainer: that work does not stay outside the tree (§4)                                                             |
| A repository or workspace access token              | Bitbucket Cloud issues it to the organisation's admins, not the owner; availability on its plan unverified                |
| Per-agent verified email aliases                    | The maintainer: verifying hundreds of addresses is not effective; the bot address already links (§6)                      |
| A global handle registry                            | No authority can run one for an open-source server; the issuer's domain is the namespace (§5)                             |

## Phasing

Each piece lands in the ADR-014 phase that builds what it depends on
([Phasing](./014-agent-authority-tree.md#phasing)).

- **P0a — the STS.** The explicit resource list (§3) and the vendor
  interface with its `github` kind. Test: against a mock platform, every
  installation-token request the STS sends names its resources.
- **P0c — the platform identity (§1), with the account allowlist at vend,
  the sweep and audited removal (§2), and authorship (§6).** Test: a binding
  whose platform identity name differs from the handle provisions, and the
  profile lists the identity's bot login. For §2, against a mock platform, a
  vend on an unlisted account is refused. The sweep deletes that installation
  with one audit row, while an allowlisted installation survives. For §6,
  ADR-014's P0c authorship test suffices.
- **P0c — approval-only, closed half (§3).** The owner setting, and the
  STS refusal. Test: a node whose ceiling names an approval-only resource
  gets no vend, and the refusal is logged.
- **P0c — the pass-through leg (§4).** The leg's kind, the switch, the
  scope, the broker's helper for the platform's host and the precondition.
  Test: a node without the scope gets nothing; a node with it gets one vend,
  logged by `jti` without the token, and its commit is owner-authored with
  both trailers; a vend after the leg's end date is refused. ADR-014's P0c
  authorship test then covers git-host bindings only.
- **P0c — the display form (§5).** Test: the profile's JSON names the agent
  as `handle@issuer-host`, with the host taken from `JWT_ISSUER`.
- **P2 — `locations` on the pass-through leg (§4).** Test: a vend for a node
  whose `locations` do not name the resource is refused.
- **P3 — the installation webhook (§2).** Test: a badly signed webhook
  changes nothing; a valid one deletes an unlisted account's installation
  and never an allowlisted one.
- **P5 — an approval opens an approval-only resource (§3).** Test: one
  approve-once elevation buys exactly one vend, and a second vend under it is
  refused. Inside a window, each matched renewal may buy one new vend. The
  broker deletes each token at its leaf's expiry.

## Consequences

### Positive

- One agent, one bot name, every resource it works in (§1); a stranger's
  installation buys nothing and does not stay (§2).
- A resource can be closed to agents without losing the emergency path;
  each approval costs a passkey, and every vend leaves a record (§3).
- Work on a platform without narrowed credentials enters the tree's log
  (§4), and a handle always travels with its issuer (§5).

### Negative

- The STS gains a platform webhook endpoint and a write action on the
  platform, deleting installations (§2).
- The pass-through leg hands a node the owner's full personal credential. The
  tree's main property, a narrowed credential, does not hold there (§4).
- Approval-only is a second standing owner setting beside "always block".
  The owner has to know the difference (§3).
- Unsigned commits: a third party cannot verify authorship offline (§6).

### Neutral

- Default off. With `AUTHORITY_TREE_ENABLED` off none of this runs, and the
  pass-through leg needs its own switch as well.
- ADR-014 §9 and §13 name §2's account allowlist since 2026-10-09. By the
  maintainer's decisions, decision 4 changes (§2) and §9's author rule
  narrows (§4). ADR-014 §9's `Agent:` line was updated on 2026-10-09 to match
  question 5. §14's step 4 applies to approval-only resources as written,
  window included (§3).

## Decisions parked for the maintainer

Each question carries the default this record was written on. As of
2026-10-09 every question below is decided.

1. **Handles when one issuer serves agents in more than one realm.** Should
   a handle be unique across the issuer, or stay realm-unique with a
   realm-qualified display form? Two issuers sharing a host under different
   paths raise the same question. Default: decision 9's realm-unique
   handles. The display form and the profile path carry whatever makes them
   unique, the realm or the issuer's path, spelled when the routing for a
   second realm is built. Why: decision 9 stands until the maintainer decides.
   _Closed 2026-10-09 by ADR-019:_ each realm has its own host and issuer, so
   a realm-unique handle is issuer-unique.
2. **Where the account allowlist lives.** In QAuth configuration, where
   decision 4 put installation ids, or as an owner-edited list per binding
   through an owner route (ADR-015)? Default: QAuth configuration, beside the
   identity's key. Why: nothing a node reaches can edit it. _Decided
   2026-10-09 (maintainer):_ a per-binding list in the transactional store.
   The owner edits it through an owner route, under ADR-015 §3's guard, with
   a passkey approval per operation. An operator may cap it in configuration.
3. **Where the pass-through token rests between vends.** QAuth-side, released
   by the STS per vend, or on the box, in the broker's keyring? Default:
   QAuth-side; the broker holds it in memory for the nodes it serves. Why:
   ADR-014 keeps the App's private key and the vend policy off the box (T2).
   _Decided 2026-10-09 (maintainer):_ QAuth-side, encrypted under a
   dedicated per-realm key for this purpose; the broker holds it in memory
   only. The pass-through leg is experimental in 1.0, outside the stability
   promise.
4. **An owner-visible end date for the pass-through leg.** Should the leg
   carry a date after which it stops? Default: no date for the leg. The
   token's own expiry is recorded when it is stored, and the STS stops
   vending after it. Why: the end condition is the owner's to name, and the
   token expiry already forces a yearly review at most. _Decided 2026-10-09
   (maintainer):_ a mandatory end date, no later than the token's own expiry
   and at most 90 days away. The owner renews it with a passkey.
5. **The `Agent:` trailer outside the issuer.** Keep §9's `<agent_id>`, or
   write `handle@issuer-host`, or both? Default: §9 as written. Why: §9 is
   ADR-014's text. A deployment that writes the bare handle would have §5
   write it as `<handle>@<issuer-host>`. _Decided 2026-10-09 (maintainer):_
   both. The `Agent:` trailer carries the `agent_id` and
   `handle@issuer-host`, with a version marker. ADR-014 §9 was updated to
   match on 2026-10-09.

## Related

- [ADR-014](./014-agent-authority-tree.md) — the tree this record builds on:
  [§9](./014-agent-authority-tree.md#9-cli--qauth-broker-and-a-qauth-side-sts-the-credential-is-the-gate)
  (the STS, provenance),
  [§13](./014-agent-authority-tree.md#13-agent-identity--a-principal-with-an-owner-held-by-qauth-and-asserted-nowhere-else)
  (bindings, the profile),
  [§14](./014-agent-authority-tree.md#14-remote-approval--a-refused-request-the-owner-approves-out-of-band)
  (approve once, always block),
  [Threat model](./014-agent-authority-tree.md#threat-model) (T2, T4, T6, T7,
  T8), and
  [decisions 3, 4, 9 and 12](./014-agent-authority-tree.md#decisions-parked-for-the-maintainer)
- [ADR-015](./015-agent-tree-hardening.md) — owner routes and rate limits;
  [ADR-012](./012-dynamic-client-ownership.md) — the ownership check
- Example, GitHub: [App visibility](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/making-a-github-app-public-or-private) ·
  [registering an App (name rules)](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app) ·
  [REST: Apps](https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28) ·
  [the `installation` webhook](https://docs.github.com/en/webhooks/webhook-events-and-payloads#installation) ·
  [validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries) ·
  [commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification) ·
  [GraphQL `createCommitOnBranch`](https://docs.github.com/en/graphql/reference/commits#mutation-createcommitonbranch)
- Example, Bitbucket Cloud and Atlassian: [using API tokens](https://support.atlassian.com/bitbucket-cloud/docs/using-api-tokens/) ·
  [creating an API token](https://support.atlassian.com/bitbucket-cloud/docs/create-an-api-token/) ·
  [managing API tokens](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)
- [gitsign](https://github.com/sigstore/gitsign)
