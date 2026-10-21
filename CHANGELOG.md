# Changelog

All notable changes to QAuth are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-10-21

Fixes backported from `main` to the 0.1 line. One of them changes what the ID
token carries; see Changed.

### Changed

- **BREAKING**: ID tokens now carry `name` only when the granted scope
  includes `profile`, the rule userinfo already follows (OIDC Core §5.4)
  ([#755]). Before, the `authorization_code` grant put the user's name in the
  ID token whatever was granted, so a client that asked only for `openid` got
  it. The ID token and userinfo now resolve the claim through one helper and
  release the same profile claims for the same grant. No other grant signs an
  ID token, and access tokens never carried `name`.

  **Who is affected**: a client that reads `name` from the ID token without
  requesting `profile`. **Action**: request the `profile` scope, which shows
  on the consent screen. Userinfo behaves as before.

### Fixed

- The auth server no longer exits when PostgreSQL closes an idle pooled
  connection, as a restart, a failover or `pg_terminate_backend` does
  ([#746]). pg-pool emits that error on the pool after it has dropped the
  client, and with no listener Node threw it and ended the process. The pool
  now logs the error and opens a fresh connection on the next query.

- `/oauth/userinfo` answers a token whose subject is not a user with 401
  `invalid_token` and a `WWW-Authenticate: Bearer` challenge, on GET and POST
  ([#754], OIDC Core §5.3.3, RFC 6750 §3.1). A `client_credentials` token
  carries its `client_id` as `sub`, and with no `resource` and no client
  `audience` its `aud` is the `client_id` too, so it passed the audience check
  and failed with 500: the user lookup, then the failure audit, sent the
  `client_id` to PostgreSQL as a user id. A token whose user no longer exists
  gets the same 401 instead of 404. Token exchange refuses such a token as
  `subject_token` with `invalid_request` before any lookup, and the users
  repository answers "no such user" for an id that is not a UUID without
  querying. `/auth/logout` had the same failure audit: a sign-out with the
  token of a deleted user answered 500. It now answers 401 `invalid_token`
  instead of the intended 404.

[#746]: https://github.com/qauth-labs/qauth/pull/746
[#754]: https://github.com/qauth-labs/qauth/issues/754
[#755]: https://github.com/qauth-labs/qauth/issues/755

## [0.1.0] - 2026-10-19

### Added

- **Wallet federation (T4, [ADR-004](./docs/adr/004-wallet-agnostic-federation.md)) —
  browser wallet sign-in.** QAuth can now generate an OID4VP 1.0 authorization
  request, take back a `direct_post` response, validate an SD-JWT VC presentation,
  resolve the account, and mint a session — a complete browser sign-in. Wallet
  sign-in never creates an account; a wallet is linked from a signed-in account
  (see **Changed**). Covered end-to-end against a mock wallet: the refusal of an
  identifier with no account, sign-in with a linked wallet, the ADR-009 §1
  takeover attempt, untrusted-issuer refusal, account linking, and `acr`
  presence/absence.

  **Off by default.** Nothing below changes how an existing email/password or
  OAuth client behaves — the routes are not even registered unless
  `WALLET_FEDERATION_ENABLED=true`. Validated so far only on the
  `oid4vp-1.0-base` profile against a mock wallet; the HAIP profile (#377) and a
  real-wallet interoperability pass (#376) remain open.

  Note: `WalletProvider.verify()` still throws unconditionally and is required to
  keep doing so (#232) — the wallet login path does not go through the generic
  `CredentialProvider` registry.
  - OID4VP 1.0 request generation + `direct_post` intake ([#233])
  - `VerifierProfile` abstraction for configurable deployment profiles ([#299])
  - SD-JWT VC presentation validation ([#234])
  - Static per-realm issuer trust registry ([#236])
  - ES256 + JWE (ECDH-ES / A\*GCM) crypto prerequisites for HAIP ([#298])
  - Credential revocation via Token Status List, HAIP §6.1 ([#297])
  - Interoperable Key Attestations validation, HAIP §9.2 ([#308])
  - VC claims normalization into `user_attributes` ([#235])
  - Configurable `SubjectResolutionStrategy` ([#300], [ADR-009](./docs/adr/009-wallet-account-resolution.md))
  - Account linking — attach a wallet credential to an existing user ([#238])
  - `acr` claim propagation from assurance level ([#237], [ADR-010](./docs/adr/010-acr-assurance-mapping.md))
  - Wallet sign-in flow in the login screens ([#239])
  - E2E integration suite against a reference mock wallet ([#240])

  **New operator configuration** (all optional; the feature is off by default):
  `WALLET_FEDERATION_ENABLED`, `OID4VP_VERIFIER_PROFILE`, `OID4VP_REQUESTED_VCT`,
  `OID4VP_SUBJECT_RESOLUTION`, `OID4VP_SUBJECT_CLAIM`,
  `OID4VP_SUBJECT_CLAIM_ISSUERS`, `OID4VP_SUBJECT_BINDING_CLAIMS`,
  `OID4VP_STATUS_LIST_TRUST_ANCHORS` (or `_PATH`),
  `OID4VP_STATUS_LIST_URI_ALLOWLIST`, `OID4VP_WALLET_INVOCATION_ENDPOINT`,
  `OID4VP_ISSUER_JWKS`, `OID4VP_TRUSTED_ISSUERS`, `OID4VP_ISSUER_ASSURANCE`,
  `ACR_VALUE_STYLE`.

- **Post-quantum hybrid signing (T4, [ADR-005](./docs/adr/005-pqc-hybrid-signing.md))
  — implemented and off by default.** Detached-parallel ML-DSA-65 + Ed25519
  signing, a mixed `AKP` + `OKP` JWKS, a napi-rs native backend over `aws-lc-rs`
  and a `@noble/post-quantum` fallback. **No behavior changes unless enabled**:
  `SIGNING_ALGORITHM_MODE` defaults to `ed25519` and `HYBRID_SIGNING_ENABLED` to
  `false`, so tokens remain Ed25519-only and classical verifiers need no action.
  Enabling hybrid by default is gated on the pre-default-on checklist in the
  [security gate review](./docs/security/005-pqc-hybrid-signing-review.md)
  (CONDITIONAL PASS). See the
  [verifier guide](./docs/hybrid-signing-verifier-guide.md).
  ([#242], [#243], [#244], [#245], [#246], [#247], [#248], [#249])

  **New operator configuration:** `SIGNING_ALGORITHM_MODE`,
  `HYBRID_SIGNING_ENABLED`, `JWT_MLDSA_PRIVATE_KEY` (or `_PATH`),
  `JWT_MLDSA_KID`, `PQC_TOKEN_DELIVERY`, `PQC_SELF_CONTAINED_ACK`.

[#232]: https://github.com/qauth-labs/qauth/issues/232
[#233]: https://github.com/qauth-labs/qauth/issues/233
[#234]: https://github.com/qauth-labs/qauth/issues/234
[#235]: https://github.com/qauth-labs/qauth/issues/235
[#236]: https://github.com/qauth-labs/qauth/issues/236
[#237]: https://github.com/qauth-labs/qauth/issues/237
[#238]: https://github.com/qauth-labs/qauth/issues/238
[#239]: https://github.com/qauth-labs/qauth/issues/239
[#240]: https://github.com/qauth-labs/qauth/issues/240
[#242]: https://github.com/qauth-labs/qauth/issues/242
[#243]: https://github.com/qauth-labs/qauth/issues/243
[#244]: https://github.com/qauth-labs/qauth/issues/244
[#245]: https://github.com/qauth-labs/qauth/issues/245
[#246]: https://github.com/qauth-labs/qauth/issues/246
[#247]: https://github.com/qauth-labs/qauth/issues/247
[#248]: https://github.com/qauth-labs/qauth/issues/248
[#249]: https://github.com/qauth-labs/qauth/issues/249
[#297]: https://github.com/qauth-labs/qauth/issues/297
[#298]: https://github.com/qauth-labs/qauth/issues/298
[#299]: https://github.com/qauth-labs/qauth/issues/299
[#300]: https://github.com/qauth-labs/qauth/issues/300
[#308]: https://github.com/qauth-labs/qauth/issues/308

### Changed

- **BREAKING**: access tokens now carry `email`/`email_verified` only when the
  granted scope includes `email`, the rule ID tokens (#259) and userinfo
  (#229) already follow. This holds on every grant that mints a user access
  token: `authorization_code`, `refresh_token`, RFC 8693 token exchange and
  the RFC 7523 `jwt-bearer` grant. A refresh or an exchange that narrows
  `email` out of the scope drops the claims. The first-party `/auth/login`
  token is granted no scope and no longer carries them. `client_credentials`
  never did. Before, every user access token carried the user's verified
  address whatever was granted. The client could read it from the JWT in the
  same response whose ID token withheld it, so the `email` scope and the
  consent screen line for it controlled nothing (ANT-2026-2O0T72HY).

  **Who is affected**: a resource server that reads `email` from access tokens
  issued without the `email` scope. **Action**: have the client request the
  `email` scope, which shows on the consent screen. ID tokens and userinfo
  behave as before.

- **BREAKING**: `/oauth/userinfo` (GET and POST) now checks the access token's
  audience, as [`docs/security/threat-model.md`](./docs/security/threat-model.md)
  promises for every token. A token is accepted only when its `aud` contains
  the token's own `client_id` or the `userinfo_endpoint` URL that discovery
  publishes. Every other token gets `401` with
  `WWW-Authenticate: Bearer error="invalid_token"`. Before, any live token this
  server issued was accepted, so a resource server could read the claims of
  the user whose token it had been handed.

  **Who is affected**: an OIDC client that runs the code flow without
  `resource` gets `aud` = its `client_id` and keeps working, and so does the
  developer portal's `/auth/login` token. A client that binds its grant to a
  resource server with RFC 8707 `resource`, or whose operator configured an
  `audience` for it, and then calls UserInfo with that token is refused.
  **Action**: read identity from the ID token, or add the UserInfo URL as
  another `resource` at `/oauth/authorize` (an operator can add it to the
  client's `audience` instead).

- **BREAKING (ID-JAG mint; only with `ID_JAG_ENABLED`, which is off by
  default)**: an ID-JAG minted through RFC 8693 token exchange now carries only
  scopes that are in the agent client's registered `scopes`. This is the ceiling
  `client_credentials` and the `jwt-bearer` consume side already apply
  ([ADR-011](./docs/adr/011-enterprise-managed-authorization.md) §3, amended
  2026-10-19). Before, the mint copied the subject token's scope unchecked, so
  an agent could carry a scope it is not registered for to a partner's server
  (ANT-2026-L66R3GFR). A scope outside the list is refused with
  `invalid_scope`, not dropped; the agent sends `scope` to ask for less.

  **Action for operators**: an agent provisioned with an empty `scopes` list
  can no longer mint a scoped assertion. List in its `scopes` every scope it
  should be able to carry to a partner. The delegation branch of token exchange
  (`requested_token_type` access token) is unchanged.

- **BREAKING (security)**: `POST /auth/register` no longer reveals whether an
  address already has an account (ANT-2026-SPEMY9GU). It answered `409` for a
  registered address and `201` with the new user for a free one, so any caller
  could test any address.
  - Every address now gets `202 Accepted` with the same body,
    `{ "message": "Registration received. Check your inbox for an email with the next step." }`,
    the same headers (`Cache-Control: no-store`) and the same work on the
    request path (the password is hashed and the insert attempted either way,
    under a 500 ms floor). The body has **no `id`, `email`, `emailVerified`,
    `realmId`, `createdAt` or `updatedAt`** any more, and the route never
    answers `409`.
  - What happened goes to the mailbox. A free address gets its account and a
    verification link. The owner of a verified account gets a new "someone
    tried to register with your address" notice, with no link. An account that
    is still unverified gets its verification link again, which verifies only
    with the password chosen at the first registration. Mail to an existing
    account counts toward the `RESEND_VERIFICATION_*` per-address caps, and
    every registration claims the minimum interval there, so a resend straight
    after a registration answers `429`. No mail is awaited by the request.
  - `POST /auth/login` and `POST /ui/login` refuse an account whose address is
    not verified exactly as they refuse a wrong password: `401 INVALID_CREDENTIALS`
    (it was `403 EMAIL_NOT_VERIFIED`) and the same login page. The
    `qauth_login_attempts_total` metric counts it as `invalid_credentials`; the
    log line and audit row keep `email_not_verified`.
  - The developer portal shows the same "check your inbox" screen for both
    cases and no longer has an "Email already registered" error.

  **Action for clients**: treat any `2xx` from `/auth/register` as "check your
  inbox" and stop reading a user id from it. Do not branch on `409` or on
  `EMAIL_NOT_VERIFIED`.

- **BREAKING (security)**: `REQUIRE_VERIFIED_ACCOUNT` now defaults to **`true`**
  (maintainer decision, 2026-10-19). Without it, registering an address with a
  password of one's choice and then logging in with it told a free address
  (`200`) from a registered one (`401`). An unset or blank value of the
  variable, or of its deprecated alias `REQUIRE_EMAIL_VERIFIED`, now means
  `true`.

  **Action for operators**: existing accounts whose address was never verified
  can no longer sign in with a password until they verify (they can request a
  new link through `POST /auth/resend-verification` or the portal). A stack on
  `EMAIL_PROVIDER=mock` delivers no mail, so its sign-ups cannot be verified:
  configure `smtp` or `resend`. Set `REQUIRE_VERIFIED_ACCOUNT=false` only
  knowingly; it gives the register-then-login answer back.

- **BREAKING (wallet federation, `WALLET_FEDERATION_ENABLED=true` only)**: a
  first wallet presentation no longer creates an account. From `v0.1.0-rc.1` to
  `v0.1.0-rc.3`, presenting a valid credential on `/ui/wallet-login` with an
  identifier that had no account enrolled a new account on that identifier,
  bound to the presenter's credential, while an identifier with an account was
  refused. Anyone holding a credential from a trusted issuer could therefore
  learn which identifiers have accounts (including wallet-only accounts) and
  claim identifiers that belong to other people. Wallet sign-in now signs in
  only an account the credential is already bound to; an identifier with no
  account gets the same refusal as a taken one (same status, body, headers and
  cookies) and nothing is written.
  ([ADR-009](./docs/adr/009-wallet-account-resolution.md) §1, amended
  2026-10-19; ANT-2026-NCX3VXDP)

  **Action for operators**: accounts that wallet sign-in created before this
  release keep signing in. A new person gets wallet sign-in by creating an
  account, signing in to it, and linking the wallet at `/ui/wallet-link` (or
  `POST /auth/link/wallet`). Wallet-first sign-up arrives with the hosted
  sign-up pages ([ADR-017](./docs/adr/017-first-party-login.md)). No
  configuration or migration is involved.

- **BREAKING**: ID tokens now release `email`/`email_verified` only when the
  granted scope includes `email`, matching the userinfo endpoint's gating
  (OIDC Core §5.4 data minimization). Clients requesting only `openid` no
  longer receive the user's email in the ID token — request the `email`
  scope. Access-token convenience claims and userinfo behavior are
  unchanged. ([#259]) _Superseded in part on 2026-10-19: access tokens now
  follow the same `email` scope rule (see the access-token entry above)._

[#259]: https://github.com/qauth-labs/qauth/issues/259

- **BREAKING (schema)**: migration 0011 completes ADR-002 — it **drops**
  `users.email`, `users.email_normalized`, and `users.password_hash` (and
  their indexes), drops `email_verification_tokens.user_id`, and promotes
  `email_verification_tokens.credential_id` to NOT NULL. `users` is now a
  pure identity anchor; all credential data lives in `user_credentials`, and
  the `(realm_id, provider_type, external_sub)` unique index is the sole
  duplicate-registration guard. ([#230], Epic #224)

  **Deploy ordering (enforced)**: the previous release (#228/#229 dual-write)
  must be fully deployed — with no pre-#228 app instances still running —
  before applying this migration. Migration 0011 opens with an in-SQL guard
  that **aborts atomically** (zero DDL applied) if any user's identity data
  exists only in the legacy columns, printing remediation instructions.
  Conversely, apply migration 0011 (`pnpm nx run infra-db:db:migrate`)
  before starting any instance of this release — the new binary writes only
  the ADR-002 tables; this direction has no in-SQL guard.
  Upgrading from a pre-#229 deployment is a two-hop path: first deploy the
  previous release — the last one containing the `db:backfill-identity`
  target, which is commit **`00c23f04`** ("Merge pull request #260 …",
  2026-07-18), the immediate parent of `29abe4a` and therefore the newest
  state of `main` that still has the tool and does _not_ yet have migration
  0011 — run its backfill runbook (`--refresh`, then `--verify-only`; both
  exit 0), then upgrade to this release. **No tag names that commit yet**;
  giving the hop a pinnable tag is tracked in [#362]. `v0.1.0-rc.0`
  (2026-07-25) is **not** it — that tag postdates 0011 and already contains
  the destructive migration, so starting the two-hop path from it is exactly
  the mistake this note exists to prevent. Note: that script's help says `--refresh` is
  "PRE-CUTOVER ONLY" — the warning does not apply on that release, because
  its binary dual-writes the legacy columns in the same transactions,
  keeping them equal to the authoritative tables; `--refresh` is safe there.

  **Rollback**: there is **no rollback after 0011**. Dropped columns cannot
  be reconstructed (password hashes are unrecoverable by design). Take a
  database backup immediately before applying; restoring it is the only undo
  and discards all post-migration writes.

  **Minor operational notes**: in-flight verification tokens minted without a
  `credential_id` are re-pointed where resolvable and otherwise deleted (the
  affected user clicks resend once). For accounts created before #228, a few
  user-visible strings (verification response, consent-screen address, logs)
  now show the normalized lowercase email — the original-case string ceased
  to exist with the column. `users.email_verified`/`email_verified_at`
  survive as vestigial columns (no writers; one sanctioned reader — the
  register 201 response's default surface); their drop is tracked in
  [#261].

[#230]: https://github.com/qauth-labs/qauth/issues/230
[#362]: https://github.com/qauth-labs/qauth/issues/362
[#261]: https://github.com/qauth-labs/qauth/issues/261

- **BREAKING**: `email` and `email_verified` claims — in ID tokens, userinfo
  responses, **and** the non-standard access-token convenience claims — now
  resolve exclusively from **verified** `user_attributes` rows using the
  ADR-002 trust order (`wallet > oidc_* > self_reported`, expiry-aware). When
  a user has **no verified email attribute, both claims are omitted entirely**
  — never `null`, never present-with-`false`. When `email` is present,
  `email_verified` is always `true`: presence is the verification signal
  (OIDC Core 1.0 §5.1). There is **no compatibility flag** — this is the
  OIDC-correct behavior; the previous always-emit behavior was a documented
  MVP shortcut. ([#229], ADR-002)

  **Migration for operators**: claim emission now depends entirely on
  `user_attributes` rows. Before deploying this release against a database
  that predates the ADR-002 identity backfill (#226) — or whose backfill may
  be partial — run:

  ```bash
  pnpm nx run infra-db:db:backfill-identity -- --refresh
  pnpm nx run infra-db:db:backfill-identity -- --verify-only
  ```

  Both must exit 0. `--verify-only` confirms every user has a
  `(self_reported, email)` attribute row; without it, existing users —
  **including those with a verified email** — silently lose the
  `email`/`email_verified` claims on token, refresh, and userinfo responses.

  **Migration for integrators**: treat `email` as optional everywhere.

  ```js
  // Before — unsafe after this release:
  const { sub, email } = await userinfo(accessToken); // email may be absent!

  // After:
  const { sub, email } = await userinfo(accessToken);
  if (email === undefined) {
    // No verified email on record — collect one, or proceed without.
  }
  ```

  Clients that require an email for account linking should request the
  `email` scope AND handle its absence; an absent claim means QAuth has no
  _verified_ address for that user, not that the user has no address.

[#229]: https://github.com/qauth-labs/qauth/issues/229

- **Schema**: migration 0012 drops the vestigial
  `users.email_verified`/`email_verified_at` columns kept out of 0011's
  issue-literal scope. No behavior change: they had no writers since #230,
  and the register 201 response's `emailVerified: false` is now a literal
  (byte-identical wire value). No guard or special deploy ordering needed.
  ([#261])

- **Schema**: migrations 0013–0016 support the OIDC and T4 work above. All four
  are additive and require no special deploy ordering or backfill.
  - `0013` — adds `authorization_codes.auth_time`, carrying the authentication
    instant through to the ID token's `auth_time` claim.
  - `0014` — widens `authorization_codes.nonce` and `.state` from `varchar` to
    `text`. Clients that previously had long values rejected now succeed; no
    existing row changes.
  - `0015` — adds the `oid4vp_request_states` table (realm-scoped, with a unique
    `state_hash`, the DCQL query, expiry and single-use `redeemed_at`), backing
    OID4VP request/response correlation. Unused unless wallet federation is on.
  - `0016` — adds `authorization_codes.assurance_level`, constrained to
    `substantial` / `high` or NULL, feeding the `acr` mapping in ADR-010.

### Deprecated

- **`REQUIRE_EMAIL_VERIFIED` is renamed `REQUIRE_VERIFIED_ACCOUNT`.** Email is a
  user attribute, not the trust gate. The gate is a verified account.
  **The rename alone changes no behaviour**: for a password account, the proof
  is still the confirmed address. (The default changed separately, to `true`;
  see Changed above.)
  - The old name keeps working as an alias through the 1.x deprecation window
    of at least 12 months.
  - A deployment that sets only the old name logs a deprecation warning at
    boot.
  - Setting both names to different values fails the boot with a message that
    names both.
  - `docker-compose.yml` forwards both names, so a deployment that still sets
    only the old one keeps its gate.
  - A blank value of either name now reads as unset, instead of failing the
    boot. This lets compose forward both names when they are unset.

  **Action for operators**: rename the variable to `REQUIRE_VERIFIED_ACCOUNT`.

### Security

- **66 security advisories are fixed in this release.** 65 come from a private
  report by Anthropic's OSS Scanner (scan `qauth-20261015-005`, 2026-10-15);
  one was found while fixing them. Every release candidate, `v0.1.0-rc.0` to
  `v0.1.0-rc.3`, is affected: upgrade to `v0.1.0`. Each advisory names its fix
  commits and anything the fix does not cover.
  - Critical: [GHSA-cvh4-23vc-5f3v](https://github.com/qauth-labs/qauth/security/advisories/GHSA-cvh4-23vc-5f3v) — Resource validation bypass in OAuth authorize lets clients set aud to system
  - High: [GHSA-442q-jwq9-p5g4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-442q-jwq9-p5g4) — Oversized request arrays get one Zod error per element: unauthenticated DoS
  - High: [GHSA-5gvj-7cjh-2rmx](https://github.com/qauth-labs/qauth/security/advisories/GHSA-5gvj-7cjh-2rmx) — ssrfSafeGet(): idle timeout lets a client_id host hold fetches open (DoS)
  - High: [GHSA-6fcc-mxv4-c4mq](https://github.com/qauth-labs/qauth/security/advisories/GHSA-6fcc-mxv4-c4mq) — max_age coercion: nested JSON arrays let anyone block the event loop
  - High: [GHSA-87qh-m945-hhvv](https://github.com/qauth-labs/qauth/security/advisories/GHSA-87qh-m945-hhvv) — Unbounded client size and count let any account crash auth-server (heap OOM)
  - High: [GHSA-98f5-2857-ggjf](https://github.com/qauth-labs/qauth/security/advisories/GHSA-98f5-2857-ggjf) — Unauthenticated ReDoS in normalizeInternalAuthorizeUrl via # in request URL
  - High: [GHSA-9f5r-frxp-952q](https://github.com/qauth-labs/qauth/security/advisories/GHSA-9f5r-frxp-952q) — Deeply nested typ array in unsigned SD-JWT VC blocks the event loop
  - High: [GHSA-9hr7-g6qj-pchf](https://github.com/qauth-labs/qauth/security/advisories/GHSA-9hr7-g6qj-pchf) — Quadratic check on unbounded refresh_token scope blocks the event loop
  - High: [GHSA-c4qp-jrqq-g428](https://github.com/qauth-labs/qauth/security/advisories/GHSA-c4qp-jrqq-g428) — Crafted CIMD JWK member names block the event loop via localeCompare
  - High: [GHSA-p5hg-342x-frxj](https://github.com/qauth-labs/qauth/security/advisories/GHSA-p5hg-342x-frxj) — Event loop blocked by non-ASCII resource URLs parsed before length cap
  - High: [GHSA-r7r3-r5xx-ghmq](https://github.com/qauth-labs/qauth/security/advisories/GHSA-r7r3-r5xx-ghmq) — ssrfSafeGet(): TLS handshake lets a client_id host block the event loop
  - High: [GHSA-rpfh-v75p-mp6p](https://github.com/qauth-labs/qauth/security/advisories/GHSA-rpfh-v75p-mp6p) — Deeply nested key_ops in a client JWK blocks the event loop pre-auth
  - High: [GHSA-wwwm-6wr3-qmg5](https://github.com/qauth-labs/qauth/security/advisories/GHSA-wwwm-6wr3-qmg5) — auth-server OOM crash: stalled POSTs to unknown routes skip rate limiting
  - High: [GHSA-x3h3-q45q-qwc7](https://github.com/qauth-labs/qauth/security/advisories/GHSA-x3h3-q45q-qwc7) — Stale consent page can grant newly allowlisted scopes it never showed
  - Medium: [GHSA-2659-cfr9-8m7c](https://github.com/qauth-labs/qauth/security/advisories/GHSA-2659-cfr9-8m7c) — Slow client_id DNS starves all other DNS lookups, blocking CIMD clients
  - Medium: [GHSA-2vrf-hhqc-26w9](https://github.com/qauth-labs/qauth/security/advisories/GHSA-2vrf-hhqc-26w9) — Per-IP failed-login lockout bypass: own-account login resets the counter
  - Medium: [GHSA-3x89-8vq5-mjp9](https://github.com/qauth-labs/qauth/security/advisories/GHSA-3x89-8vq5-mjp9) — refresh_token grant keeps minting scopes removed from the client
  - Medium: [GHSA-45rm-3wwq-cwj3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-45rm-3wwq-cwj3) — CIMD allows non-loopback http redirect URIs, auth codes sent in cleartext
  - Medium: [GHSA-4j52-qf49-36jx](https://github.com/qauth-labs/qauth/security/advisories/GHSA-4j52-qf49-36jx) — Refresh token revocation racing a rotation leaves the new token valid
  - Medium: [GHSA-5vr7-c5hq-ghp6](https://github.com/qauth-labs/qauth/security/advisories/GHSA-5vr7-c5hq-ghp6) — Anyone registering a wallet-only user's email permanently locks them out
  - Medium: [GHSA-67hx-hp5c-gg7j](https://github.com/qauth-labs/qauth/security/advisories/GHSA-67hx-hp5c-gg7j) — SSRF guard treats NAT64 and site-local IPv6 addresses as public
  - Medium: [GHSA-6fqv-hjx9-jgj2](https://github.com/qauth-labs/qauth/security/advisories/GHSA-6fqv-hjx9-jgj2) — zxcvbn l33t matcher blocks event loop for 7 s despite the length cap
  - Medium: [GHSA-6qmv-hg2c-5gwc](https://github.com/qauth-labs/qauth/security/advisories/GHSA-6qmv-hg2c-5gwc) — mcp-guard: junk tokens exhaust shared introspection rate limit (DoS)
  - Medium: [GHSA-6x6v-r7rf-xqgq](https://github.com/qauth-labs/qauth/security/advisories/GHSA-6x6v-r7rf-xqgq) — Wallet sign-in as another holder: binding claims above 2^53 collide
  - Medium: [GHSA-7773-2gx7-gpch](https://github.com/qauth-labs/qauth/security/advisories/GHSA-7773-2gx7-gpch) — private_key_jwt uses stale CIMD row: removed keys accepted, CIMD off ignored
  - Medium: [GHSA-7fxx-3c59-jx98](https://github.com/qauth-labs/qauth/security/advisories/GHSA-7fxx-3c59-jx98) — Argon2 client-secret checks exhaust the thread pool, stalling JWT verification
  - Medium: [GHSA-7hqm-pq5g-m4j4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-7hqm-pq5g-m4j4) — readCookie() trims NBSP, bypassing the __Host- prefix (login CSRF)
  - Medium: [GHSA-7rw4-gmrr-w8w3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-7rw4-gmrr-w8w3) — Consent screen resets session TTL, so stolen sessions never expire
  - Medium: [GHSA-86p7-gc4h-mr29](https://github.com/qauth-labs/qauth/security/advisories/GHSA-86p7-gc4h-mr29) — Status-list fetch crashes auth-server by leaving an error body unread
  - Medium: [GHSA-8hhv-hgc6-x8gp](https://github.com/qauth-labs/qauth/security/advisories/GHSA-8hhv-hgc6-x8gp) — One-time consent yields a refresh token the user cannot list or revoke
  - Medium: [GHSA-8qcr-q895-p5p3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-8qcr-q895-p5p3) — Failed-login lockout race lets concurrent guesses exceed the limit
  - Medium: [GHSA-9xvv-wmw4-rxxw](https://github.com/qauth-labs/qauth/security/advisories/GHSA-9xvv-wmw4-rxxw) — Auth codes still mint refresh tokens after consent revocation or logout
  - Medium: [GHSA-c9jp-4m3g-mfxx](https://github.com/qauth-labs/qauth/security/advisories/GHSA-c9jp-4m3g-mfxx) — Operator-disabled client can be re-enabled by its owner via PATCH
  - Medium: [GHSA-ccg3-88g5-42w3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-ccg3-88g5-42w3) — Explicit-curve keys in Status List Token x5c block the event loop
  - Medium: [GHSA-cmf7-wjxq-4pch](https://github.com/qauth-labs/qauth/security/advisories/GHSA-cmf7-wjxq-4pch) — Unbounded client_id and email let anyone grow audit_logs and Redis
  - Medium: [GHSA-f656-4x94-rwcx](https://github.com/qauth-labs/qauth/security/advisories/GHSA-f656-4x94-rwcx) — Logout accepts any client's token, revoking all the user's refresh tokens
  - Medium: [GHSA-h45w-5rh3-4jfc](https://github.com/qauth-labs/qauth/security/advisories/GHSA-h45w-5rh3-4jfc) — Wallet email marked verified if holder withholds email_verified false
  - Medium: [GHSA-hhf6-7jxh-56mg](https://github.com/qauth-labs/qauth/security/advisories/GHSA-hhf6-7jxh-56mg) — ID-JAG mint via token exchange ignores the agent's scope allowlist
  - Medium: [GHSA-hqvc-gxfj-5jfc](https://github.com/qauth-labs/qauth/security/advisories/GHSA-hqvc-gxfj-5jfc) — Bearer path on OAuth authorize skips consent, even for DCR clients
  - Medium: [GHSA-hr63-jxw4-gwp8](https://github.com/qauth-labs/qauth/security/advisories/GHSA-hr63-jxw4-gwp8) — mcp-guard: child-scope guard accepts tokens for the parent's resource
  - Medium: [GHSA-j6vv-jh87-x5p9](https://github.com/qauth-labs/qauth/security/advisories/GHSA-j6vv-jh87-x5p9) — Race in OAuth authorize: code issued after consent is revoked
  - Medium: [GHSA-m48p-6v3q-gr97](https://github.com/qauth-labs/qauth/security/advisories/GHSA-m48p-6v3q-gr97) — Open redirect via authorize errors for anonymously registered clients
  - Medium: [GHSA-m96q-3554-9vmg](https://github.com/qauth-labs/qauth/security/advisories/GHSA-m96q-3554-9vmg) — Revoked wallet credential's email still emitted as a verified claim
  - Medium: [GHSA-mv5p-wm66-jj74](https://github.com/qauth-labs/qauth/security/advisories/GHSA-mv5p-wm66-jj74) — Token endpoint leaks internal IPs via private_key_jwt failure reasons
  - Medium: [GHSA-qr96-hx7r-rqw5](https://github.com/qauth-labs/qauth/security/advisories/GHSA-qr96-hx7r-rqw5) — OAuth revoke silently ignores refresh tokens hinted as access_token
  - Medium: [GHSA-rwcf-7xw4-vw87](https://github.com/qauth-labs/qauth/security/advisories/GHSA-rwcf-7xw4-vw87) — private_key_jwt and ID-JAG replay: jti TTL short by one clock-skew leeway
  - Medium: [GHSA-vpf6-9vgr-6rj4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-vpf6-9vgr-6rj4) — Consent ignores RFC 8707 resource: client gets tokens for any audience
  - Medium: [GHSA-vv57-g568-5vx9](https://github.com/qauth-labs/qauth/security/advisories/GHSA-vv57-g568-5vx9) — Access tokens and unredeemed auth codes survive grant revocation
  - Medium: [GHSA-vw34-9q55-2vg3](https://github.com/qauth-labs/qauth/security/advisories/GHSA-vw34-9q55-2vg3) — Disabled users keep using existing browser sessions and management tokens
  - Medium: [GHSA-w4jp-r6vp-v3qj](https://github.com/qauth-labs/qauth/security/advisories/GHSA-w4jp-r6vp-v3qj) — Any anchored certificate can sign any status list (revocation bypass)
  - Medium: [GHSA-w5x8-p2qg-mg6f](https://github.com/qauth-labs/qauth/security/advisories/GHSA-w5x8-p2qg-mg6f) — CIMD re-resolution race lets a client undo an operator's disable
  - Low: [GHSA-2rcm-rp7j-h3xf](https://github.com/qauth-labs/qauth/security/advisories/GHSA-2rcm-rp7j-h3xf) — Account enumeration via 409 on registration, contrary to threat model
  - Low: [GHSA-4g89-vhr5-8r96](https://github.com/qauth-labs/qauth/security/advisories/GHSA-4g89-vhr5-8r96) — Logout does not end browser session; old cookie still gets new tokens
  - Low: [GHSA-8gmh-6wp5-xxv6](https://github.com/qauth-labs/qauth/security/advisories/GHSA-8gmh-6wp5-xxv6) — Hosted login page: content spoofing via the error query parameter
  - Low: [GHSA-935x-3jwv-755g](https://github.com/qauth-labs/qauth/security/advisories/GHSA-935x-3jwv-755g) — Unknown key_storage entry lets a basic grade pass the haip-1.0 floor
  - Low: [GHSA-c46j-f88j-9hcf](https://github.com/qauth-labs/qauth/security/advisories/GHSA-c46j-f88j-9hcf) — Email verification password check skips failed-login lockout
  - Low: [GHSA-chc6-vw6m-mr8h](https://github.com/qauth-labs/qauth/security/advisories/GHSA-chc6-vw6m-mr8h) — Account enumeration via wallet login: unknown identifiers are enrolled
  - Low: [GHSA-g6cw-g5qq-2pqp](https://github.com/qauth-labs/qauth/security/advisories/GHSA-g6cw-g5qq-2pqp) — Race in resend-verification interval check allows email enumeration
  - Low: [GHSA-p97w-p94p-4f8v](https://github.com/qauth-labs/qauth/security/advisories/GHSA-p97w-p94p-4f8v) — authorization_code grant ignores max_agent_mode lowered after consent
  - Low: [GHSA-prxf-g4px-38hw](https://github.com/qauth-labs/qauth/security/advisories/GHSA-prxf-g4px-38hw) — Account enumeration via login timing once Argon2id jobs queue up
  - Low: [GHSA-rg3w-mqm8-m8x8](https://github.com/qauth-labs/qauth/security/advisories/GHSA-rg3w-mqm8-m8x8) — Access tokens leak user email to clients without the email scope
  - Low: [GHSA-rjh9-w9rr-vxw4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-rjh9-w9rr-vxw4) — Client registration accepts javascript: and data: redirect URIs
  - Low: [GHSA-rrw7-9pwv-vxm6](https://github.com/qauth-labs/qauth/security/advisories/GHSA-rrw7-9pwv-vxm6) — Duplicate registration logs password hash via Drizzle SQL params
  - Low: [GHSA-w26w-8h69-7h5w](https://github.com/qauth-labs/qauth/security/advisories/GHSA-w26w-8h69-7h5w) — Wallet login DoS: pinned but untrusted issuer trips status-list breaker
  - Low: [GHSA-wx9c-x6qf-24jr](https://github.com/qauth-labs/qauth/security/advisories/GHSA-wx9c-x6qf-24jr) — Timing-based email enumeration in resend-verification via slow mail send
  - Low: [GHSA-xh4j-6p3v-qqw4](https://github.com/qauth-labs/qauth/security/advisories/GHSA-xh4j-6p3v-qqw4) — Skipped key attestation stating basic storage still clears haip-1.0 floor
- **BREAKING, from the other advisory fixes** (each advisory has the detail):
  - Consent now covers RFC 8707 resources: an existing consent asks once more
    for a request that names a `resource`. Migration 0021 adds
    `oauth_consents.resource_scopes`.
  - The `/oauth/authorize` Bearer path needs a consent that covers the
    request, and `unauthorized_client` is answered with HTTP 400.
  - A one-time approval no longer gets a refresh token, and a refresh into a
    scope the client no longer has is refused.
  - `SESSION_COOKIE_TTL` is an absolute lifetime, and logout ends the
    user's hosted browser sessions.
  - `http://` redirect URIs to a host that is not a loopback address are
    refused in every environment.
  - `private_key_jwt` failures carry no `error_description`.
  - Requests are refused that carry URIs with raw Unicode or spaces, URIs or
    `client_id`s over 2048 characters, email addresses over 254 characters,
    or a `max_age` that is not all digits.
  - A wallet email counts as verified only with a disclosed
    `email_verified: true`, or when its issuer is in
    `OID4VP_EMAIL_VERIFYING_ISSUERS`. Migration 0022 adds
    `user_attributes.provenance`.
  - A status list served from another host needs a matching SAN or an entry
    in `OID4VP_STATUS_LIST_SIGNERS`.
  - `haip-1.0` grades key storage more strictly, and DSA and DH keys in
    `x5c` are refused.
  - Two `mcp-guard` instances registered on one plugin scope no longer boot.
- **New configuration from the advisory fixes**: `MAX_CLIENTS_PER_DEVELOPER`
  (default 100), `REQUEST_TIMEOUT_MS` (default 60000),
  `OID4VP_EMAIL_VERIFYING_ISSUERS` and `OID4VP_STATUS_LIST_SIGNERS` (both
  unset), and `mcp-guard`'s `introspectionLocalCheck` option (default `true`).
- **BREAKING**: `/oauth/authorize` and `GET /ui/consent` redirect an
  authorization error automatically only to a client an operator provisioned
  (RFC 9700 §4.11.2, ANT-2026-O8U3P920). Every other client, including one a
  developer account creates through `POST /api/clients`, gets the error on an
  issuer page (HTTP 400) with a link to its redirect URI. Migration 0023 adds
  `oauth_clients.provisioned_by_operator` (default `false`) and sets it for the
  system client and the clients the seed scripts created; the
  `db:seed-oauth-clients` manifest sets it on create and on `--rotate`. An
  owner who changes the redirect URIs of a marked client loses the marker.
  OIDF conformance `prompt=none` modules need an operator-provisioned client
  (see `docs/oidf-op-certification-runbook.md`).
- **Operator suspension separate from `enabled`** (ANT-2026-DR5XI3LV).
  `oauth_clients.enabled` is the client owner's switch again:
  `PATCH /api/clients/{id}` may set it either way (it no longer answers `403`
  to `"enabled": true`). An operator keeps a client off with the new
  `oauth_clients.suspended` / `suspended_at` (migration 0023), which no route
  writes and a CIMD re-resolution never touches; a suspended client is refused
  wherever a disabled one is, with the same error. New operator tooling:
  `pnpm nx run infra-db:db:suspend-oauth-client -- --realm=<name>
--client-id=<client_id> [--lift]`. The management API returns a read-only
  `suspended` field. **Upgrade note**: migration 0023 suspends every client that
  is disabled when it runs; one its owner had disabled stays off until an
  operator lifts the suspension, after which the owner re-enables it.
- **BREAKING**: a Client ID Metadata Document is refused whole when any of its
  `redirect_uris` fails the check Dynamic Client Registration applies
  (ANT-2026-D0XJAT8S follow-up). Such URIs were dropped and the rest accepted;
  now the client does not resolve (`invalid_client` at `/oauth/authorize` and
  `/oauth/token`), including a client already in use whose document lists one.
- **BREAKING**: redirect URIs are limited to `https`, `http` to a loopback host,
  and RFC 8252 §7.1 private-use schemes (a reverse domain name such as
  `com.example.app:/callback`). Dynamic Client Registration,
  `POST /api/clients` (create and update) and CIMD documents refuse any other
  scheme, including `javascript:`, `data:`, `file:` and schemes without a period
  such as `myapp:`, with `invalid_redirect_uri`. `/oauth/authorize` and the
  consent screen refuse such a URI on a client stored earlier
  (`redirect_uri not permitted for this environment`). Re-register a native
  app that used a scheme without a period under a reverse-domain scheme.

[Unreleased]: https://github.com/qauth-labs/qauth/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/qauth-labs/qauth/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/qauth-labs/qauth/releases/tag/v0.1.0
