# Changelog

All notable changes to QAuth are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Wallet federation (T4, [ADR-004](./docs/adr/004-wallet-agnostic-federation.md)) —
  browser wallet sign-in.** QAuth can now generate an OID4VP 1.0 authorization
  request, take back a `direct_post` response, validate an SD-JWT VC presentation,
  resolve or enrol the account, and mint a session — a complete browser sign-in.
  Covered end-to-end against a mock wallet: first-time enrolment, returning login,
  the ADR-009 §1 takeover attempt, untrusted-issuer refusal, account linking, and
  `acr` presence/absence.

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

- **BREAKING**: ID tokens now release `email`/`email_verified` only when the
  granted scope includes `email`, matching the userinfo endpoint's gating
  (OIDC Core §5.4 data minimization). Clients requesting only `openid` no
  longer receive the user's email in the ID token — request the `email`
  scope. Access-token convenience claims and userinfo behavior are
  unchanged. ([#259])

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
  previous release (the last one containing the `db:backfill-identity`
  target — pin to the concrete release tag once releases are cut), run its
  backfill runbook (`--refresh`, then `--verify-only`; both exit 0), then
  upgrade to this release. Note: that script's help says `--refresh` is
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
