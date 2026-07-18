# Changelog

All notable changes to QAuth are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
