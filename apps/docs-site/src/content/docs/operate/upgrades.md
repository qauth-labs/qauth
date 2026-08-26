---
title: Upgrades
description: The ADR-002 identity-migration runbook — the destructive schema change that drops users.email/email_normalized/password_hash, its required backfill precondition, and why there is no rollback.
sidebar:
  order: 7
lastVerified: '2026-07-27'
---

QAuth's history contains one **destructive** schema migration you must plan
around: migration **0011** (ADR-002, issue [#230]), which permanently drops
`users.email`, `users.email_normalized`, and `users.password_hash`. Skipping
its precondition doesn't just fail the migration — it can **silently** strip
`email`/`email_verified` claims from existing users, including users whose
email was verified, without an error anywhere.

This page restates the runbook from `CHANGELOG.md`'s `[Unreleased]` section as
an ordered procedure. **`CHANGELOG.md` is the source of record** — if the two
disagree, trust the CHANGELOG and the migration files in
`libs/infra/db/drizzle/`, and file an issue against this page.

[#230]: https://github.com/qauth-labs/qauth/issues/230

> **⚠️ No rollback after migration 0011.** Migration 0011 **drops columns**.
> Dropped columns cannot be reconstructed — password hashes are unrecoverable
> by design, and once `users.email` is gone there is no way to get it back
> from inside the database. **A full database backup taken immediately before
> running the migration is the only undo.** Restoring it discards every write
> made after the backup. Take the backup before Step 4 below, not after
> something looks wrong.

## Which path applies to you

| Your current deployment                                                                                                    | Path                                                                                                                                    |
| -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Already running a release at or after the #228/#229 dual-write cutover, not yet past #230 (migration 0011 not yet applied) | **One-hop** — go to [Step 3](#step-3-run-the-backfill-verification)                                                                     |
| Running anything older (pre-#228), or unsure                                                                               | **Two-hop** — go to [Step 1](#step-1-the-two-hop-precondition-pre-229-deployments-only)                                                 |
| A fresh install with no existing users                                                                                     | Migrations apply cleanly with no data to guard; skip to [Step 4](#step-4-back-up-the-database) as a formality, or just run `db:migrate` |

If you don't know which release you're running, check whether
`pnpm nx run infra-db:db:backfill-identity` exists as a target in your
deployed checkout's `libs/infra/db/project.json`. If it does, you're on the
dual-write release — one-hop. If it doesn't (as on current `main`, see below),
and you haven't already applied migration 0011, you need the two-hop path.

## Step 1: the two-hop precondition (pre-#229 deployments only)

**The backfill tooling has been deleted from the tree.** `db:backfill-identity`
(the nx target, `libs/infra/db/src/scripts/backfill-identity.ts`, and its
implementation under `libs/infra/db/src/lib/backfill/`) was added in #226 and
**removed** in the same commit that added migration 0011
(`29abe4a`, closing #230) — the CHANGELOG entry for that removal reads "#226
backfill machinery retired (git history is the archive...)". Current `main`
has no `db:backfill-identity` target at all — verify with
`pnpm nx show project infra-db --json | grep backfill` against your checkout.

This is what actually **gates** the two-hop path: it is not a runtime guard,
it is that the tool you need has already been deleted from anything at or
after migration 0011. If you're upgrading from before the #228/#229 dual-write
cutover, you cannot get the backfill tool by deploying current `main` — you
must:

1. Deploy a build from the commit range that has the backfill target: at or
   after `62886c9` (#226, "add idempotent ADR-002 identity backfill") and
   before `29abe4a` (#230, "drop legacy users identity columns"). At the time
   of writing no tagged release pins this window — identify the commit your
   deploy pipeline can build from, or ask in the tracking issue if you land
   here and none exists yet.
2. Run the [Step 3](#step-3-run-the-backfill-verification) backfill against
   that deployment.
3. Only then continue upgrading, release by release, until you reach the
   target release containing migration 0011.

Skip this step entirely if you're already on a release at or after the
dual-write cutover (#228/#229) and haven't applied migration 0011 yet — go
straight to Step 3.

## Step 2: understand the dual-write window (context, no action)

The release between #228 and #230 **dual-writes**: it writes both the legacy
`users.email`/`password_hash` columns and the new `user_credentials` /
`user_attributes` tables in the same transactions, so the two stay in sync.
This is why the CHANGELOG notes that `--refresh` is safe on that release even
though the backfill tool's own `--help` text calls `--refresh`
"PRE-CUTOVER ONLY" — the warning is about running `--refresh` against an
**older**, non-dual-writing release, where it would overwrite already-correct
rows with stale legacy-column data. On the dual-write release itself, the two
sources are equal by construction, so refreshing is a no-op-safe reconciliation.

## Step 3: run the backfill verification

Run this against the dual-write release (#228/#229) — either the one you're
already on (one-hop), or the intermediate one you deployed in Step 1 (two-hop):

```bash
pnpm nx run infra-db:db:backfill-identity -- --refresh
pnpm nx run infra-db:db:backfill-identity -- --verify-only
```

**Both commands must exit `0`.** `--verify-only` confirms every user has a
`(self_reported, email)` `user_attributes` row (among the other identity
rows the backfill populates).

**If `--verify-only` exits non-zero:** do not proceed. Something did not
backfill cleanly — re-run `--refresh` and `--verify-only` again; if it still
fails, this is a data problem to resolve before touching schema, not something
migration 0011's guard will explain further (its guard message is deliberately
terser — see Step 5).

**Why this matters, concretely:** without a clean backfill, existing users —
**including users with a verified email** — silently lose their `email` and
`email_verified` claims on token, refresh, and userinfo responses once you're
past migration 0011. There is no error at request time; the claims are simply
absent, because claim resolution reads exclusively from `user_attributes`
after ADR-002, and nothing populates that table except this backfill (or
normal post-cutover writes). This is the reason this page exists — do not
skip this step because the app "seems to still work" after upgrading. It will
appear to work until a user's client asks for their email.

## Step 4: back up the database

Immediately before running the migration. This is your only undo (see the
warning at the top of this page).

```bash
# Adjust host/container/credentials to your deployment.
docker exec qauth-postgres pg_dump -U qauth -d qauth -F c -f /tmp/qauth-pre-0011.dump
docker cp qauth-postgres:/tmp/qauth-pre-0011.dump ./qauth-pre-0011.dump
```

Confirm the dump file is non-empty and, if you can afford the time, that it
restores cleanly to a scratch database before proceeding.

## Step 5: optional — preflight the migration's own guard

Migration 0011 opens with an in-SQL guard (`libs/infra/db/drizzle/0011_striped_brother_voodoo.sql`)
that runs **before any DDL** in the same file and **aborts the entire
migration atomically** — zero schema changes applied — if it finds:

- any user with a `password_hash` but no matching `user_credentials` row
  (`provider_type = 'password'`), or
- any user with an `email` but no `user_credentials` row at all.

You can run the same two checks yourself first, without touching schema:

```sql
SELECT count(*) FROM users u
WHERE u.password_hash IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM user_credentials uc
    WHERE uc.user_id = u.id AND uc.provider_type = 'password'
  );

SELECT count(*) FROM users u
WHERE u.email IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM user_credentials uc WHERE uc.user_id = u.id
  );
```

Both should return `0`. If either doesn't, **stop** — go back to Step 3; the
migration will abort with the same finding, but finding it here costs you
nothing (this is a read-only `SELECT`, not a migration attempt).

If the guard fires anyway when you run the real migration, the error message
names the count of affected users on each side and tells you to re-run the
Step 3 backfill runbook. **No data is modified when the guard fires** — the
whole file rolls back (drizzle-kit runs each migration file in a transaction),
so it's safe to fix the underlying data and simply retry.

## Step 6: apply migration 0011, before starting the new release

```bash
pnpm nx run infra-db:db:migrate
```

**Ordering matters and is asymmetric.** Apply this migration **before**
starting any instance of the release that expects it — the new binary writes
only the ADR-002 tables (`user_credentials` / `user_attributes`), not the
legacy columns, so an old-schema database fed new-binary traffic accumulates
writes the still-there legacy columns won't reflect. Unlike the direction
above (guarded by migration 0011's own precheck), **this direction has no
in-SQL guard** — nothing stops you from starting the new binary against an
unmigrated database. Sequence your rollout so the migration completes first.

**What you'll see on success:** the migration applies, in this order (reading
straight from `0011_striped_brother_voodoo.sql`):

- `email_verification_tokens` drops its `email_verification_tokens_user_id_users_id_fk`
  foreign-key constraint (the column it references is dropped last, below).
- Four indexes on the legacy columns are dropped:
  `idx_users_realm_email_normalized_unique`, `idx_users_email`,
  `idx_users_realm_email_enabled`, `idx_email_verification_tokens_user_id`.
- `email_verification_tokens.credential_id` is promoted to `NOT NULL`.
- `users.email` is dropped.
- `users.email_normalized` is dropped.
- `users.password_hash` is dropped.
- `email_verification_tokens.user_id` is dropped.

Plus a `NOTICE` if any in-flight email-verification tokens were deleted — see
[Step 7](#step-7-minor-operational-consequences-to-expect) below.

**What you'll see on the guard firing:** a `RAISE EXCEPTION` naming the two
counts above and telling you to deploy the backfill release and re-run
Step 3. `drizzle-kit migrate` reports this as a failed migration; nothing was
applied. Go fix Step 3, then re-run this step.

## Step 7: minor operational consequences to expect

Neither of these blocks the migration; both are one-time and self-healing:

- **In-flight email-verification tokens.** Migration 0011 first re-points any
  verification token minted without a `credential_id` at the user's password
  credential (an idempotent re-run of the #228 backfill), then deletes
  whatever remains unresolvable. An affected user's outstanding verification
  link stops working; they click "resend" once and get a new one. Nothing to
  action operationally — just don't be surprised by a small number of deleted
  rows in the migration's `NOTICE` output.
- **Normalized-case email in old UI strings.** For accounts created before
  #228, a few user-visible strings (the register response, the consent-screen
  address, log lines) switch from the original-case email to its normalized
  lowercase form, because the original-case string lived in the now-dropped
  `users.email` column and only the normalized form survives in
  `user_credentials`. Cosmetic only — sign-in and claim resolution are
  unaffected (email matching was always case-insensitive).

## Step 8: migration 0012 (no precondition, any time after 0011)

A later migration drops two more columns —
`users.email_verified` / `users.email_verified_at`
(`libs/infra/db/drizzle/0012_flat_morlocks.sql`) — but **needs no guard and no
special ordering**. They've had no writers since migration 0011 (verified
state has lived in `user_credentials.credential_data.email_verified` /
`user_attributes.verified` since then), and their one sanctioned reader was a
literal default value, not a real read. Apply it whenever you apply the rest
of that release's migrations — nothing to sequence around.

## Verify after upgrading

- `pnpm nx run infra-db:db:migrate` exits 0 and the migration log shows 0011
  (and 0012, if applicable) applied.
- Log in as an existing user with a previously-verified email and confirm
  `email`/`email_verified` are present in the ID token, userinfo response, and
  access-token convenience claims — this is the concrete symptom of a skipped
  backfill, so check it explicitly rather than assuming Step 3 worked.
- Spot-check a user created before #228 for the normalized-email cosmetic
  change (Step 7) so it doesn't get reported as a bug later.

## See also

- [Docker](/operate/docker/) — running `migration-runner`; its Troubleshooting
  section points back here for a migration 0011 failure.
- [Keys](/operate/keys/) — unrelated to this migration, but worth checking
  while you have the deployment open for maintenance.
