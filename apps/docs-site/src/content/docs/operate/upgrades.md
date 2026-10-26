---
title: Upgrades
description: How to upgrade QAuth — back up the database, run the new version's migration runner, start the new version — and the history of migration 0011, the destructive ADR-002 identity migration.
sidebar:
  order: 7
lastVerified: '2026-10-25'
---

Every upgrade takes the same three steps: back up the database, run the new
version's migration runner, then start the new version. Migrations only go
forward and downgrades are not supported, so the backup is your only way back
([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)).

## Upgrade procedure

### 1. Back up the database

```bash
# Adjust host, container and credentials to your deployment.
docker exec qauth-postgres pg_dump -U qauth -d qauth -F c -f /tmp/qauth-pre-upgrade.dump
docker cp qauth-postgres:/tmp/qauth-pre-upgrade.dump ./qauth-pre-upgrade.dump
```

Confirm the dump is not empty. Restoring it later discards every write made
after it was taken.

### 2. Run the migration runner of the new version

The runner is the `migration-runner` image built from
`apps/migration-runner/Dockerfile`. Each release also publishes it, signed, as
`ghcr.io/qauth-labs/qauth/migration-runner` (see
[Published images](/operate/images/)). It holds Node and one program, with the
new version's migrations beside it, and needs only `DATABASE_URL`:

```bash
# Docker Compose: build the new version's image, then run it once.
docker compose build migration-runner
docker compose run --rm migration-runner

# Any other platform: run the image as a one-off job.
docker run --rm -e DATABASE_URL='postgresql://qauth:…@db:5432/qauth' qauth/migration-runner

# From a checkout of the new version, with pnpm installed.
pnpm nx run migration-runner:migrate
```

It applies every pending migration in one transaction and logs each with its
duration:

```text
Applying 2 migrations in one transaction: 0034_webauthn_rp_id_lock, 0035_event_deliveries.
  0034_webauthn_rp_id_lock ran in 14 ms
  0035_event_deliveries ran in 34 ms
Applied 2 migrations in 212 ms. The database is current.
```

It is safe to run twice. A run on a current database prints
`The database is current: all 36 migrations are applied. Nothing to do.` and
exits `0`. The runner holds a Postgres advisory lock while it works, so a second
runner started beside it, for example by every node of a cluster at once, waits
for the first, then finds nothing to do.

| Exit code | Meaning                                                                                                                                             |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`       | The database is current: the run applied the pending migrations, or there were none.                                                                |
| `1`       | A migration failed. The error names it, and the whole run rolled back: no migration of the run was applied. With `--check`: migrations are pending. |
| `2`       | Usage error: an unknown flag, or `DATABASE_URL` is not set.                                                                                         |
| `3`       | The run could not start: the database is unreachable, or the migrations folder cannot be read.                                                      |

`--check` reports the pending migrations and changes nothing: it takes no lock
and creates nothing, so a read-only database role can run it.

```bash
docker compose run --rm migration-runner --check
```

```text
The database lacks 1 of 36 migrations: 0035_event_deliveries. Run the migration runner without --check to apply them.
```

A failed run changed nothing. Fix the cause the error names, then run the
runner again.

### 3. Start the new version

```bash
docker compose up -d auth-server
```

At boot the auth server compares the database with the migrations of its own
release. When the database lacks some, the server waits for the migration
runner, up to `DB_MIGRATION_WAIT_MS` (60 seconds by default, `0` to check once),
then exits non-zero with a message that names the missing migrations:

```text
The database lacks 1 migration this release needs: 0035_event_deliveries. Waited 60 s for the migration runner. Run it against this database, then start the server again.
```

So a server started beside the runner, as a platform without job ordering
does, waits for it instead of failing on a missing table.

A database **ahead** of the release does not stop the server: during a rolling
upgrade the old version keeps running on the new schema for a short time. The
server logs a warning with the number of newer migrations and starts.

### Release notes that need more than these steps

Read the release's `CHANGELOG.md` entry before you upgrade. One migration in
QAuth's history needs more: migration 0011, below.

### Users sign in once more after the upgrade to v0.2

From v0.2 the auth server keeps browser sessions in Postgres, with Redis as a
cache in front of them
([ADR-019 Decision 3](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)).
The upgrade does not move the sessions an earlier version kept in Redis. A user
who was signed in to the hosted pages (`/ui/login`, the consent screen, wallet
sign-in) is asked to sign in once more. A consent screen open during the
upgrade is refused when it is submitted and shown again after that sign-in.

Nothing else is lost. Access tokens, refresh tokens and stored consents are
untouched, so an application that already holds tokens keeps working without
the user. The old Redis session keys (`session:<id>`) are no longer read and
expire on their own within `SESSION_COOKIE_TTL`; there is nothing to delete.

During a rolling upgrade, a sign-in served by a node of the old version is not
seen by a node of the new version, so a user can be asked to sign in twice
until the last old node is gone.

### The developer portal's token: the new audience is accepted first

The developer portal's token moves to the developer API's audience,
`urn:qauth:aud:developer:v1-rc.0`, in two releases, expand then contract
(ADR-018 §5; [#509](https://github.com/qauth-labs/qauth/issues/509),
[API conventions](/reference/api-conventions/#issuing-a-family-audience)):

- **v0.2 accepts it.** `/api/clients`, `/api/consents`, `/auth/logout`, the
  Bearer path of `/oauth/authorize` and userinfo accept a system-client token
  whose `aud` is the developer audience, beside today's token, whose `aud` is
  the system client's id. Nothing mints the new token yet: `POST /auth/login`
  still mints today's, and the system client's row is not changed.
- **A later release mints it** ([#524](https://github.com/qauth-labs/qauth/issues/524)).
  Every v0.2 node accepts the tokens such a node mints.

The upgrade to v0.2 is safe to roll: a node of the previous release accepts
every portal token a v0.2 node mints, because it is the same token. There is no
migration and nothing to run. Upgrade every node to v0.2 before the release
that mints the new token, so no node that refuses it is left.

### Refresh tokens pause while migration 0038 runs

Migration 0038 ([#552](https://github.com/qauth-labs/qauth/issues/552)) records
when each refresh-token family started. It fills the new column for every row
of `refresh_tokens` in one statement, inside the runner's transaction. Before
anything else it locks `authorization_codes` and then `refresh_tokens`, the
order a code redemption takes them in, and holds both until that transaction
commits. While the runner works, every request that reads or writes a refresh
token or an authorization code waits: a code exchange, a refresh,
`POST /auth/login`, minting a code at `/oauth/authorize` or on the consent
screen, and the purge job. Nothing fails; those requests finish once the runner
does, unless your proxy or client gives up first. A database that ran 0038 from
`main` before its locks moved to the start is unaffected: the change only
reorders its locks, and the runner never runs a migration twice.

The pause grows with the number of rows in `refresh_tokens`, rotated and
revoked tokens included. Measured on a 12-vCPU AMD EPYC virtual machine with
47 GB of memory, against a `postgres:18-alpine` container on its default
settings (`shared_buffers` 128 MB, `max_wal_size` 1 GB), with five tokens per
family:

| Rows in `refresh_tokens` | Table size | Whole migration | A token insert waited |
| ------------------------ | ---------- | --------------- | --------------------- |
| 100,000                  | 58 MB      | 5.7 s           | 4.7 s                 |
| 1,000,000                | 588 MB     | 100 s           | 99.8 s                |

Almost all of it is the `UPDATE` (5.5 s and 98.4 s). Taking the locks first
adds no work, so these figures, measured before the locks moved, still hold;
minting a code now waits as long as a token insert. These were default
settings; more `shared_buffers` and a larger `max_wal_size` may shorten the
pause, which we have not measured. To estimate your own, count first:

```sql
SELECT count(*) FROM refresh_tokens;
```

With many rows, run the migration at a quiet hour, and keep the proxy's and
the clients' timeouts above the expected pause.

Migrations 0038 and 0041 both take their locks in a redemption's order: a
redemption spends its code in `authorization_codes`, then stores the refresh
token it buys. So a redemption in flight during the upgrade, on a node of either
version, waits for the runner instead of deadlocking with it.

### Migration 0041 reads `refresh_tokens` once more

Migration 0041 ([#627](https://github.com/qauth-labs/qauth/issues/627)) links
each refresh-token family to the authorization code that started it. It adds a
column that starts empty, so it rewrites no row, but its foreign key and index
each read the whole table while the runner holds the lock 0038 described. It
first locks `authorization_codes` against writes, then `refresh_tokens`, in the
order a redemption takes them, so it cannot deadlock with one. So minting a
code at `/oauth/authorize` or on the consent screen, redeeming one at
`/oauth/token` and a logout wait until the runner commits, on nodes of either
version. On the same virtual machine, against a `postgres:18-alpine` container
with 1,000,000 rows in `refresh_tokens` (531 MB), it took 1.3 s, and a token
insert waited for it. Upgrading from a release before 0038 runs 0038 and 0041
in the one transaction, so the two pauses add up.

The same release records each access token it issues from a code or a refresh
family in Redis, so that a replay can deny-list them. It sets those records'
lifetimes with `EXPIRE` and its `NX` and `GT` options, which need **Redis 7.0
or later**. The bundled Compose file runs Redis 7; check the version of a Redis
you run yourself.

### Admin scopes and the admin audience need an admin grant

From this release the token endpoint issues a `qauth:admin:*` scope only to an
account that holds an admin grant reaching that scope's class, through a client
that lists the admin API's audience, and the admin audience only to an account
that holds an admin grant ([#510](https://github.com/qauth-labs/qauth/issues/510)).
A `client_credentials` token gets neither, and neither do the ID-JAG grants. Migration 0042 only adds the empty
`admin_grants` and `admin_roles` tables. No admin route ships in this release,
so nothing that works today stops working; before you use the admin API, give
each account that will use it a grant. During a rolling upgrade a node of the
previous release still issues those scopes without the check, which reaches no
route either.

## Upgrading within 1.x

:::caution[Back up first]
Take the backup of [step 1](#1-back-up-the-database) before every upgrade.
Downgrades are not supported, within 1.x or otherwise: restoring the backup is
the only way back.
:::

This section is a stub until 1.0 ships. From 1.0 on, ADR-018 §5 promises:

- An upgrade within 1.x is the three steps above and nothing else: back up, run
  the new version's migration runner, start the new version.
- No 1.x migration is destructive. None drops or renames a table or column,
  narrows a column's type or deletes rows. A change of shape adds the new form
  beside the old one, so the previous version keeps working on the new schema
  while a rolling upgrade replaces its nodes.
- CI tests an upgrade from every earlier 1.x minor release.

That test runs today, before 1.0, from each release listed in
`upgrade-baselines.json` at the repository root. It starts the release, writes
data through its HTTP API, runs this version's migration runner and nothing
else, and starts this version. Then it checks that tokens issued before the
upgrade still introspect, the refresh token rotates, consents and API keys are
still there, and passwords still sign in. It then starts the old release again
on the migrated database and runs the same smoke tests. Until the 1.0 release
candidate, a failure of that last check is reported but does not fail CI.

## History: the migration 0011 runbook (ADR-002)

This runbook predates the migration runner: where it says
`pnpm nx run infra-db:db:migrate` or `drizzle-kit migrate`, run the migration
runner of Step 2 above. A failed migration is reported the same way, by name,
and rolls back.

QAuth's history contains one **destructive** schema migration you must plan
around: migration **0011** (ADR-002, issue [#230]), which permanently drops
`users.email`, `users.email_normalized`, and `users.password_hash`. Skipping
its precondition doesn't just fail the migration — it can **silently** strip
`email`/`email_verified` claims from existing users, including users whose
email was verified, without an error anywhere.

This section restates the runbook from `CHANGELOG.md`'s `[Unreleased]` section
of the time as an ordered procedure. **`CHANGELOG.md` is the source of record** — if the two
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

### Which path applies to you

| Your current deployment                                                                                                    | Path                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Already running a release at or after the #228/#229 dual-write cutover, not yet past #230 (migration 0011 not yet applied) | **One-hop** — go to [Step 3](#step-3-run-the-backfill-verification)                                                                             |
| Running anything older (pre-#228), or unsure                                                                               | **Two-hop** — go to [Step 1](#step-1-the-two-hop-precondition-pre-229-deployments-only)                                                         |
| A fresh install with no existing users                                                                                     | Migrations apply cleanly with no data to guard; skip to [Step 4](#step-4-back-up-the-database) as a formality, or just run the migration runner |

If you don't know which release you're running, check whether
`pnpm nx run infra-db:db:backfill-identity` exists as a target in your
deployed checkout's `libs/infra/db/project.json`. If it does, you're on the
dual-write release — one-hop. If it doesn't (as on current `main`, see below),
and you haven't already applied migration 0011, you need the two-hop path.

### Step 1: the two-hop precondition (pre-#229 deployments only)

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
   before `29abe4a` (#230, "drop legacy users identity columns").

   **Build `00c23f04`** unless you have a reason not to. It is the immediate
   parent of `29abe4a` — the newest state of `main` that still carries the
   backfill tool and migration 0010's dual-write behaviour, and does not yet
   carry migration 0011. Verify what you checked out before deploying it:

   ```bash
   git show 00c23f04:libs/infra/db/project.json | grep backfill-identity   # must match
   git ls-tree 00c23f04 libs/infra/db/drizzle | grep 0011                  # must be EMPTY
   ```

   **No release tag names this commit** — giving the hop a pinnable tag is
   tracked in [#362](https://github.com/qauth-labs/qauth/issues/362). Until
   then a SHA is the only precise instrument available, which is why this page
   gives you one rather than a tag that would be wrong.

   :::danger[`v0.1.0-rc.0` is not a safe starting point]
   The repository's first tag, `v0.1.0-rc.0` (2026-07-25), **postdates**
   migration 0011 and already contains the destructive drop, as every later
   release does. Deploying it as
   the "previous release" of a two-hop upgrade applies 0011 to a database that
   was never backfilled — which is the failure this whole page exists to
   prevent. Confirm for yourself with
   `git ls-tree v0.1.0-rc.0 libs/infra/db/drizzle | grep 0011`.
   :::

2. Run the [Step 3](#step-3-run-the-backfill-verification) backfill against
   that deployment.
3. Only then continue upgrading, release by release, until you reach the
   target release containing migration 0011.

Skip this step entirely if you're already on a release at or after the
dual-write cutover (#228/#229) and haven't applied migration 0011 yet — go
straight to Step 3.

### Step 2: understand the dual-write window (context, no action)

The release between #228 and #230 **dual-writes**: it writes both the legacy
`users.email`/`password_hash` columns and the new `user_credentials` /
`user_attributes` tables in the same transactions, so the two stay in sync.
This is why the CHANGELOG notes that `--refresh` is safe on that release even
though the backfill tool's own `--help` text calls `--refresh`
"PRE-CUTOVER ONLY" — the warning is about running `--refresh` against an
**older**, non-dual-writing release, where it would overwrite already-correct
rows with stale legacy-column data. On the dual-write release itself, the two
sources are equal by construction, so refreshing is a no-op-safe reconciliation.

### Step 3: run the backfill verification

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

### Step 4: back up the database

Immediately before running the migration. This is your only undo (see the
warning at the top of this page).

```bash
# Adjust host/container/credentials to your deployment.
docker exec qauth-postgres pg_dump -U qauth -d qauth -F c -f /tmp/qauth-pre-0011.dump
docker cp qauth-postgres:/tmp/qauth-pre-0011.dump ./qauth-pre-0011.dump
```

Confirm the dump file is non-empty and, if you can afford the time, that it
restores cleanly to a scratch database before proceeding.

### Step 5: optional — preflight the migration's own guard

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

### Step 6: apply migration 0011, before starting the new release

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

### Step 7: minor operational consequences to expect

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

### Step 8: migration 0012 (no precondition, any time after 0011)

A later migration drops two more columns —
`users.email_verified` / `users.email_verified_at`
(`libs/infra/db/drizzle/0012_flat_morlocks.sql`) — but **needs no guard and no
special ordering**. They've had no writers since migration 0011 (verified
state has lived in `user_credentials.credential_data.email_verified` /
`user_attributes.verified` since then), and their one sanctioned reader was a
literal default value, not a real read. Apply it whenever you apply the rest
of that release's migrations — nothing to sequence around.

### Verify after applying 0011

- `pnpm nx run infra-db:db:migrate` exits 0 and the migration log shows 0011
  (and 0012, if applicable) applied.
- Log in as an existing user with a previously-verified email, through a
  client granted the `email` scope, and confirm `email`/`email_verified` are
  present in the ID token, the userinfo response and the access token — this is
  the concrete symptom of a skipped backfill, so check it explicitly rather than
  assuming Step 3 worked. Without the `email` scope all three omit the claims
  by design.
- Spot-check a user created before #228 for the normalized-email cosmetic
  change (Step 7) so it doesn't get reported as a bug later.

## See also

- [Docker](/operate/docker/) — the `migration-runner` service; its
  Troubleshooting section points back here for a migration 0011 failure.
- [Configuration](/operate/configuration/) — `DB_MIGRATION_WAIT_MS`, the auth
  server's wait for missing migrations at boot.
- [Keys](/operate/keys/) — unrelated to migrations, but worth checking while
  you have the deployment open for maintenance.
