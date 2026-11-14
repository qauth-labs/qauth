---
title: Migration policy
description: How a schema change reaches the database without breaking an upgrade — expand first, then switch the code, and within 1.x never drop anything — and the CI check that holds every new migration to it.
sidebar:
  order: 9
lastVerified: '2026-11-14'
---

[ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/#5-the-stability-contract)
promises three things about upgrades within 1.x. Migrations only go forward. Every upgrade
completes by running the migration runner, with no manual step. No 1.x migration is destructive:
none drops or renames a table or column, narrows a column's type or deletes rows.

During a rolling upgrade the previous release keeps running on the new schema until its last node
is replaced, and the [upgrade test](/operate/upgrades/#upgrading-within-1x) starts it again on the
migrated database. So a migration must leave everything the previous release reads and writes in
place. This page says how to write one, and what the `infra-db:migration-policy` check refuses.

## Expand, then switch

A change of shape takes two steps, in this order.

1. **Expand.** The migration adds the new form beside the old one: a new nullable column, a new
   table, a new index. A column that must always hold a value gets a `DEFAULT`, so the inserts of
   the previous release, which do not name it, still succeed. A backfill (`UPDATE`) may fill the
   rows that exist. When the new form must also hold what the previous release writes to the old
   one, the migration adds a trigger that copies each such write across. The previous release
   writes only the old form until its last node is replaced, and a backfill misses every write
   it makes after the migration ran.
2. **Switch the code.** The release reads and writes the new form. The old form stays, because
   the previous release still uses it while the upgrade runs.

Within 1.x there is no third step. Removing the old form (the "contract" step of
expand-then-contract) drops something, so it waits for the next major release, like every other
removal: deprecated in a minor release, removed no sooner than 12 months later, and only in a new
major release.

| You want to                       | Within 1.x                                                                                                                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Rename a column or a table        | Add the new one, a trigger that copies each write to the old one into it, and a backfill. The release reads the new one and writes both. The old name stays until the next major release.        |
| Change a column's type            | Add a column of the new type, a trigger that copies (and converts) each write to the old column into it, and a backfill. The release reads the new column and writes both; the old column stays. |
| Make a column required            | Add it with a `DEFAULT`, or keep it nullable and require it in the code.                                                                                                                         |
| Remove a column, table or a check | Stop using it. The drop waits for the next major release.                                                                                                                                        |
| Delete rows                       | Leave them, or let the code delete them at run time. A migration does not.                                                                                                                       |

## What the check refuses

The check reads the SQL of every migration added since the baseline (below): the statements
drizzle-kit generates and the custom SQL written beside them. It refuses these statement kinds:

| Statement kind        | Statements                                                                           | Why                                                                    |
| --------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| `drop-table`          | `DROP TABLE`, `DROP SCHEMA`                                                          | Drops a table and every row in it                                      |
| `drop-column`         | `ALTER TABLE … DROP [COLUMN]`                                                        | Drops a column and its data                                            |
| `drop-constraint`     | `ALTER TABLE … DROP CONSTRAINT`                                                      | Drops a constraint the previous release relies on                      |
| `alter-column-type`   | `ALTER TABLE … ALTER [COLUMN] … [SET DATA] TYPE`                                     | Can narrow the column, or rewrite the table                            |
| `rename`              | Any `ALTER … RENAME`                                                                 | The previous release still uses the old name                           |
| `truncate`            | `TRUNCATE`                                                                           | Deletes every row of a table                                           |
| `delete-from`         | `DELETE FROM`, `MERGE … THEN DELETE`                                                 | Deletes rows                                                           |
| `set-not-null`        | `ALTER TABLE … ALTER [COLUMN] … SET NOT NULL`, `ADD [CONSTRAINT …] NOT NULL …`       | Fails on existing NULLs, and refuses the previous release's writes     |
| `add-column-not-null` | `ADD [COLUMN] … NOT NULL` (or `PRIMARY KEY`) with no `DEFAULT` and no `GENERATED`    | Fails on a table with rows, and refuses the previous release's inserts |
| `raise-exception`     | `RAISE` at level `EXCEPTION` (the default level), or `ASSERT`, in code that runs now | A precondition that stops the upgrade until someone acts by hand       |
| `drop-cascade`        | `DROP … CASCADE` of anything but a table or schema                                   | Also drops what depends on it: `DROP TYPE … CASCADE` drops its columns |
| `dynamic-sql`         | `EXECUTE` in code that runs now                                                      | Runs SQL the check cannot read                                         |

`raise-exception` is the manual-step risk. Migration 0011 aborted unless the operator had run a
backfill first, which made its upgrade a two-hop runbook (see
[the history of migration 0011](/operate/upgrades/#history-the-migration-0011-runbook-adr-002)).

The check reads what runs at migration time, which is the code that "runs now" above. The body of
a `DO` block runs then, and so does the body of a routine the migration runs itself: a `pg_temp`
helper, or a function or procedure another of its statements calls, including a call from a body
that runs now. Those are read like any other SQL. A routine named only in a `CREATE`, `ALTER` or
`DROP` statement (a trigger's `EXECUTE FUNCTION`, a column default) is not followed. Any other `CREATE FUNCTION` or `CREATE PROCEDURE` body runs only when something calls
it later, so it is not read: a trigger function that raises to refuse a write is a guard, not a
migration step. Words inside string literals, quoted identifiers and comments match nothing.
Dropping a temporary table or a `pg_temp` helper the migration made is not refused either.

The file is read the way the migration runner splits it: drizzle cuts it at every
`--> statement-breakpoint`, even one inside a comment, so the check cuts it there too.

Some statements it prints for review without refusing them:

- an `ALTER` form, or an `ALTER TABLE` action, it does not know;
- a `DROP` of anything but a table, without `CASCADE`: an index, a function, a trigger or a type.
  Dropping one loses no rows, but the previous release may still use it, for example a unique
  index its `ON CONFLICT` names;
- a `CALL` of a procedure the migration does not define, whose body the check cannot read.

## Released migrations never change

The baseline is the highest release tag (`vX.Y.Z`, release candidates included) reachable from
the commit under check. A release candidate counts because its testers ran its migrations. The
check compares `libs/infra/db/drizzle` with the baseline:

- Every migration file of the baseline is still there, under the same name, with the same
  contents (the same git blob id). To change what a released migration did, write a new one.
- The journal, `meta/_journal.json`, only grows. The baseline's entries stay as they are, in
  their place. A new entry takes the next index, a file name with that number, and a `when` later
  than the entry before it. The migration runner applies only the migrations newer than the last
  one a database ran, so an entry dated earlier would be skipped on every database already
  upgraded. When a rebase puts your migration after one that landed first, generate it again
  with drizzle-kit.
- Every `.sql` file is in the journal, and every journal entry has its file.

Only the migrations added since the baseline have their SQL checked. The ones a release has
shipped are history: 0011, 0012 and a few later 0.x migrations drop columns, which this policy
would now refuse.

## Exceptions during 0.x

Before 1.0, a destructive statement can still be the right change. It passes when
`libs/infra/db/drizzle/policy-exceptions.json` lists it:

```json
{
  "frozen": false,
  "exceptions": [
    {
      "migration": "0075_example.sql",
      "statement": "drop-column",
      "reason": "users.legacy_flag has had no reader since 0.2; the upgrade guide says so",
      "issue": "#1234"
    }
  ]
}
```

Each entry names one migration file, one statement kind, the reason it is safe or needed, and the
issue that decided it. It covers every statement of that kind in that migration, and no other
kind. An entry that names no migration file, or a checked migration with no statement of its
kind, fails the check: the list says only what is true.

Entries stay after their migration is released, as the record of what 0.x allowed. The list
started empty.

**The freeze.** The issue that cuts the 1.0 release candidate sets `"frozen": true`. From then on
the list may not grow: an entry that the list at the pull request's base does not hold fails, a
migration an entry covers may not change, and `frozen` cannot go back to `false`. Every 1.x
migration then passes the policy with no exception.

## Running it

```bash
pnpm exec nx run infra-db:migration-policy
```

It needs the release tags (`git fetch --tags` in a clone without them) and exits `2` when it
finds none, rather than checking nothing. It prints a report: the baseline, the migrations it
checked, what it refused, what it prints for review and every exception, used or not.

In CI, `infra-db:typecheck` depends on the target, so the affected `typecheck` leg runs it
whenever a migration, the journal, the exceptions file or the check itself changes. That leg has
the full history and the tags, compares a frozen list with the pull request's base (`NX_BASE`),
and puts the report in the job summary. The script and its rules live in
`scripts/migration-policy/`, with their tests beside them.
