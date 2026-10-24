# upgrade-test

Upgrades from earlier releases, tested the way an operator runs them
([ADR-018 §5](../../docs/adr/018-1-0-scope-and-stability.md), #475): start a released QAuth, write
data through its HTTP API, run the new version's migration runner and **nothing else**, start the
new version, and check that nothing was lost. Then start the released server again on the migrated
database (the rolling-upgrade leg): old code must keep working after the new migrations ran, which
is what "expand, then contract" means.

CI runs it as the `upgrade-test` job of the `Upgrade test` workflow, once per release tag in
[`upgrade-baselines.json`](../../upgrade-baselines.json) at the repository root.
`scripts/upgrade-test/upgrade-test.sh` drives the containers; this project holds the checks.

## What it checks

**Populate**, against the baseline release (`populate` target):

1. a developer and an end user register and verify their address with the token from the
   verification mail;
2. the developer creates two confidential clients through `POST /api/clients`;
3. the end user runs the authorization code flow with PKCE through the hosted sign-in and consent
   pages and allows the client for good;
4. the code is exchanged for an access token, an ID token and a refresh token;
5. the second client is marked `development` in the database (the operator step static API keys
   need: no release offers it over HTTP), and the developer mints an API key for it.

The results go to the state file (`QAUTH_UPGRADE_STATE`), mode `0600`, never uploaded.

**Verify**, against the new build after the upgrade (`verify` target):

- the old access token introspects as active, with its subject, client and expiry, until it expires;
- both old passwords sign in;
- the consent is listed, and the hosted sign-in no longer asks for it;
- the API key is listed, and its plaintext verifies against the stored argon2id hash. No release
  has a route that authenticates with an API key, so this reads the `api_keys` row the server's
  `authenticateApiKey` reads;
- the old refresh token rotates, and is refused once rotated.

**Smoke**, against whichever server runs (`smoke` target): health, discovery and keys, then the
whole populate scenario afresh, userinfo, a refresh and an API key. It runs on the new build after
the upgrade and on the baseline in the rolling leg, so both write rows into the migrated schema. The
job also runs the [wire suite](../wire-suite/README.md) against the new build on the upgraded
database.

The checks use only what every baseline answers. Where releases differ, the helper accepts each
answer: registration answers `201` with a user in the 0.1.0 release candidates and `202` with no
user from 0.1.0 on, so the user id comes from the login token.

## The rolling leg

It fails when a migration removes or changes something the released code still uses: a dropped or
renamed column, a new `NOT NULL` column without a default. Until the repository has a release at or
after `v1.0.0-rc.0`, a failure is reported as a warning and in the job summary and the job stays
green; from then on it fails the job (`scripts/upgrade-test/lib.mjs`, `rollingLegBlocks`).

## Run it locally

You need Docker and a workspace install (`pnpm install`). One command builds the four images, runs
every step and removes the containers:

```bash
UPGRADE_BASELINE=v0.1.0-rc.2 scripts/upgrade-test/upgrade-test.sh all
```

Its ports default to `3000` (the server), `5432` (Postgres) and `8025` (Mailpit's API) on
`localhost`; set `UPGRADE_HTTP_PORT`, `UPGRADE_PG_PORT` and `UPGRADE_MAIL_PORT` when those are
taken. `scripts/upgrade-test/upgrade-test.sh` without a command lists the steps, which you can also
run one at a time as the CI job does.

## Add a baseline

Add the tag to `upgrade-baselines.json`. It becomes one more matrix entry; nothing else changes.
From 1.0 on, the list holds every earlier 1.x minor release. The `baselines` job refuses a name
that is not a tag of the repository.

## Configuration

| Variable                     | Meaning                                                                      |
| ---------------------------- | ---------------------------------------------------------------------------- |
| `QAUTH_UPGRADE_ALLOW_WRITES` | Must be exactly `1`. Confirms the server and its database may be written to. |
| `QAUTH_BASE_URL`             | The server's issuer, e.g. `http://localhost:3000`. Both servers share it.    |
| `QAUTH_UPGRADE_DATABASE_URL` | The server's database, reachable from where the test runs.                   |
| `QAUTH_UPGRADE_STATE`        | The state file the populate step writes and the verify step reads.           |
| `QAUTH_UPGRADE_MAIL_URL`     | Mailpit's HTTP API, which receives the servers' mail over SMTP.              |

The script sets them all. The steps refuse to start without `QAUTH_UPGRADE_ALLOW_WRITES=1`, before
any request is sent.

## The project's own tests

`src/**/*.test.ts` (no `.upgrade.`) tests the configuration guard, the state file and the HTML and
mail helpers. They need no server and run with the rest of the unit suite:
`pnpm nx test upgrade-test`.
