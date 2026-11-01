# @qauth-labs/fastify-plugin-sign-in-engine

The auth server's side of the sign-in engine (#614,
[`@qauth-labs/server-sign-in-engine`](../../../server/sign-in-engine/README.md)): the adapters
that give the engine's ports the server's repositories, password hasher and key custody, the
mapping of the engine's audit records onto registered events, and a plugin that decorates the
server with one engine. The app may not import a `scope:server` library, so it reaches the engine
through this one, which re-exports the types it needs.

| Export                               | What                                                                                                                                |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `createRepositoryAccountDirectory`   | Before the password: its credential and users row only. After a proof: every password and passkey credential and the admin grants   |
| `createArgon2PasswordVerifier`       | Argon2id through the server's hasher, and the dummy verification, which fails only as a real one does and always costs one Argon2id |
| `createCookieSecretIdentifierDigest` | The identifier's keyed HMAC, under a key derived with HKDF from the realm's `cookie_hmac` secret and a label of its own             |
| `signInAuditEvent`                   | An audit record as `user.sign_in_step_passed` or `user.sign_in_failed`, with the user as subject once resolved and the HMAC before  |
| `signInEnginePlugin`                 | Decorates `fastify.signInEngine` with an engine built from its options; in production only with a `ladder` hook                     |
| `createRedisFailureLadder`           | The per-account failure ladder (#615) in Redis: one script reserves an attempt before its check; no key holds an address            |
| `createPasswordHardAction`           | The ladder's hard action at 100 failures: mark the password disabled, alert the operator, notify the owner; only while armed        |
| `createHardActionArming`             | Whether the hard action is armed in a realm: the hosted reset (#642) on and the owner's notice (#637) sendable, asked every call    |
| `createPasswordAttempts`             | The ladder as the legacy login routes use it: reserve before the password, settle after, a store error as one error type            |
| `END_USER_IP_HMAC_LABEL`             | The HKDF label of the end-user IP digest the ladder keeps known IPs under                                                           |

Nothing registers the plugin yet: the transports do, the Interaction API's answer route (#616)
and the FiPA endpoint (#646), and they emit the mapped events with the server's event writer.
Each keeps the engine's transaction server-side, under an unguessable handle bound to the realm and
the client: the transaction is not sealed (see the engine's README). In production (`NODE_ENV`, or
the `production` option) the plugin refuses to register without `hooks.ladder`: the engine's
default ladder counts nothing, so a password could be guessed without limit.

The auth server's legacy routes, `POST /auth/login` and `POST /ui/login`, use the ladder today,
through `createPasswordAttempts`, beside their own lock: an attempt is reserved before the password
is read, refused inside its wait, and settled after the check. The plugin also requires
`passwordHardAction` in production, the hard action the engine's password step calls at the
ceiling.

The ladder's keys are `sign-in-ladder:{<realm id>:<identifier HMAC>}:<factor>` (a hash: the run's
consecutive failures, the end of its wait, the run's id) and `…:known-ips` (a sorted set of
end-user IP HMACs, scored by their last successful sign-in). The braces are a Redis Cluster hash
tag, so one script reads and writes both. Every Redis call is bounded (2 s), and any error or
timeout of a reservation refuses the attempt before a credential is checked.

## Known gaps

- The identifier and end-user IP keys are derived from the realm's cookie secret, with no secret of
  their own (#615 keeps it so). In one process every role reads it as `local`; the remote signer
  (#497) hands it to the `web` role only, so an `api`-only node, which serves `POST /auth/login`,
  will need the signer to compute the digest, or that route moves. A rotation of the secret changes
  every digest, so every account's run of failures and known IPs start afresh.
- The hard action is never armed yet: the hosted reset (#642) and the owner's notice (#637) do not
  exist, so the 100th failure only logs a warning and a disabled mark is ignored and cleared by the
  next successful sign-in.
- Only the password has a ladder. The second factors (#653) and the email code (#638) reuse it
  with policies of their own; until then their reservations are refused.
- No TOTP factor is reported until TOTP is stored (#653).

## Tests

`adapters.test.ts` holds each adapter to its rules with fakes. `failure-ladder.test.ts` runs the
ladder's scripts against a model of Redis: the schedule, the known IPs, settling, fail-closed and
that no key holds an address; `password-hard-action.test.ts` the arming and the hard action.
`sign-in-engine.integration.test.ts` (target `test-integration`, Docker) runs the engine over the
real repositories and hasher against the migrated schema: a disabled user never completes a
sign-in, the right password included, and no row of any table changes.
`failure-ladder.integration.test.ts` (Docker) holds the ladder to #615's acceptance criteria on
real Redis and Postgres: 200 parallel wrong passwords reach the verifier no more often than
sequential ones, an attempt inside a wait is neither verified nor counted, the 100th failure
disables the password only while armed, an ignored mark lets the user in, a known IP skips the
wait and still counts, and a stopped Redis refuses the round before any credential is checked.
