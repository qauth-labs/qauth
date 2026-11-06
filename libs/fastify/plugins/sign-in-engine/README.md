# @qauth-labs/fastify-plugin-sign-in-engine

The auth server's side of the sign-in engine (#614,
[`@qauth-labs/server-sign-in-engine`](../../../server/sign-in-engine/README.md)): the adapters
that give the engine's ports the server's repositories, password hasher and key custody, the
mapping of the engine's audit records onto registered events, and a plugin that decorates the
server with one engine. The app may not import a `scope:server` library, so it reaches the engine
through this one, which re-exports the types it needs.

| Export                               | What                                                                                                                                                                                                 |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `createRepositoryAccountDirectory`   | Before the password: its credential and users row only. After a proof: every password and passkey credential, the admin grants and the pending required actions (#635)                               |
| `createArgon2PasswordVerifier`       | Argon2id through the server's hasher, and the dummy verification, which fails only as a real one does and always costs one Argon2id                                                                  |
| `createCookieSecretIdentifierDigest` | The identifier's keyed HMAC, under a key derived with HKDF from the realm's `cookie_hmac` secret and a label of its own                                                                              |
| `createCookieSecretEmailCodeDigest`  | An emailed code's keyed HMAC over the realm, its salt and the code (#638), under the same derivation with a label of its own                                                                         |
| `createRepositoryAddressVerifier`    | Marks a password credential's address verified, and its email attribute, in one database transaction, for an enabled subject only                                                                    |
| `createRepositoryPasswordUpdates`    | The forced password update (#635): the realm's policy, and one transaction that writes the new hash, clears the disabled mark and the `update_password` required action, for an enabled subject only |
| `signInAuditEvent`                   | An audit record as `user.sign_in_step_passed`, `user.sign_in_failed` or `user.password_breach_check_failed`, with the user as subject once resolved and the HMAC before                              |
| `signInEnginePlugin`                 | Decorates `fastify.signInEngine` with an engine built from its options; in production only with a `ladder` and a `limits` hook                                                                       |
| `createRedisFailureLadder`           | The per-account failure ladder (#615) in Redis: one script reserves an attempt before its check; no key holds an address                                                                             |
| `createPasswordHardAction`           | The ladder's hard action at 100 failures: mark the password disabled, alert the operator, notify the owner; only while armed                                                                         |
| `createHardActionArming`             | Whether the hard action is armed in a realm: the hosted reset (#642) on and the owner's notice (#637) sendable, asked every call                                                                     |
| `createPasswordAttempts`             | The ladder as the legacy login routes use it: reserve before the password, settle after, a store error as one error type                                                                             |
| `END_USER_IP_HMAC_LABEL`             | The HKDF label of the end-user IP digest the ladder keeps known IPs under                                                                                                                            |
| `createRedisRoundLimits`             | The round limits (#636) in Redis: per end-user IP, per IP bucket, per client and registration starts, one script per decision; no key holds an address                                               |
| `createRepositoryRecoveryCodes`      | The recovery codes (#649) over `user_recovery_codes` and the hasher: a code's take and its event in one transaction, then the "used" notice; `regenerate` (ACC-02, #687) and the 100-failures notice |

Nothing registers the plugin yet: the transports do, the Interaction API's answer route (#616)
and the FiPA endpoint (#646), and they emit the mapped events with the server's event writer.
Each keeps the engine's transaction server-side, under an unguessable handle bound to the realm and
the client: the transaction is not sealed (see the engine's README). In production (`NODE_ENV`, or
the `production` option) the plugin refuses to register without `hooks.ladder`: the engine's
default ladder counts nothing, so a password could be guessed without limit. It refuses to register
without `hooks.limits` too (#636): without the round limits one end-user IP could try a password on
every account.

The auth server's legacy routes, `POST /auth/login` and `POST /ui/login`, and the password check
of the email verification (`POST /auth/verify`, `POST /ui/verify`) use the ladder today,
through `createPasswordAttempts`, beside their own lock: an attempt is reserved before the password
is read, refused inside its wait, and settled after the check. The plugin also requires
`passwordHardAction` in production, the hard action the engine's password step calls at the
ceiling.

The ladder's keys are `sign-in-ladder:{<realm id>:<identifier HMAC>}:<counter>`, one per factor
and one for the wrong email codes (`email_code`, #638), and
`sign-in-ladder:{<realm id>:user:<user id>}:recovery_code` for an account's wrong recovery codes
(#649), keyed on the account so every identifier, transaction and end-user IP shares it (a hash: the run's
consecutive failures, the end of its wait, the run's id and how many of its failures came from
known IPs) and `…:known-ips` (a sorted set of
end-user IP HMACs, scored by their last successful sign-in). The braces are a Redis Cluster hash
tag, so one script reads and writes both. Every Redis call is bounded (2 s), and any error or
timeout of a reservation refuses the attempt before a credential is checked.

The round limits' keys are `round-limits:{<realm id>}:ip:<IP HMAC>:…`, `…:bucket:<bucket HMAC>:…`,
`…:client:<client hash>:…` and `…:registration:…`: sorted sets of the rounds in each window, the
bucket's identifier HMACs, and the end of each block, delay and alert. An end-user IP and its bucket
are their keyed HMACs (the ladder's label), a client and an account the SHA-256 of their ids. Every
time is the store's clock; every key expires with its window. Every Redis call is bounded (2 s),
and any error refuses the round before a credential is checked.

## Known gaps

- The identifier and end-user IP keys are derived from the realm's cookie secret, with no secret of
  their own (#615 keeps it so). In one process every role reads it as `local`; the remote signer
  (#497) hands it to the `web` role only, so an `api`-only node, which serves `POST /auth/login`,
  will need the signer to compute the digest, or that route moves. A rotation of the secret changes
  every digest, so every account's run of failures and known IPs start afresh.
- The hard action is never armed yet: the hosted reset (#642) and the owner's notice (#637) do not
  exist, so the 100th failure only logs a warning and a disabled mark is ignored and cleared by the
  next successful sign-in.
- Only the password and the email code (#638) have a ladder. The second factors (#653) reuse it
  with policies of their own; until then their reservations are refused.
- No TOTP factor is reported until TOTP is stored (#653).
- The round limits' client row and per-client registration cap wait for the FiPA endpoint (#646),
  whose authenticated client they count, and `FIRST_PARTY_CLIENT_MAX_ROUNDS` with it; the
  registration-start cap waits for the registration steps (#640). The soft thresholds delay rounds
  until the bot challenge (#643) replaces the delay.

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
wait for 20 known-IP failures of a run, whatever other addresses tried, and reaches the 100th only
through the waits, still counting each, and a stopped Redis refuses the round before any credential is checked.
`round-limits.integration.test.ts` (Docker) runs the round limits' scripts through the store
contract the memory store keeps, and holds them to #636's acceptance criteria: 30 failed rounds
from one IP refuse its rounds for 15 minutes, failures for more than 20 identifiers from one bucket
delay it and alert, the fourth registration start from one IP in an hour is refused, and a stopped
Redis refuses rounds before any credential is checked. `recovery-codes.test.ts` holds the
recovery codes' adapter to its order: the take, its event and the status in one transaction, the
notices only after it commits, and a notice that fails reported, never refusing the code.
