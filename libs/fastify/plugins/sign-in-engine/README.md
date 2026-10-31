# @qauth-labs/fastify-plugin-sign-in-engine

The auth server's side of the sign-in engine (#614,
[`@qauth-labs/server-sign-in-engine`](../../../server/sign-in-engine/README.md)): the adapters
that give the engine's ports the server's repositories, password hasher and key custody, the
mapping of the engine's audit records onto registered events, and a plugin that decorates the
server with one engine. The app may not import a `scope:server` library, so it reaches the engine
through this one, which re-exports the types it needs.

| Export                               | What                                                                                                                               |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `createRepositoryAccountDirectory`   | Before the password: its credential and users row only. After a proof: every password and passkey credential and the admin grants  |
| `createArgon2PasswordVerifier`       | Argon2id through the server's hasher, and the dummy verification, which fails only as a real one does                              |
| `createCookieSecretIdentifierDigest` | The identifier's keyed HMAC, under a key derived with HKDF from the realm's `cookie_hmac` secret and a label of its own            |
| `signInAuditEvent`                   | An audit record as `user.sign_in_step_passed` or `user.sign_in_failed`, with the user as subject once resolved and the HMAC before |
| `signInEnginePlugin`                 | Decorates `fastify.signInEngine` with an engine built from its options                                                             |

Nothing registers the plugin yet: the transports do, the Interaction API's answer route (#616)
and the FiPA endpoint (#646), and they emit the mapped events with the server's event writer.

## Known gaps

- The identifier key is derived from the realm's cookie secret, which the `web` role may read and
  the `api` role may not. A rotation of that secret changes every digest. The per-account ladder
  (#615) decides whether the identifier gets a key of its own.
- No factor is reported disabled until `user_credentials.disabled_at` exists (#615), and no TOTP
  factor until TOTP is stored (#653).

## Tests

`adapters.test.ts` holds each adapter to its rules with fakes. `sign-in-engine.integration.test.ts`
(target `test-integration`, Docker) runs the engine over the real repositories and hasher against
the migrated schema: a disabled user never completes a sign-in, the right password included, and no
row of any table changes.
