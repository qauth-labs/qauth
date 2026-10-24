# test-vectors/

Shared, language-neutral test vectors ([ADR-018 §6 and §7](../docs/adr/018-1-0-scope-and-stability.md)).
Every QAuth SDK runs the same files, in whatever language it is written, and the server's own tests
run them against its code. A vector file is plain JSON: no code, nothing generated at test time.

## Layout

```text
test-vectors/
  schema/vector-file.schema.json   the format, qauth-vectors/1, as JSON Schema (draft 2020-12)
  <area>/<name>.json               one vector file; its id is "<area>/<name>"
  examples/pkce-s256.mjs           a plain Node reader for pkce/s256, 35 lines
  generators/*.mjs                 the scripts that wrote the generated files
  project.json                     the Nx project; its validate target checks every file
```

| File                      | What it tests                                                      | Source                                                              |
| ------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------- |
| `pkce/s256.json`          | The PKCE S256 check at the token endpoint                          | RFC 7636 §4.1, §4.2, §4.6 and Appendix B                            |
| `webhooks/signature.json` | Standard Webhooks signatures, HMAC-SHA256 over `id.timestamp.body` | Generated with the reference library `standardwebhooks@1.1.1` (npm) |
| `agent/act-chain.json`    | Reading an RFC 8693 `act` chain, and QAuth's depth cap of 4        | RFC 8693 §4.1, ADR-007 §2                                           |
| `jwt/access-token.json`   | The access token checks of RFC 9068 §4                             | Generated from fixed-seed throwaway Ed25519 keys                    |

The server's tests run `pkce/s256` in `libs/server/pkce`, `jwt/access-token` in `libs/server/jwt`
and `agent/act-chain` in `apps/auth-server`. QAuth has no webhook signer yet, so
`libs/shared/test-vectors` checks `webhooks/signature` against `node:crypto` until it has one.

## The format

A file has exactly these members. Any other member makes it invalid.

| Member        | Meaning                                                                                                              |
| ------------- | -------------------------------------------------------------------------------------------------------------------- |
| `schema`      | The format version, `"qauth-vectors/1"`.                                                                             |
| `id`          | The file's path under `test-vectors/` without `.json`, such as `"pkce/s256"`.                                        |
| `description` | What the cases test and what `input` and `expected` mean in this file. A reader implements the check from this text. |
| `source`      | Where the cases come from: a specification section, or the tool and version that generated them.                     |
| `cases`       | At least one case. A case has `id`, `input`, `expected` and, optionally, `notes`, and no other member.               |

A case `id` is lower-case and hyphenated, and unique within its file. `input` and `expected` are
JSON objects. A case is a pass when the result computed from `input` equals `expected`, member for
member.

Values follow three rules:

- **Bytes with no text form of their own are base64url without padding.**
- **A value with a text form defined by its specification stays in that form**: a compact JWS, a
  `whsec_` secret, a `webhook-signature` header, a PKCE challenge.
- **Every key is a throwaway test key**, made for its file and used nowhere else. A JWK says so in
  its `kid`, which starts with `throwaway-test-`; the validator rejects a JWK without it. A webhook
  secret decodes to ASCII that says it is a throwaway test secret. The one exception is the
  reference libraries' own example secret in `webhooks/signature.json`, which is public. Files hold
  public keys only.

## Reading the files from another language

A reader needs a JSON parser and the primitive under test, nothing else:

1. Read the file and refuse it unless `schema` is `"qauth-vectors/1"`.
2. For each case, compute a result from `input` the way the file's `description` says.
3. Compare the result with `expected` as JSON values, not as text, and report the case by its
   `id`.

`examples/pkce-s256.mjs` does exactly this for `pkce/s256` with Node's standard library, and a unit
test runs it with the plain `node` binary:

```bash
node test-vectors/examples/pkce-s256.mjs
```

An SDK in another repository can vendor this directory at a pinned commit, for example as a git
subtree. To validate the files themselves without TypeScript, use any JSON Schema 2020-12 validator
with `schema/vector-file.schema.json`, and check the two rules JSON Schema cannot express: case ids
are unique, and every JWK `kid` starts with `throwaway-test-`.

## Versioning

- **Vectors are append-only.** Adding a case or a file is always allowed. A merged case is never
  edited and its id is never reused.
- **Changing a case's expected result needs a new case id.** The old case is then wrong, so the same
  change removes it, and its id stays retired. An SDK pinned to an older commit keeps the old case
  and its old meaning.
- **Changing the format is a new format version**, `qauth-vectors/2`, with its own schema. A reader
  refuses a version it does not know, so a new member never arrives unannounced.

## Working on the files

```bash
pnpm exec nx run test-vectors:validate                          # check every file
pnpm exec nx run shared-test-vectors:schema-export --skip-nx-cache  # rewrite the JSON Schema
```

`validate` rejects a missing member, a wrong `schema` id, an unknown member, a duplicate case id, a
JWK not marked as a throwaway key, and an `id` that does not match the file's path. The
`test-vectors` project's `test` target depends on it, so CI's unit job runs it.

TypeScript tests read a file with `loadVectors(id)` from `@qauth-labs/shared-test-vectors`
(`libs/shared/test-vectors`), which validates it first. A test fails when a committed vector file is
loaded by no test.

The two generated files have their generators in `generators/`. Neither runs at test time; run one
by hand after adding a case, and commit what it writes:

```bash
node test-vectors/generators/access-token.mjs
node test-vectors/generators/webhooks-signature.mjs <path to the standardwebhooks@1.1.1 package>
```

`access-token.mjs` derives its keys from fixed seeds and rewrites the committed file byte for byte.
`webhooks-signature.mjs` refuses any version of the reference library other than the pinned one;
its header says how to fetch it.

To add a file: write `<area>/<name>.json` with an `id` of `<area>/<name>`, describe `input` and
`expected` in `description` precisely enough for another language, run `validate`, and load it with
`loadVectors` in the tests of the code it covers.
