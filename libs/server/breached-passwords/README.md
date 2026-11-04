# @qauth-labs/server-breached-passwords

Answers one question for the sign-in engine: is this password on the realm's breach list?
([#635](https://github.com/qauth-labs/qauth/issues/635),
[ADR-017 Decision 8](../../../docs/adr/017-first-party-login.md)). NIST SP 800-63B-4 §3.1.1.2 asks a
verifier to compare new passwords with a list of values known to be compromised; QAuth also checks a
presented password, so a breached one can be replaced through the forced password update.

Each realm picks its source in `password.breachListSource` (seeded by
`PASSWORD_BREACH_LIST_SOURCE`, `@qauth-labs/server-realm-policy`):

| Source        | What is checked                                                                                      |
| ------------- | ---------------------------------------------------------------------------------------------------- |
| `off`         | Nothing. The default.                                                                                |
| `local`       | The operator's list at `BREACHED_PASSWORD_LIST_PATH`, in memory.                                     |
| `k_anonymity` | A range lookup at `BREACHED_PASSWORD_RANGE_URL`, through the egress client: a five-character prefix. |

**The password is never sent anywhere.** It is hashed with SHA-1 here (what breach corpora index;
not a password hash). The local list is searched in memory. The range lookup sends the digest's
first five hex characters, and nothing else of the digest or the password goes in the URL, a
header, a body or a log line.

**A check that fails never blocks a sign-in.** A source the deployment has not set up, a list that
has not loaded, or a lookup that is refused, fails or answers garbage is a `failed` result with a
reason. The caller counts it and records it in the audit log, and the sign-in proceeds.

## Usage

```typescript
import {
  createBreachedPasswordChecker,
  createBreachRangeLookup,
  createReloadableBreachList,
} from '@qauth-labs/server-breached-passwords';

const localList = env.BREACHED_PASSWORD_LIST_PATH
  ? createReloadableBreachList(env.BREACHED_PASSWORD_LIST_PATH)
  : undefined;
await localList?.reload(); // at boot; a failure leaves no list, and `local` checks fail
process.on('SIGHUP', () => void localList?.reload()); // a failed reload keeps the list in use

const checker = createBreachedPasswordChecker({
  localList,
  rangeLookup: env.BREACHED_PASSWORD_RANGE_URL
    ? createBreachRangeLookup({ egress: fastify.egress, url: env.BREACHED_PASSWORD_RANGE_URL })
    : undefined,
  onResult: (result) => breachChecks.inc({ kind: result.kind, source: result.source }),
});

const result = await checker.check({
  source: policies.password.breachListSource,
  password,
  realm: realm.name,
});
// { kind: 'off' } | { kind: 'listed' | 'not_listed', source } | { kind: 'failed', source, reason }
```

`check` never throws for a list or lookup problem. `onResult` is told every result but `off`, and
whatever it throws is dropped.

| Failure reason    | When                                                                                    |
| ----------------- | --------------------------------------------------------------------------------------- |
| `not_configured`  | `local` without `BREACHED_PASSWORD_LIST_PATH`, `k_anonymity` without the range URL.     |
| `list_not_loaded` | The list is configured and no load of it has succeeded (the boot's load failed).        |
| `lookup_blocked`  | The egress client refused the call (a private address without an allowlist entry, ...). |
| `lookup_failed`   | The call did not complete, or the host answered a status other than 200.                |
| `bad_response`    | A 200 whose body is not a range of `SUFFIX:COUNT` lines.                                |

## The local list

One SHA-1 per line, 40 hex characters in either case, optionally followed by `:<count>`: the
`HASH:COUNT` form of the [Have I Been Pwned downloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader),
whose count is ignored. Blank lines and lines starting with `#` are skipped, CRLF is accepted, and
anything else is malformed: the load fails with a `BreachListError` naming the line number, never
the line.

The file is read as a stream, and the digests are held as one sorted buffer of 20-byte digests
without repeats, searched by binary search: ten million digests take 200 MB. A sorted file (the
downloader's is) is not sorted again; an unsorted one is.

`createReloadableBreachList(path)` loads nothing until `reload()` is called. A reload that loads the
whole file replaces the list; one that fails keeps the list in use and says why. Calls made while a
load runs share it.

## The range lookup

As Have I Been Pwned's
[search by range](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange): one `GET` of
the configured URL followed by the five-character prefix, upper case, with `add-padding: true` so
the answer's size says nothing about the prefix. Padding lines have a count of 0 and list nothing.

The call goes through the egress client (ADR-019 Decision 8) as an `operator` destination with the
purpose `breached-password-range` and the realm's name, so an internal mirror on a private address
needs an `EGRESS_ALLOWLIST_PATH` entry naming the realms that use it. It follows no redirect, gives
up after 3 seconds (it runs on the sign-in path, and a failed lookup blocks nothing) and reads at
most 256 KiB.

The URL must be an absolute `https` URL without a user name, password, query or fragment;
`createBreachRangeLookup` throws a `TypeError` otherwise, and the env schema refuses it at boot.

No source of this library opens a connection itself: Oxlint's `qauth/no-direct-network` covers it,
and `no-direct-network.test.ts` pins it (#635 acceptance).

## Testing

```bash
pnpm nx test server-breached-passwords
```
