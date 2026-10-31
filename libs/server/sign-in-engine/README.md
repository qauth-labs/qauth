# @qauth-labs/server-sign-in-engine

The sign-in engine (#614, ADR-017 Decisions 4 and 7, ADR-019 Decision 6): the one engine that
decides every step of a sign-in, whatever the transport. The Interaction API (browser ceremonies,
#616) and the FiPA authorization challenge endpoint (native apps, #646) call it once per round and
map its answer onto their wire with the step grammar's mappers (`@qauth-labs/server-step-grammar`).
The flow is graphed in [`graphs/flows/core/sign-in/flow.yaml`](../../../graphs/flows/core/sign-in/flow.yaml).

It does no I/O of its own: everything it reads or calls is a port. The auth server's adapters live
in `@qauth-labs/fastify-plugin-sign-in-engine`.

```ts
import { createSignInEngine, NO_SECOND_FACTOR_POLICY } from '@qauth-labs/server-sign-in-engine';

const engine = createSignInEngine({
  accounts, // AccountDirectory: what a password needs before it is checked; the whole account after
  passwords, // PasswordVerifier: Argon2id, and the dummy hash
  policy: NO_SECOND_FACTOR_POLICY, // MfaPolicyReader: read on every round
  identifierDigest, // the identifier's keyed HMAC
  requireVerifiedAccount: true, // REQUIRE_VERIFIED_ACCOUNT
  hooks: {}, // limits, request, botChallenge, ladder: later issues fill them
  steps: [], // the steps later issues add
});

const result = await engine.advance(transaction, answer, {
  realm: { id: realmId },
  client: { id: clientId },
  loginHint, // the authorization request's login_hint, frozen at round 0
  serves, // the steps this transport can serve; every step by default
  receivedAt, // the request's arrival, for the timing floor
  audit, // where the round's audit records go
});
```

`advance` returns one of:

| `kind`     | Meaning                                                                                                    |
| ---------- | ---------------------------------------------------------------------------------------------------------- |
| `step`     | the next step, or the same step again with its error: a `StepOffer` and its personal data                  |
| `complete` | the sign-in is complete: `subject`, `identifier`, `amr`, `authTime`; the transport mints session/code      |
| `redirect` | continue elsewhere: a step the sign-in needs does not exist yet or is not served (FiPA: `redirect_to_web`) |
| `refused`  | `transaction_ended`, `throttled`, `unavailable`, `invalid_answer` or `request_refused`                     |

The transaction it returns is the one to keep for the next round; `signInTransactionSchema` checks
it when it is read back. It holds the identifier, the subject, the verified steps and `auth_time`,
and never a policy, an answer or an account's state. A completed sign-in, a redirect and a
transaction that ended return `null` in its place, so nothing completes twice. Every other refusal
returns the transaction as far as the round took it: an identifier the round fixed stays, nothing
it refused is in it.

## The rules, in order

ADR-017 Decision 4's order, from rule 3 (rules 1 and 2, the transport's own checks and client
authentication, run before the call). The first unmet rule produces the answer.

1. The MFA policy is read, on every round. A policy that cannot be read refuses the round.
2. The `limits` hook (rule 3; PRO-13, #636).
3. The `request` hook (rule 4): the transport's request checks (#628, #665).
4. The `botChallenge` hook (rule 5; PRO-19, #643). A due challenge comes before every other step:
   the `captcha` step when a handler for it is registered and the transport serves it, else a 429.
5. The identifier (rule 6): the request's `login_hint`, else an answer's (the identifier step's,
   or a password answer's; no other answer's). It is checked (an email address of at most 254 bytes)
   and normalised. The first one is fixed; a different one ends the transaction, audited as
   `subject_mismatch`. With none, the identifier step; or, once a discoverable first factor is
   registered (#651), that factor first, preferred, with the password and the identifier step beside
   it (ADR-017 Decision 4).
6. The first factor (rule 7), offered alike to every account until one succeeds: the password
   required, with any other first factor beside it. The password answer is reserved on the
   `ladder` hook (PRO-12, #615) before it is verified.
7. After a first factor (rule 8): the downgrade rule (the transaction must prove the account's
   strongest bound factor; a disabled factor still counts as bound), then the MFA policy just read
   (a policy that requires a second factor needs `mfa` in the `amr`). A rule no registered step can
   meet answers `redirect`.
8. Complete (rule 9).

## What holds for every round

- **The same answer for every account until a factor succeeds.** An unknown identifier, a
  password-only, passkey-only, disabled or locked account and an unverified one under
  `REQUIRE_VERIFIED_ACCOUNT` get the same offer and the same error, in body and in timing; no
  account is read before a credential is answered, and then only what the password needs (the
  whole account is read once a factor proved it). Every refused password costs one Argon2id
  verification (against a dummy hash when there is no usable password). `login_hint` changes no
  offer.
- **The timing floor.** Every round answers no earlier than 500 ms
  (`SIGN_IN_MIN_RESPONSE_TIME_MS`, `MIN_RESPONSE_TIME_MS.LOGIN`) after `receivedAt`, success,
  refusal or failure.
- **Eager answers.** An answer is verified only when its step is the one the engine asks for next.
  Any other is ignored: not verified, not counted, not audited.
- **One subject per transaction.** The first identifier and the first user proven are fixed.
- **Fail closed.** A port that throws (the policy, the directory, a hook, the ladder's reservation,
  the verifier, the identifier key) refuses the round as `unavailable`; every one of them that can
  fail before a credential is checked does so alike for every identifier. Settling a ladder
  reservation never changes the answer: a failure there is reported through `onUnavailable`.
- **A disabled user is never changed.** It gets the ordinary invalid-credentials answer, and no
  subject is fixed, so no transport can mint for it. The engine checks this for every factor step,
  not only the password: a step that proves a disabled account (or an unverified one under the
  gate) is refused like a wrong answer.
- **Try another way.** Before a factor succeeds, a step's alternatives are what every account is
  offered; after one, the account's remaining usable methods that can meet the rules. An email
  code can never be registered as a sign-in step.

## Audit records

Each processed step writes one record through the round's `audit` sink: `passed`, `refused` or
`ended`, the step, the reason, and the person by the transaction's subject once a factor fixed one,
by the identifier's keyed HMAC before; a refused answer never names a user it happened to resolve. A record never holds a password, a code or the identifier. A sink that fails
fails the round. The adapters map them onto `user.sign_in_step_passed` and `user.sign_in_failed`.

## Adding a step

A step joins the engine as a `StepHandler` (`src/lib/steps/handler.ts`), passed in `steps`: its
role (`challenge`, `first_factor`, `second_factor`), the factor it proves, whether an account can
use it, its params and personal data, and how it verifies an answer the step grammar has already
read. A first factor may be `discoverable` (a passkey that names the account by itself): it is
offered before any identifier, and after the password once one is held. A handler refuses a
disabled account itself, settling its ladder as a failure. Passkeys (#651), TOTP (#653) and the
email code (#638) come this way; an email code can never be registered as a factor.

## Known gaps, for the issues that follow

- The per-transaction budgets of the FiPA `auth_session` (rounds, failures per step) are #647's.
- The policy has no storage yet: `NO_SECOND_FACTOR_POLICY` is the default until it has one.
- `user_credentials.disabled_at` does not exist yet (#615): the adapters report no factor disabled.
