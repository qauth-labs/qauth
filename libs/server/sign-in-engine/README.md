# @qauth-labs/server-sign-in-engine

The sign-in engine (#614, ADR-017 Decisions 4 and 7, ADR-019 Decision 6): the one engine that
decides every step of a sign-in, whatever the transport. The Interaction API (browser ceremonies,
#616) and the FiPA authorization challenge endpoint (native apps, #646) call it once per round and
map its answer onto their wire with the step grammar's mappers (`@qauth-labs/server-step-grammar`).
The flow is graphed in [`graphs/flows/core/sign-in/flow.yaml`](../../../graphs/flows/core/sign-in/flow.yaml).

It does no I/O of its own: everything it reads or calls is a port. The auth server's adapters live
in `@qauth-labs/fastify-plugin-sign-in-engine`.

```ts
import {
  createCaptchaStep,
  createSignInEngine,
  NO_SECOND_FACTOR_POLICY,
} from '@qauth-labs/server-sign-in-engine';

const engine = createSignInEngine({
  accounts, // AccountDirectory: what a password needs before it is checked; the whole account after
  passwords, // PasswordVerifier: Argon2id, and the dummy hash
  policy: NO_SECOND_FACTOR_POLICY, // MfaPolicyReader: read on every round
  identifierDigest, // the identifier's keyed HMAC
  requireVerifiedAccount: true, // REQUIRE_VERIFIED_ACCOUNT: decides only without emailCodes
  emailCodes: { digest, addresses }, // the inline verification of an unverified account (#638)
  breachCheck, // BreachedPasswordCheck: the realm's breach list (#635); none checks nothing
  passwordUpdates, // PasswordUpdates: the forced password update (#635); none redirects it
  registrations, // AccountRegistrations: registration's gate and account creation (#640)
  resets, // AccountResets: the password reset's gate and its write (#642)
  sessionEpochs, // SessionEpochReader: each user's last reset, read on every round (#642)
  recoveryCodes, // RecoveryCodes: a lost factor's recovery codes (#649); none offers none
  hooks: { ladder, limits }, // ladder: #615; limits: #636; request: later issues; botChallenge: optional (#643)
  passwordHardAction, // the ladder's hard action at its ceiling; none by default
  steps: [createCaptchaStep(provider)], // the bot challenge (#643), and the steps later issues add
});

const result = await engine.advance(transaction, answer, {
  realm: { id: realmId },
  client: { id: clientId },
  loginHint, // the authorization request's login_hint, frozen at round 0
  serves, // the steps this transport can serve; every step by default
  receivedAt, // the request's arrival, for the timing floor
  endUserIp, // the end-user IP as the limiters key it (an IPv6 address by its /64); none: no IP row
  environment, // the client's effective environment (ADR-008 §7): development relaxes the limits
  audit, // where the round's audit records go
  sendCode, // the capped sender of email codes (#637), bound to the request
  flow, // 'register' for prompt=create (#640), 'reset' for a reset (#642); absent for a sign-in
  freshSignIn, // max_age or prompt=login: a reset is never offered (#642)
});
```

`advance` returns one of:

| `kind`     | Meaning                                                                                                                             |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `step`     | the next step, or the same step again with its error: a `StepOffer` and its personal data                                           |
| `complete` | the sign-in is complete: `subject`, `identifier`, `amr`, `authTime`; a registration's: `registered`, a reset's: `recovered`, no amr |
| `redirect` | continue elsewhere: a step the sign-in needs does not exist yet or is not served (FiPA: `redirect_to_web`)                          |
| `refused`  | `transaction_ended`, `throttled`, `unavailable`, `invalid_answer` or `request_refused`                                              |

The transaction it returns is the one to keep for the next round; `signInTransactionSchema` checks
it when it is read back. It holds the realm and the client it is for, when round 0 began, the
identifier, the subject, the verified steps, `auth_time` and the salt and keyed HMAC of an email
code it mailed, and never a policy, an answer, a code or an account's state. A completed sign-in, a redirect and a transaction that ended return `null` in its
place, so nothing completes twice. Every other refusal returns the transaction as far as the round
took it: an identifier the round fixed stays, nothing it refused is in it.

**The transaction is not sealed.** Whoever can write one can claim any subject and any verified
step, so the transport must keep it server-side, under an unguessable handle bound to the realm and
the client, and never take one back from the client. The engine ends (`transaction_ended`) a
transaction that is not well formed, belongs to another realm or client, begins more than a minute
in the future, or is older than two hours (`SIGN_IN_TRANSACTION_MAX_AGE_MS`, the longest
`INTERACTION_TTL` allows; a transport ends its own sooner), and audits the end naming nobody.

## The rules, in order

ADR-017 Decision 4's order, from rule 3 (rules 1 and 2, the transport's own checks and client
authentication, run before the call). The first unmet rule produces the answer.

1. The MFA policy is read, on every round. A policy that cannot be read refuses the round.
2. The `limits` hook (rule 3; PRO-13, #636): a round from an end-user IP inside its hard block, or
   above the client's rounds a minute, is refused as `throttled`. See
   [The round limits](#the-round-limits).
3. The `request` hook (rule 4): the transport's request checks (#628, #665).
4. The bot challenge (rule 5; PRO-19, #643). It is due when a registration owes it, or, while the
   transaction holds no unspent pass, when a soft threshold holds or the optional `botChallenge`
   hook says so. See [The bot challenge](#the-bot-challenge). A due challenge comes before every
   other step, in addition to the delay: the `captcha` step alone when the transport serves it.
   Without a handler for it, or with a provider that cannot answer, the round is refused as
   `unavailable`: a due challenge is never waved through. A transport that does not serve
   `captcha` meets the delay and the 429 alone, never a redirect.
5. The identifier (rule 6): the request's `login_hint`, else an answer's (the identifier step's,
   or a password answer's; no other answer's). It is checked (an email address of at most 254 bytes)
   and normalised. The first one is fixed; a different one ends the transaction, audited as
   `subject_mismatch`. With none, the identifier step; or, once a discoverable first factor is
   registered (#651), that factor first, preferred, with the password and the identifier step beside
   it (ADR-017 Decision 4).
6. The first factor (rule 7), offered alike to every account until one succeeds: the password
   required, with any other first factor beside it. The password answer is reserved on the
   `limits` hook (#636), then on the `ladder` hook (PRO-12, #615), before it is verified: inside a
   delay, a hard limit or the account's wait it is refused as `throttled`, neither verified nor
   counted.
7. After a first factor (rule 8): the downgrade rule (the transaction must prove the account's
   strongest bound factor; a disabled factor still counts as bound), then the MFA policy just read
   (a policy that requires a second factor needs `mfa` in the `amr`). A rule no registered step can
   meet answers `redirect`: an account that lacks the second factor the policy requires gets the
   set-up step, never a code. On a transport that serves `recovery_code`, a recovery code may stand
   in for the factor these rules ask for: see [Recovery codes](#recovery-codes). With
   `emailCodes`, an account whose address is not verified yet is
   verified inline before the second factor is asked for, or before completing when none is: see
   [The email code](#the-email-code). Then a password update that is due (a password on the breach
   list, or an `update_password` required action) is asked for before completing: see
   [The forced password update](#the-forced-password-update).
8. Complete (rule 9).

A registration runs the same rules with its own gate and steps: see [Registration](#registration).
So does a password reset: see [Password reset](#password-reset).

## What holds for every round

- **The same answer for every account until a factor succeeds.** An unknown identifier, a
  password-only, passkey-only, disabled or locked account and an unverified one get the same offer
  and the same error, in body and in timing; no
  account is read before a credential is answered, and then only what the password needs (the
  whole account is read once a factor proved it). Every refused password costs one Argon2id
  verification (against a dummy hash when there is no usable password). `login_hint` changes no
  offer.
- **The timing floor.** Every round answers no earlier than 500 ms
  (`SIGN_IN_MIN_RESPONSE_TIME_MS`, `MIN_RESPONSE_TIME_MS.LOGIN`) after `receivedAt`, success,
  refusal or failure.
- **Eager answers.** An answer is verified only when its step is the one the engine asks for next.
  Any other is ignored: not verified, not counted, not audited.
- **One subject per transaction.** The first identifier and the first user proven are fixed. A
  factor that names its account by itself (a discoverable passkey) offered once an identifier is
  held must prove the account that identifier names, or the transaction ends.
- **Fail closed.** A port that throws (the policy, the directory, a hook, the limits' or the
  ladder's reservation, the verifier, the identifier key) refuses the round as `unavailable`; every
  one of them that can fail before a credential is checked does so alike for every identifier.
  Settling a reservation never changes the answer: a failure there is reported through
  `onUnavailable`, and a reporter that throws changes nothing either. The engine's default ladder
  counts nothing and it has no default limits, so the plugin of
  `@qauth-labs/fastify-plugin-sign-in-engine` refuses to build a production engine without a
  `ladder` and a `limits` hook.
- **A disabled user is never changed.** It gets the ordinary invalid-credentials answer, and no
  subject is fixed, so no transport can mint for it. The engine checks this for every factor step,
  not only the password: a step that proves a disabled account (or, in an engine built without
  `emailCodes`, an unverified one under the gate) is refused like a wrong answer.
- **Try another way.** Before a factor succeeds, a step's alternatives are what every account is
  offered; after one, the account's remaining usable methods that can meet the rules. An email
  code can never be registered as a sign-in step.

## The failure ladder

`PASSWORD_LADDER_POLICY` (`src/lib/ladder.ts`) is the password's ladder (ADR-017 Decision 7): from
5 consecutive failures the next attempt waits 2^(n−5) seconds, capped at 15 minutes; an end-user IP
with a successful sign-in to the account in the last 30 days skips the wait while fewer than 20 of the
run's counted failures came from known IPs (`knownIpFreeFailures`, #968) and waits as any other
address from then on, every attempt counted; 100 consecutive counted failures fire the hard action; a run is kept after its last counted failure
2 days while it has fewer than 5 (`freeRetentionMs`) and 30 days once it has reached a wait
(`retentionMs`), by the count alone, so the same for an identifier no account holds (#969). A
correct password clears its own counter and no other (`onSuccess: 'clear'`); a counter
of failures alone only takes the attempt back (`withdraw`). The store applies the policy (the auth
server's is a Redis script in `@qauth-labs/fastify-plugin-sign-in-engine`); `ladderWaitMs` and
`checkLadderPolicy` are the one source every store and test reads.

A failure counted at the ceiling, for an enabled account whose usable password it was, calls
`passwordHardAction.ceilingReached`; the adapter disables the password only while the hard action
is armed (the realm's hosted reset is on and the deployment can send the owner the notice, asked at
run time). While it is not, the directory reports a disabled mark as `ignoredMark` and the password
stays usable, and a sign-in that proves it calls `clearIgnoredMark`. Neither call changes the
answer: a failure is reported through `onUnavailable`. `src/testing/memory-ladder.ts` is an
in-memory ladder with the same rules, for tests.

## The round limits

`createRoundLimiter(store, { ipDigest, perClient, onAlert })` (`src/lib/round-limits.ts`) is the
`limits` hook (PRO-13, #636; ADR-017 Decision 7). It keys a round by the keyed HMACs of its
end-user IP and of the IP's bucket (`endUserIpBucket`: an IPv4 address's /24, an IPv6 address's
/48; a translated or IPv4-mapped address by its IPv4 /24), and by its client only with `perClient`,
the FiPA endpoint's authenticated client (#646). A credential round is one whose answer carries a
`password`, an `otp`, a `recovery_code` or a `webauthn_response` (`isCredentialAnswer`), and an
email code. Each is reserved, counted as a failed round of every row, before the account's ladder
and the verifier, and settled after: a right credential takes the failure back (and counts once
for its account on the client row), a wrong one keeps it, and a round the ladder refused inside a
wait is withdrawn.

| Row                | Soft: a delay                                                                                         | Hard: `429`                        |
| ------------------ | ----------------------------------------------------------------------------------------------------- | ---------------------------------- |
| End-user IP        | from 10 failed rounds in 15 minutes, one round per 30 s                                               | 30 failures: 15 minutes, any round |
| The IP's bucket    | failures for more than 20 distinct identifiers in 15 minutes: each IP one round per 30 s, an alert    |                                    |
| Client (FiPA only) | a failure ratio above 50 % over at least 200 rounds, or more than 300 failures, in 5 minutes, 1 per s | above 600 rounds a minute          |

`ROUND_LIMIT_POLICY` holds the numbers; `roundLimitPolicy({ clientMaxRounds, registrationPerIp })`
derives the client's failure budget (a tenth of what `FIRST_PARTY_CLIENT_MAX_ROUNDS` admits in 5
minutes) and its delay from the rounds a minute, and takes the per-IP registration-start cap
(3 an hour by default; 1,000 an hour per client). A delay is a pace: while a soft threshold holds,
the row admits one credential round per delay and refuses the others with `Retry-After`, neither
verified nor counted. The bucket only counts identifiers: past its threshold it paces each of its
IPs, so one address cannot hold the other addresses of its network back. While a soft threshold
of its IP, its bucket or its client holds, a round also owes the bot challenge (rule 5), in
addition to the delay: the store says so on the round's `continue` verdict (`softThreshold`). In `development`
(`RoundContext.environment`, ADR-008 §5) every count is tenfold and every delay a tenth;
`staging`, `production` and an unknown value meet the numbers above.

The store (`RoundLimitStore`) makes each decision atomically; the auth server's is a set of Redis
scripts in `@qauth-labs/fastify-plugin-sign-in-engine`. `src/testing/round-limit-store-contract.ts`
is the contract every store runs, and `src/testing/memory-round-limits.ts` an in-memory store with
the same rules, for tests. An alert (an IP blocked, a bucket past its identifiers, a client past
its ratio, its budget or its rounds a minute) goes to `onAlert` once per window, with the key's
HMAC, never an address. `reserveRegistrationStart` caps registration starts for the registration
steps (#640).

## The bot challenge

`createCaptchaStep(provider)` (`src/lib/steps/captcha.ts`) is the `captcha` step (PRO-19, #643;
ADR-017 Decision 7), passed in `steps`. It is due:

- when a registration owes it: `registrations.challengeRequired` says the realm or the client
  requires one, and the transaction has passed none (see [Registration](#registration));
- while the transaction holds no unspent pass, when a soft threshold holds: the `limits` hook's
  (`softThreshold` on its `continue` verdict) or the ladder's (`ladder.softThreshold`: the round's
  identifier past the password's or the email code's free failures, `CHALLENGE_LADDER_COUNTERS`);
- or when the optional `botChallenge` hook answers `due`.

The puzzle it offers is kept in the transaction until it is answered, so the answer is read
against what was offered. A right answer leaves a pass, which the next credential round spends,
and the pending step resumes in the same round. A wrong one is refused with `captcha_failed` and
a new puzzle, and counted as a failed round on the limiters (`limits.reserve`, settled as a
failure), so a stream of wrong answers meets the hard 429. The answer, `captcha_token`, is at most
4096 bytes, and is never logged, audited or put in an error.

A `BotChallengeProvider` issues the params and checks a token; a throw is an outage, which refuses
the round. Two exist:

- `createProofOfWorkProvider({ difficulty })`, the default: a 256-bit random `challenge`, solved by
  the smallest decimal nonce whose SHA-256 over `<challenge>:<nonce>` starts with `difficulty`
  zero bits (1 to 32; the realm's `botChallenge.difficulty`, 18 by default, about 2^18 hashes).
  The server checks it in one hash. The page's solver is `solveProofOfWork` in
  `@qauth-labs/shared-interaction-client`, served from the realm origin.
- `createSiteVerifyChallengeProvider` in `@qauth-labs/fastify-plugin-sign-in-engine`: a hosted
  provider that takes a form `POST` of the secret and the token and answers `success`, reached
  through the egress client at the one verify URL the operator configured. A `false` whose
  `error-codes` blame the secret, the site key or the provider is an outage, not a wrong token.

A provider's `params` learns the transaction's `flow`, so a deployment can pick one by flow: the
auth server answers a password reset with the proof of work even when a hosted provider is
configured, since that provider's script may run on the sign-in and sign-up pages only (ADR-019
Decision 5). The callback round of an upstream provider (#639) is never held for a challenge: it
carries the provider's proof, which a challenge would throw away.

## The email code

With `emailCodes` (#638; ADR-017 Decisions 5 and 8), the correct password of an account whose
address is not verified yet proves it, whatever `REQUIRE_VERIFIED_ACCOUNT` says, and rule 8 then
verifies the address before the sign-in completes. The flow is graphed in
[`graphs/flows/core/account-verification/flow.yaml`](../../../graphs/flows/core/account-verification/flow.yaml).

- The engine draws a 6-digit code from the CSPRNG (`crypto.randomInt`; 8 digits for recovery and
  registration), mails it through the round's `sendCode` and offers
  `email_code` with the purpose `verify_account`. A send cap that answers 429 refuses the round as
  `throttled`, and nothing is held. The Interaction API never offers `confirm_sign_in`.
- The transaction holds the code only as its keyed HMAC (`emailCodes.digest`) under a salt of its
  own; an answer is digested and compared HMAC to HMAC in constant time. No audit record, answer
  or transaction holds a code.
- A code lives 10 minutes (`EMAIL_CODE_TTL_MS`), works once and belongs to its transaction. The
  transaction's 5th wrong answer burns it and ends the transaction (`code_burned`). An answer with
  no `otp` asks for a new code, one minute after the last at the earliest; the new code keeps the
  count of wrong answers.
- Every code answered within its time is reserved first on the ladder's `email_code` counter
  (`EMAIL_CODE_LADDER_POLICY`): the identifier HMAC's key with a counter of its own, across
  transactions, for addresses with and without an account. From 5 wrong codes the next attempt
  waits, 1 second and doubling up to 15 minutes; inside a wait an answer is refused (`locked_out`)
  and neither compared nor counted. It has no hard stop and never suppresses mail, and a right code
  outside a wait is accepted and clears the counter. The engine hands it no end-user IP: an
  account whose address is not proved has no owner whose IPs are known.
- A right code marks the address verified (`emailCodes.addresses`) and is recorded among the
  verified steps: it adds no `amr` value, never counts toward `mfa` and moves no `auth_time`.

An engine built without `emailCodes` keeps the gate: an unverified account's right password is
refused like a wrong one under `REQUIRE_VERIFIED_ACCOUNT`, and signs in while it is off.

## Registration

With `registrations`, `emailCodes` and `passwordUpdates`, a round whose `flow` is `register` (the
request's `prompt=create`, #640; ADR-017 Decision 8) registers a password account. The flow is
graphed in [`graphs/flows/core/sign-up/flow.yaml`](../../../graphs/flows/core/sign-up/flow.yaml).
The transaction keeps its flow from round 0: a round of another flow ends it.

- **The gate**, after the request checks, on every round: `registrations.allowed` must say that
  the realm (its sign-up switch) and the client (a redirect-flow client's `hosted_flows`, a
  native client's `first_party_policy.flows`) both allow it. Otherwise the round is refused as
  `request_refused` with `registration_not_allowed` (`REGISTRATION_NOT_ALLOWED`), audited as
  `registration_closed`, and nothing is mailed or written. An engine or a transport that cannot
  serve the identifier, `email_code` and `new_password` steps answers `redirect`.
- **The bot challenge**, after the gate, when `registrations.challengeRequired` says the realm
  (`botChallenge.requiredAtSignUp`) or the client (its operator-set `registration_challenge`)
  requires one: the `captcha` step, once a transaction, before anything is mailed. A transport
  that does not serve `captcha` is refused as `request_refused` with `registration_not_allowed`,
  never sent to a browser in its place.
- **The address**, alone: the identifier step, with no factor and no upstream provider beside it.
- **The mailbox**: an 8-digit `email_code` with the purpose `verify_account`, the same step for a
  new address and for one an account holds, in body and in timing. The first code is a
  registration start, which the `limits` hook's `reserveRegistrationStart` caps (3 an hour per
  end-user IP by default). Only the mail tells the two apart (`sendCode`'s `registration`:
  `new_address`, or `account_exists` with an "account exists" notice); and it skips no send cap
  (`afterFirstFactor: false`). Every code is otherwise the email code above: the ladder, the
  limiters, the 5th wrong answer, the resend.
- **A disabled user's address** gets no mail (`withheld`: counted on every cap, never mailed), and
  every code answered for it is answered and counted as a wrong one (`account_disabled`), a code
  mailed before it was disabled included: nothing of that user changes. Every issue and every
  right answer re-reads the account.
- **After the code**, an address no account holds gets `new_password` with the purpose `register`:
  the realm's password policy and its breach list, as for every new password. Once it passes,
  `registrations.create` creates the account in one write: the `users` row, the verified password
  credential with its normalisation marker, and the verified address. An address another account
  took meanwhile ends the transaction (`registration_conflict`; FiPA's `invalid_session`). No
  account exists before both the code and the password pass. The registration completes with
  `registered: true` and neither `amr` nor `authTime` (ADR-017 Decision 10).
- **An address an account holds** is helped to sign in: rule 7's first factor, then rule 8 as for
  any sign-in. An account whose address is not verified yet is verified once its password is
  proved, since the same person proved the mailbox and the password. Until PRO-17 (#641) ends an
  unclaimed account instead, that holds for one too.

## Password reset

With `resets`, `emailCodes` and `passwordUpdates`, the engine resets a password (#642; ADR-017
Decision 8). The flow is graphed in
[`graphs/flows/core/password-reset/flow.yaml`](../../../graphs/flows/core/password-reset/flow.yaml).
A reset starts from the `password_reset` step: the alternative rule 7 offers beside the first
factors, the same for every address, or round 0 of a round whose `flow` is `reset`. Its answer
turns the transaction into a reset; a `login_hint` it brings must name the address the transaction
holds, else the transaction ends. A transaction keeps its flow from then on, and a reset never
goes upstream.

- **The gate**, on every round: `resets.allowed` must say that the realm and the client allow the
  `reset` flow. Closed, the reset is not offered, and a round of a reset is refused as
  `request_refused` with `reset_not_allowed` (`RESET_NOT_ALLOWED`), audited as `reset_closed`. An
  engine or a transport that cannot serve `password_reset`, `email_code` and `new_password` does
  not offer it, and answers a reset `redirect`. **Under `max_age` or `prompt=login`**
  (`freshSignIn`) it is never offered, and a round of a reset answers `redirect` (`request`): a
  reset proves no factor, so it can never satisfy them.
- **The mailbox**: an 8-digit `email_code` with the purpose `recovery`, the same step for every
  address, in body and in timing. Only the mail tells them apart (`sendCode`'s `reset`: `account`
  for an enabled account with a password and a verified address; `withheld` for every other
  address, counted on every cap and never mailed). A code answered for a disabled user, an unknown
  address, an account without a password or an unclaimed account (its address never verified) is
  answered and counted as a wrong one: nothing of that user changes. An unclaimed account may be
  someone else's squat on the address, and a reset would keep its `sub` (audited as
  `account_unclaimed`): PRO-17 (#641) ends such an account at the first mailbox proof instead.
- **Every other authenticator** the account holds (a passkey, TOTP), disabled or not, is proved
  next, with any registered, served step that proves it; an email code never stands in for it, and
  a recovery code may, on a transport that serves `recovery_code` (#649). When none can, the answer
  is `redirect` and nothing is written.
- **The new password**: `new_password` with the purpose `reset`, through the realm's password
  policy and its breach list, as for every new password. Every eager answer before is ignored.
  `resets.reset` writes it and ends what the old password opened (see the adapter); an account
  disabled meanwhile, or that is no longer the transaction's subject, ends the transaction.
- **The completion** is `recovered: true` with neither `amr` nor `authTime`: a reset proves the
  mailbox, not a factor (ADR-017 Decision 10). The transaction of a reset holds its subject with no
  `auth_time`. The completion carries the session epoch the reset advanced to (`epoch`), so the
  transport can end whatever the reset finished at a later reset.

**The session epoch.** With `sessionEpochs`, every round of a transaction that holds a subject
reads the time of that user's last reset (`notBefore`, a margin included); a transaction created
no later ends (`reset_since`). A reset therefore ends every live interaction of the user that is
still in the engine. Two resets of one account whose last rounds run at the same time can both
write: the check runs at the start of each round, not in the reset's write. A read that fails
refuses the round as `unavailable`.

## Recovery codes

With `recoveryCodes`, a lost second factor is recovered with a recovery code (#649; ADR-017
Decisions 7 and 8, ADR-018 §3). The flow is graphed in
[`graphs/flows/core/recovery-code/flow.yaml`](../../../graphs/flows/core/recovery-code/flow.yaml).
Both steps are Interaction-API-only: a transport that does not serve them (the FiPA endpoint, by
its `serves`) never sees them, and a round that needs one answers `redirect` (FiPA:
`redirect_to_web`).

- **A set** (`createRecoveryCodeService`, `src/lib/recovery-codes.ts`) is 10 codes of 80 bits
  each from the CSPRNG, shown as `xxxx-xxxx-xxxx-xxxx` in lowercase base32 and typed back with any
  case, spaces and dashes. Only salted hashes from the password hasher (Argon2id) are stored. A
  code is checked against every unused hash of the set, padded to 10 with a decoy, so the check
  costs the same however many are left, and it is taken in one conditional write: it works once.
  Issuing a set replaces the old one, every code of which stops working.
- **Redemption** (`recovery_code`, its answer `recovery_code`): after the first factor, rule 8
  offers it beside the factor's own steps (the downgrade rule's, the MFA policy's, the forced
  update's factor beyond the password) while the account holds an unused code, once a transaction.
  It stands in for that factor and adds no `amr` value, never `mfa`, and leaves `auth_time` as the
  first factor set it. So an MFA policy is never met by a code: the factor the account still holds
  is asked for next, and with none the round is `redirect` to bind a new one (the set-up steps of
  #651 and #653). A wrong code is refused with `invalid_credentials`, the same for a wrong code, a
  used one and one of another set.
- **The ladder.** Wrong codes count on the `recovery_code` counter of the failure ladder, keyed on
  the account rather than an identifier, so every transaction and every end-user IP share it, and
  a right password never clears it (`RECOVERY_CODE_LADDER_POLICY`): from 5 failures the next
  attempt waits 2^(n−5) seconds up to 15 minutes, no known IP skips the wait, and once the account
  is past its free failures the `captcha` step comes before the next answer is read. Each wrong
  code counted at or past the hard ceiling of 100 calls `recoveryCodes.ceilingReached`, which tells
  the user and the operator; a failure there changes no answer. A right code clears the counter.
- **A new set, shown once** (`recovery_codes`, its params `{ count: 10 }`): a sign-in that proved
  a factor beyond the password, of an account with no set the person confirmed, issues one before
  it completes. The codes are the round's personal data alone; the step is answered
  `acknowledged: true`, which marks the set confirmed (`recoveryCodes.confirm`), and a round
  without that confirmation issues a new set in place of the one shown. A set nobody confirmed (a
  closed tab, a lost answer) was never seen for sure, so the next such sign-in replaces it with a
  new one. A transport that does not serve it answers `redirect`.

## The forced password update

With `breachCheck` (#635; ADR-018 §3, ADR-020 §3, ADR-017 Decision 8), a password that proved its
account is checked against the realm's breach list, in the form it was verified (NFC when the
credential records it). Only a right password is checked: a wrong one, and the dummy verification of
an identifier no account holds, never reach the list. The port answers `off` (the realm's setting
is off: nothing changes), `not_listed`, `listed` or `failed`; a port that throws counts as
`failed` (`unavailable`). **A failed check never blocks a sign-in**: the sign-in goes on as if the
password were not listed, and the round writes an `unchecked` audit record naming the failure
(`breach_check_failed`). A listed password is remembered in the transaction (`breachedPassword`).

A password update is due when the password proved the account and was listed, or the account holds
an `update_password` required action (`SignInAccount.requiredActions`, read with the whole account;
a directory that reads none fails closed). An action the transaction saw is remembered in it
(`updatePasswordRequired`): another sign-in that sets a new password, and so removes the action,
never releases one that proved only the old password. It is never asked for before the rest of
rule 8:

- An account with a factor beyond the password (TOTP, a passkey) proves that factor first, whatever
  the MFA policy says; an email code never stands in for it. When no registered, served step can
  ask for it, the answer is `redirect`.
- A password-only account proves its mailbox first: an 8-digit `email_code` with the purpose
  `recovery`, as a reset does. A code the transaction already took for the mailbox (the inline
  verification of an unverified address) counts, and no second one is mailed.

Then the engine asks for `new_password` with the purpose `update_required` (`min_length` from
`passwordUpdates.minLength`, `max_length` 256). Until the update is written no code or session is
issued, and every eager answer (a new password before the mailbox code or the factor) is ignored.
A new password is checked against the realm's password policy and then the breach list; a refused
one is asked for again with `password_rejected` and its reasons (a listed one as `blocklisted`),
audited as `password_rejected` or `password_breached`. A failed check of the new password does not
refuse it, and is recorded the same way. `passwordUpdates.replace` writes the new hash and clears
the `update_password` required action; an account that was disabled meanwhile, or that is not the
transaction's subject, ends the transaction. The update adds no `amr` value: the sign-in completes
with the `amr` of the factors that proved it.

An update the sign-in cannot run answers `redirect`: an engine built without `passwordUpdates`, a
transport that does not serve `new_password`, a password-only account in an engine built without
`emailCodes`, and a transaction that holds no identifier.

## Audit records

Each processed step writes one record through the round's `audit` sink: `passed`, `refused` or
`ended`, the step, the reason, and the person by the transaction's subject once a factor fixed one,
by the identifier's keyed HMAC before; a refused answer never names a user it happened to resolve,
and a step refused before the transaction holds any identifier names nobody. A solved bot challenge
is a `passed` record too. So is every refusal of the whole round: a limiter's (`rate_limited`), the
request checks' (`request_refused`) and a malformed answer (`invalid_answer`) are `refused`
records, and a transaction the round may not use (`transaction_invalid`, `transaction_expired`) an
`ended` one that names nobody. Such a record names the step the answer names when the engine has a
handler for it, else the identifier step. A record never holds a password, a code or the
identifier. A sink that fails fails the round. A breach-list check that failed adds an `unchecked`
record after the step's own (`breach_check_failed`, with the failure), naming the subject. The
adapters map them onto `user.sign_in_step_passed`, `user.sign_in_failed` and
`user.password_breach_check_failed`.

## Adding a step

A step joins the engine as a `StepHandler` (`src/lib/steps/handler.ts`), passed in `steps`: its
role (`challenge`, `first_factor`, `second_factor`), the factor it proves, whether an account can
use it, its params and personal data, and how it verifies an answer the step grammar has already
read. A first factor may be `discoverable` (a passkey that names the account by itself): it is
offered before any identifier, and after the password once one is held. A handler refuses a
disabled account itself, settling its ladder as a failure. Passkeys (#651) and TOTP (#653) come this
way; `totp` only as a second factor. An `email_code` or `new_password` step handler is refused when
the engine is built: the email code and the forced update are the engine's own, and never an
authenticator.

## Known gaps, for the issues that follow

- The per-transaction budgets of the FiPA `auth_session` (rounds, failures per step) are #647's.
- An answer is read against the params the engine computes for the round, not a stored copy of the
  ones it offered. The `captcha` step keeps its offered params in the transaction (#643); another
  challenge handler whose params change every round needs the same first.
- ADR-017 Decision 7 counts an end-user IP that changes within a transaction as a soft threshold.
  The transaction does not hold the IP, so that one is not applied yet.
- The policy has no storage yet: `NO_SECOND_FACTOR_POLICY` is the default until it has one.
- A due password update in a transaction that holds no identifier (a discoverable passkey that
  proved the account by itself, #651) answers `redirect`: the mailbox code needs the identifier.
- A registration for an unclaimed account (a password account whose address is not proved) is
  helped to sign in to it; PRO-17 (#641) ends that account and registers the mailbox owner instead.
  A reset of one is withheld (no mail, no change) until #641 applies the same rule there.
- No step can prove a passkey in a hosted reset until the passkey step (#651) is registered: such an
  account is answered `redirect` until then, unless a recovery code stands in for it (#649), and
  keeps its password.
- A recovery code stands in only after the first factor. A passkey-only account (PRO-30) has none
  before its passkey, so a code in place of that passkey waits for the passkey step (#651) and
  #655; such an account gets its set when it first proves the passkey, as every account with a
  factor beyond the password does.
- Of the required actions only `update_password` is acted on; `setup_mfa`, `setup_passkey` and
  `complete_profile` wait for the steps that set them up.
