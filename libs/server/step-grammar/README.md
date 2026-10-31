# @qauth-labs/server-step-grammar

The step grammar (#591, ADR-017 Decision 3, ADR-019 Decision 6, ADR-018 §5): every step of a
sign-in ceremony as Zod schemas, its closed error set and its `amr`, and one mapper per transport.
The Interaction API (browser ceremonies) and the FiPA authorization challenge endpoint (native
apps) both serve the same steps; only the envelope differs. Pure: no I/O outside the export script.

The published reference is the Interaction API contract (#590,
`libs/shared/interaction-contract`): one JSON Schema per step under
`apps/docs-site/public/interaction/v1-rc.0/steps/`. The JSON Schema generated here from the Zod
schemas must equal those files, so what the server checks at run time and what the contract
publishes cannot drift apart.

## What it holds

| Module, under `src/`        | What                                                                                            |
| --------------------------- | ----------------------------------------------------------------------------------------------- |
| `lib/grammar.ts`            | `defineStep`, and what a step is: name, URN, transports, params, personal data, answer, errors  |
| `lib/zod-kit.ts`            | Zod builders, one per JSON Schema builder of the contract (display text, base64url, URIs, …)    |
| `lib/steps/*.ts`            | The 17 steps, by area; `lib/steps/index.ts` lists them and derives the constants and types      |
| `lib/json-schema.ts`        | Zod to JSON Schema, in the contract's spelling (`const`, integer enums, open objects)           |
| `lib/step-files.ts`         | Each step's schema file, generated from the grammar with the contract's file layout             |
| `lib/offer.ts`              | `StepOffer`: what the engine offers next, before a transport wraps it; the grammar's checks     |
| `lib/interaction-mapper.ts` | The Interaction API mapper: the step-grammar members of the step read                           |
| `lib/fipa-mapper.ts`        | The FiPA mapper: `403 insufficient_authorization`, or `403 redirect_to_web`                     |
| `lib/mapping-error.ts`      | `StepMappingError`: why a mapper refused an offer (a code fault, never sent)                    |
| `lib/amr.ts`                | `transactionAmr`: a transaction's `amr` from the steps it verified (ADR-017 Decision 10)        |
| `lib/answer-error.ts`       | `StepAnswerError`: why an answer was refused before the engine read it (a fault of the request) |
| `lib/formats.ts`            | The `uri` and `date-time` checks of ajv-formats, which the Zod schemas run beside each pattern  |
| `lib/vectors.ts`            | The contract's step examples as shared test vectors, with each transport's answer               |
| `scripts/export-vectors.ts` | Writes `test-vectors/interaction/steps.json`. Nothing imports it                                |

## What it exports

- `STEP_GRAMMAR`, `STEP_LIST`, `STEP_NAMES`: every step; `StepName`, `StepParams<N>`,
  `StepAnswer<N>`, `StepPersonal<N>`, `StepError<N>` are inferred from the Zod schemas.
- `STEP_URNS`: each step's name on the wire, `urn:qauth:ia:<name>:v1-rc.0`, typed as its literal.
- `STEP_ERRORS`, `STEP_ERROR_CODES`: each step's closed error set, and their union.
- `STEP_AMR`: the `amr` values a successful answer adds, from RFC 8176 §2 and the IANA-registered
  `pop` (`password` `pwd`, `webauthn_get` `pop` and `mfa`, `totp` `otp`, none for the others).
- `FIPA_STEP_NAMES`, `INTERACTION_ONLY_STEP_NAMES`: the nine steps ADR-017 lists, which the FiPA
  endpoint may serve, and the eight only the Interaction API serves.
- `transactionAmr(verifiedSteps)`: a transaction's `amr`, ADR-017 Decision 10's table, from the
  steps it verified with the params they were offered with. Each step adds its `STEP_AMR` values,
  and factors of two kinds add `mfa` (password and TOTP give `["pwd","otp","mfa"]`). An email code
  or a recovery code adds nothing. A registration or a reset, whatever else it verified, and a
  transaction that verified no factor give `undefined`: no `amr` and no `auth_time`.
- The steps, their lists, the constants above, the mapper tables and `FIPA_SERVES_ALL` are frozen.
  The freeze is shallow: the Zod schemas a step holds are Zod's own objects and are not frozen, so
  no code may change them.

## The mappers

The engine is transport-neutral (ADR-017 Decision 4). It gives a `StepOffer`: the step it asks
for, with its params and, after a refused answer, that step's error, and the alternatives it
accepts next. Each mapper checks the offer against the grammar (known steps, params valid for their
step, an error only from the current step's closed set, no step twice, no member the grammar does
not define) and then wraps it:

```ts
import { createFipaMapper, createInteractionMapper } from '@qauth-labs/server-step-grammar';

const offer = {
  current: { step: 'password', params: {}, error: 'invalid_credentials' },
  alternatives: [{ step: 'password_reset', params: {} }],
} as const;

createInteractionMapper().stepView(offer);
// { step: 'urn:qauth:ia:password:v1-rc.0', error: 'invalid_credentials',
//   alternatives: ['urn:qauth:ia:password_reset:v1-rc.0'], params: { …: {}, …: {} } }

createFipaMapper({ serves: ['identifier', 'password', 'password_reset'] }).challenge(offer, {
  issuer: 'https://auth.example.com',
  newAuthSession, // makes the round's new handle, called only when the body carries it
  interactionTypesSupported, // the client's list, parsed
});
// { status: 403, body: { error: 'insufficient_authorization', iss, auth_session,
//   interaction_type_required, qauth_interaction_types_offered, qauth_interaction_params,
//   qauth_interaction_error } }
```

- **Which steps a transport serves is its configuration**, not the grammar's: `serves` lists them.
  The Interaction API serves every step by default. The FiPA mapper accepts only the steps
  ADR-017 lists, in the type check and at run time.
- **The FiPA mapper never serialises a step only the Interaction API serves.** As the required
  step, such a step (or one this deployment does not serve, or one the client did not list in
  `interaction_types_supported`) gives `403 redirect_to_web`; as an alternative it is left out.
- **A preferred step gives way; a required one does not.** The offer's `required` says whether the
  current step is required or only preferred, and an offer without it is required (fail closed).
  When the FiPA endpoint cannot serve a current step that is not required, and the client can
  answer one of the alternatives, the first such alternative becomes `interaction_type_required`,
  with its own params and no error carried over: in ADR-017 Decision 4's passkey-first round, a
  client that cannot do passkeys gets `password`. A required step (a second factor, or any step
  the engine marks required) still gives `redirect_to_web`. The Interaction API serves every step,
  so it puts nothing of the flag on the wire.
- **A bot challenge never becomes `redirect_to_web`** (ADR-017 Decisions 4 and 7). The engine asks
  `negotiates('captcha', listing)` before it offers one, and answers a client that cannot answer it
  with its own delay and 429. An offer of one to such a client is refused with `not_negotiated`,
  a fault of the engine like every `StepMappingError`.
- **Passkey enrolment on the FiPA endpoint** (`webauthn_create`) is offered only to an account
  that already holds a recovery-code set: a first enrolment issues the set, and only the hosted
  pages show it (`recovery_codes` is the Interaction API's alone). Any other account gets
  `redirect_to_web`. That is the engine's rule (#614, #665); the offer does not say whether the
  account holds a set, so the mapper cannot check it.
- **No prose.** No output carries `error_description` or a sentence the server writes: every string
  is a step name, an error code, an envelope value or a bounded token (a `const`, an `enum` or a
  token pattern). The only params that hold words are text the realm's admin set, under the display
  rule: a scope's consent text and the realm's name in the passkey options. An offer with a member
  the grammar does not define, a params value outside its schema or an error outside the closed set
  is refused with a `StepMappingError`, which the transport answers as an internal error. What each
  per-step mapper returns is parsed again by the step's schema.
- **Rules between members.** A bot challenge (`captcha`) is offered alone and never as an
  alternative: the pending step resumes after it, so no other answer may skip it (ADR-017
  Decision 4). `new_password` carries `reasons` exactly when its last answer was refused with
  `password_rejected`, and its `min_length` is not above its `max_length`. An `email_code` has the
  length its purpose takes (ADR-017 Decision 5: 8 digits for `recovery`, 6 for `confirm_sign_in`,
  8 or 6 for `verify_account`, at registration or after a password) and an `expires_in` of at most
  600 seconds. The published schema is wider (6 or 8 digits for any purpose, up to a day); the
  server's offers keep to these.
- **Personal data is parsed before it is served.** `personalView(offer, data)` on the Interaction
  API mapper gives the personal data read (`PersonalData` in the contract): the current step's
  personal data, parsed by its step's strict schema into a new object. A member the step does not
  declare (a user row spread in whole) or a value outside its schema is refused with
  `invalid_personal_data`, whose message names paths, never values. An alternative's personal data
  is never served, and the FiPA mapper has no counterpart: personal data never goes to the FiPA
  endpoint.
- **What may be answered next** is what the output names: the step read's `step` and
  `alternatives`, or the FiPA body's `qauth_interaction_types_offered` (none after
  `redirect_to_web`). Each mapper's `readAnswer` enforces it, with one implementation for both
  (`readAnswer` in `lib/offer.ts`): `interaction.readAnswer(lastOffer, stepUrn, form, encoding)`
  and `fipa.readAnswer(lastOffer, listing, stepUrn, form)` refuse a step the transport did not
  present with `not_offered`, take only the answered step's own members from the body (the
  envelope's members and another step's fields stay behind), parse them with the step's strict
  answer schema, and check them against the params the step was offered with: a code has exactly
  the offered number of digits (`email_code`, `totp`, `totp_setup`), and a passkey enrolment the
  person may not decline carries a response. A refusal is a `StepAnswerError` (`invalid_answer`),
  a fault of the request that the transport answers as a malformed request and the engine never
  counts as a failed credential; its message names paths, never values. A form post's `true` and
  `false` are read as booleans. What only the engine knows stays the engine's: a password policy's
  bounds (`password_rejected`), whether the transaction already holds an identifier, a device
  code's letters.
- **The FiPA round** carries the realm's issuer (no query, fragment or userinfo; `http` only for a
  development realm), `newAuthSession`, which makes the round's new handle (43 base64url
  characters), and the client's parsed `interaction_types_supported`, at most 16 entries. The
  mapper calls `newAuthSession` once, and only for an answer that carries the handle
  (`insufficient_authorization`), after every check: a `redirect_to_web` or a refused offer makes
  none. The endpoint burns the old handle first and binds the one the body carries (ADR-017
  Decision 6).
- **Exhaustive.** Each mapper has a table keyed by the step union, so a step added to `STEP_LIST`
  without an entry on both transports fails the type check; on the FiPA table a step only the
  Interaction API serves takes the `INTERACTION_ONLY` marker, and cannot take a mapper.

## Changing a step

A step is defined twice on purpose: here as Zod (the server's checks and types), and in the
contract as published documentation. Change both, then regenerate what is generated:

```bash
pnpm exec nx run shared-interaction-contract:contract-export
pnpm exec nx run server-step-grammar:vectors-export
```

`json-schema.test.ts` fails while a generated step file differs from the published one, and names
the step. The shared vectors follow the contract's release candidate (`test-vectors/README.md`):
until QAuth 1.0.0 the generated file is replaced whole when an example or a mapper changes, and its
cases keep their ids; from 1.0.0 on its cases are fixed, and a changed one needs a new case id.

Zod and the published schema's validator read the same rules, `format` included: the Zod schemas
run ajv-formats' `uri` and `date-time` checks, the ones the contract's own tests validate with.
Both count a string's length in code points (Zod since 4.5). Two differences remain, on purpose.
A password (`password`, `new_password`) is counted in UTF-16 code units, as ADR-017 Decision 8 and
the published description say, through `passwordSchema` from `@qauth-labs/shared-validation`:
stricter than the published `maxLength` for a character outside the Basic Multilingual Plane, so
129 emoji are refused. And the server parses a WebAuthn response string as the JSON document it
names, which JSON Schema's `contentSchema` only annotates.

## Known gaps, for the issues that serve these steps

- On the FiPA endpoint, `new_password` sends the contract's `purpose` (`register`, `reset` or
  `update_required`), which ADR-017 Decision 3's table does not list for that endpoint.
- `webauthn_create` keeps the account's `user` and `excludeCredentials` in its personal data,
  which only the Interaction API reads. A native app on the FiPA endpoint needs them in the
  creation options; the passkey enrolment issue decides where they go.

## The tests

| Test                         | What it holds the grammar to                                                                                          |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `json-schema.test.ts`        | The generated step files equal the published ones; every INT-01 example validates; Zod and the published schema agree |
| `offer.test.ts`              | The rules between members, the second check of mapper output, and frozen tables and lists                             |
| `steps.test.ts`              | The names, URNs, transports, errors and `amr` equal the contract's                                                    |
| `interaction-mapper.test.ts` | The step view and personal data read of every example equal the contract's examples                                   |
| `fipa-mapper.test.ts`        | ADR-017's wire examples; `redirect_to_web`; `interaction_type_required` is always a version-1 name                    |
| `no-prose.test.ts`           | No output of either mapper, personal data included, carries prose; an offer that tries is refused                     |
| `answer.test.ts`             | Every example answer on both transports; an answer to a step not presented, foreign members, lengths, empty answers   |
| `amr.test.ts`                | Every row of ADR-017 Decision 10's `amr` table, and what adds nothing                                                 |
| `zod-kit.test.ts`            | A value over its maximum length is refused before a pattern, a `format` or a JSON parse reads it                      |
| `exhaustive.test.ts`         | Runs the TypeScript compiler: a step without a mapper fails the type check                                            |
| `vectors.test.ts`            | The committed vectors are what the mappers give, and a reader recovers each step from them                            |
