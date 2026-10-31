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

| Module                      | What                                                                                           |
| --------------------------- | ---------------------------------------------------------------------------------------------- |
| `lib/grammar.ts`            | `defineStep`, and what a step is: name, URN, transports, params, personal data, answer, errors |
| `lib/zod-kit.ts`            | Zod builders, one per JSON Schema builder of the contract (display text, base64url, URIs, …)   |
| `lib/steps/*.ts`            | The 17 steps, by area; `lib/steps/index.ts` lists them and derives the constants and types     |
| `lib/json-schema.ts`        | Zod to JSON Schema, in the contract's spelling (`const`, integer enums, open objects)          |
| `lib/step-files.ts`         | Each step's schema file, generated from the grammar with the contract's file layout            |
| `lib/offer.ts`              | `StepOffer`: what the engine offers next, before a transport wraps it; the grammar's checks    |
| `lib/interaction-mapper.ts` | The Interaction API mapper: the step-grammar members of the step read                          |
| `lib/fipa-mapper.ts`        | The FiPA mapper: `403 insufficient_authorization`, or `403 redirect_to_web`                    |
| `lib/mapping-error.ts`      | `StepMappingError`: why a mapper refused an offer (a code fault, never sent)                   |
| `lib/formats.ts`            | The `uri` and `date-time` checks of ajv-formats, which the Zod schemas run beside each pattern |
| `lib/vectors.ts`            | The contract's step examples as shared test vectors, with each transport's answer              |
| `scripts/export-vectors.ts` | Writes `test-vectors/interaction/steps.json`. Nothing imports it                               |

## What it exports

- `STEP_GRAMMAR`, `STEP_LIST`, `STEP_NAMES`: every step; `StepName`, `StepParams<N>`,
  `StepAnswer<N>`, `StepPersonal<N>`, `StepError<N>` are inferred from the Zod schemas.
- `STEP_URNS`: each step's name on the wire, `urn:qauth:ia:<name>:v1-rc.0`, typed as its literal.
- `STEP_ERRORS`, `STEP_ERROR_CODES`: each step's closed error set, and their union.
- `STEP_AMR`: the RFC 8176 values a successful answer adds (`password` `pwd`, `webauthn_get`
  `pop` and `mfa`, `totp` `otp`, none for the others).
- `FIPA_STEP_NAMES`, `INTERACTION_ONLY_STEP_NAMES`: the nine steps ADR-017 lists, which the FiPA
  endpoint may serve, and the eight only the Interaction API serves.

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
  authSession, // the round's new handle
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
  `interaction_types_supported`) gives `403 redirect_to_web`; as an alternative it is left out. A
  bot challenge is the one exception: it never becomes `redirect_to_web` (ADR-017 Decisions 4 and
  7), so the mapper throws and the engine throttles instead.
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
  `password_rejected`, and its `min_length` is not above its `max_length`.
- **Personal data is parsed before it is served.** `personalView(offer, data)` on the Interaction
  API mapper gives the personal data read (`PersonalData` in the contract): the current step's
  personal data, parsed by its step's strict schema into a new object. A member the step does not
  declare (a user row spread in whole) or a value outside its schema is refused with
  `invalid_personal_data`, whose message names paths, never values. An alternative's personal data
  is never served, and the FiPA mapper has no counterpart: personal data never goes to the FiPA
  endpoint.
- **What may be answered next** is what the output names: the step read's `step` and
  `alternatives`, or the FiPA body's `qauth_interaction_types_offered` (none after
  `redirect_to_web`). A transport accepts an answer only to one of those.
- **The FiPA round** carries the realm's issuer (no query or fragment; `http` only for a
  development realm), the new `auth_session` (43 base64url characters) and the client's parsed
  `interaction_types_supported`, at most 16 entries.
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
the step. The shared vectors are append-only (`test-vectors/README.md`): a changed example needs a
new case id, not an edited case.

Zod and the published schema's validator read the same rules, `format` included: the Zod schemas
run ajv-formats' `uri` and `date-time` checks, the ones the contract's own tests validate with.
Two differences remain, on purpose. Zod counts a string's length in UTF-16 code units, where JSON
Schema counts code points: stricter against a maximum, and no value is affected against a minimum,
because every string with a minimum above one is held to ASCII by its pattern or parsed as JSON.
And the server parses a WebAuthn response string as the JSON document it names, which JSON
Schema's `contentSchema` only annotates.

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
| `zod-kit.test.ts`            | A value over its maximum length is refused before a pattern, a `format` or a JSON parse reads it                      |
| `exhaustive.test.ts`         | Runs the TypeScript compiler: a step without a mapper fails the type check                                            |
| `vectors.test.ts`            | The committed vectors are what the mappers give, and a reader recovers each step from them                            |
