---
title: Wallet sign-in (OID4VP)
description: The browser wallet-login flow — the asserted-identifier step, QR / deep-link targeting, fail-closed gating, account linking, and how to turn the flow on.
sidebar:
  order: 7
lastVerified: '2026-08-07'
---

How an end user signs in with a wallet credential, what the server does at each
step, and what is deliberately not built yet. Implements
[ADR-004](/reference/records/adr/004-wallet-agnostic-federation/) and
[ADR-009](/reference/records/adr/009-wallet-account-resolution/) (issue #239).

> **Status (updated by #238): the sign-in completes, and a wallet credential can
> be linked to an existing account.** Presentation validation (#234), issuer
> trust (#236) and subject resolution (#300) are now wired end to end — see
> [The authentication seam](#the-authentication-seam) and
> [Account linking](#account-linking-238). A deployment additionally has to
> configure `OID4VP_ISSUER_JWKS` (whose key each issuer signs with) and
> `OID4VP_SUBJECT_BINDING_CLAIMS` (the entitlement check). Since #379 the second
> of those is a **boot requirement**, not a runtime one: a deployment with
> `WALLET_FEDERATION_ENABLED=true` and no usable subject-resolution
> configuration now **refuses to start**, naming the variable to set. It
> previously started and then refused every presentation.
>
> Claims normalization into `user_attributes` (#235) landed too: a validated
> credential's claims become `source='wallet'` attribute rows, and a first
> presentation for an unknown identifier enrols the account (ADR-009 §1's first
> bootstrap case).
>
> The whole flow is covered end to end against real containers and a mock wallet
> (#240) — see [End-to-end tests](#end-to-end-tests-and-the-mock-wallet-240).
> Interoperability with a REAL wallet remains **unverified**.

## Where it lives

The browser-facing screens are server-rendered by `apps/auth-server`, next to the
password login they extend:

| Path                                  | What it does                                                                      |
| ------------------------------------- | --------------------------------------------------------------------------------- |
| `GET /ui/login`                       | Password form; offers a **Sign in with your wallet** link when the flow is usable |
| `GET /ui/wallet-login`                | Collects the account identifier the user asserts                                  |
| `POST /ui/wallet-login`               | Issues an OID4VP request and renders the QR code + deep link                      |
| `GET /ui/wallet-login/:handle`        | Re-renders a flow in progress; the no-JavaScript refresh path                     |
| `GET /ui/wallet-login/:handle/status` | Polled by the page; completes the sign-in when the wallet has responded           |
| `GET /ui/wallet-link`                 | **Signed-in only.** Confirmation screen for linking a wallet credential (#238)    |
| `POST /ui/wallet-link`                | Starts a linking flow and renders the QR code + deep link                         |
| `GET /ui/wallet-link/:handle`         | Re-renders a linking flow; the no-JavaScript refresh path                         |
| `POST /auth/link/wallet`              | JSON API: starts a linking flow (session cookie + `X-CSRF-Token`)                 |
| `GET /auth/link/wallet/:handle`       | JSON API: polls, and completes the link when the wallet has responded             |
| `POST /oid4vp/response`               | The `response_uri` the **wallet** posts to (issue #233) — not a browser surface   |
| `GET /oid4vp/request/:handle`         | The `request_uri` a **wallet** fetches a signed request object from (#377)        |

`libs/ui` is the React primitive set used by the developer portal; it is not
involved here.

## The flow

1. **The user asserts an account.** The identifier field is REQUIRED. ADR-009
   Decision §1: `asserted-lookup` is the universal default because no
   protocol-guaranteed stable wallet subject identifier exists, so **there is no
   usernameless wallet login**. The user says which account they mean; the
   presentation proves entitlement to it. The identifier is normalized exactly as
   the password provider normalizes an email, because it lands in the same
   `user_credentials.external_sub` column.

   It is never looked up at this step. Every submission renders a QR code whether
   or not the account exists, so the screen is not an account oracle.

2. **The server issues a presentation request.** An OID4VP 1.0 Authorization
   Request (`response_type=vp_token`, `response_mode=direct_post`) is built under
   the active `VerifierProfile`, its `state` digest is persisted, and the wallet
   invocation URI is rendered as a QR code and an **Open my wallet** deep link.
   The URI is **opaque to the UI**: under `oid4vp-1.0-base` it carries the request
   inline; under a profile that mandates signed requests it is a `request_uri`
   reference to a signed JAR the wallet fetches from
   `GET /oid4vp/request/:handle` (#377). The page renders what the backend
   produced, and which form it is follows from the Client Identifier Prefix
   rather than from a setting.

3. **The wallet responds.** It posts the Authorization Response to
   `POST /oid4vp/response`, which redeems the single-use `state` and publishes a
   transport signal. That signal says a structurally valid `vp_token` came back —
   nothing about who presented it.

4. **The browser is told.** The page polls the status endpoint every three
   seconds. On completion it navigates to the original `return_to`; on any failure
   it shows one fixed sentence.

## Scope decision — QR / deep link only

OID4VP 1.0 offers two ways to reach a wallet: the cross-device QR / same-device
deep link, and the browser-native **Digital Credentials API**, whose `origin:`
Client Identifier Prefix is reserved for it.

**This ships QR/deep-link only.** The DC API path needs the `origin:` prefix,
which QAuth's client-identifier module does not implement. Signed requests are no
longer the blocker — #377 wired the ES256/JAR crypto from #298 into the request
path — but the missing prefix still is. Shipping half of it would mean an entry point
that works in one browser build and fails everywhere else. Because the invocation
URI is treated as opaque throughout, adding the DC API later changes what the
backend produces, not the structure of these screens.

## Fail-closed gating

The wallet entry point appears only when the deployment can actually serve the
flow. Every one of these turns it off — with no button rendered, rather than a
button that fails:

- `WALLET_FEDERATION_ENABLED` is off (default). The routes are not registered at
  all: the paths 404.
- No `VerifierProfile` is selected, or the selected one is not provisioned. There
  is never a fallback to the more capable profile (#296, LOCKED).
- The profile mandates SIGNED requests and the deployment provisioned no verifier
  signing material. Signing itself is built (#377): a deployment that configures
  `OID4VP_VERIFIER_SIGNING_KEY` and its chain signs an `x509_hash`-identified
  request and delivers it by `request_uri`. What is refused is the profile
  mandating it with nothing to sign with.
- The profile's response posture contradicts its permitted modes — a table
  entry requiring encryption while listing only plain `direct_post`, say. An
  encrypted response itself is never a reason: `direct_post.jwt` is built (#377
  Phase C) and needs nothing provisioned, because the ECDH-ES key is minted per
  request, published in `client_metadata.jwks`, and the private half rides the
  request-state row until the wallet's JWE arrives. `OID4VP_RESPONSE_KEY_SECRET`
  optionally wraps that stored key in AES-256-GCM; unset, it is stored in the
  clear beside the `nonce` that already is.
- The profile does not permit `dc+sd-jwt`, the one credential format QAuth ships
  an adapter for.
- `OID4VP_REQUESTED_VCT` is unset. A DCQL query with no type constraint asks a
  wallet for any credential it holds, which OID4VP 1.0 §15.6 warns Verifiers
  against.

## Configuration

| Variable                            | Default        | Notes                                                             |
| ----------------------------------- | -------------- | ----------------------------------------------------------------- |
| `WALLET_FEDERATION_ENABLED`         | `false`        | Registers the wallet provider and these routes                    |
| `OID4VP_VERIFIER_PROFILE`           | _(none)_       | `oid4vp-1.0-base`, or `haip-1.0` once fully provisioned (#377)    |
| `OID4VP_REQUESTED_VCT`              | _(none)_       | Comma-separated `vct` values; **no wallet flow without it**       |
| `OID4VP_WALLET_INVOCATION_ENDPOINT` | `openid4vp://` | The wallet Authorization Endpoint the QR and deep link target     |
| `OID4VP_VERIFIER_SIGNING_KEY`       | _(none)_       | ES256 key the Verifier signs a request object with (#377)         |
| `OID4VP_VERIFIER_CERTIFICATE_CHAIN` | _(none)_       | `x5c` chain, leaf first, **anchor excluded** (#377)               |
| `OID4VP_VERIFIER_TRUST_ANCHORS`     | _(none)_       | Anchors QAuth's OWN chain must terminate at (#377)                |
| `OID4VP_RESPONSE_KEY_SECRET`        | _(none)_       | Opt-in AES-256-GCM wrap of the per-request decryption key (#377)  |
| `OID4VP_TRUSTED_ISSUERS`            | _(empty)_      | Per-realm issuer allowlist (#236) — the opposite trust direction  |
| `OID4VP_ISSUER_JWKS`                | _(empty)_      | Issuer public JWKs (#234) — **nothing verifies without it**       |
| `OID4VP_SUBJECT_RESOLUTION`         | _(profile)_    | Account-resolution strategy (#300); defaults to `asserted-lookup` |
| `OID4VP_SUBJECT_BINDING_CLAIMS`     | _(none)_       | The entitlement check (#300) — **required to BOOT when enabled**  |
| `OID4VP_ISSUER_ASSURANCE`           | _(empty)_      | Per-realm issuer → eIDAS LoA (#237); drives the `acr` claim       |
| `OID4VP_ATTESTING_ISSUERS`          | _(empty)_      | Issuance chains that attest key storage (#308/#379)               |
| `ACR_VALUE_STYLE`                   | `eidas-uri`    | Vocabulary the `acr` value is written in (#237)                   |

### Subject resolution is required to BOOT when wallet federation is on (#379)

`WALLET_FEDERATION_ENABLED=true` with **no** `OID4VP_SUBJECT_*` variables used to
start. It is now refused at startup, beside the issuer-allowlist and
credential-status gates, with the resolver's own message naming the variable.

This is a deliberate breaking change and it takes nothing away. The profile
default is `asserted-lookup`, and `asserted-lookup` with no binding claims has
nothing to match a presentation against — [ADR-009](/reference/records/adr/009-wallet-account-resolution/)
§1 calls that a total authentication bypass, so the server already rejected every
presentation. What changes is only where the operator finds out: a failed start
instead of a 100% login-failure rate. Set `OID4VP_SUBJECT_BINDING_CLAIMS` (and,
for `issuer-scoped-claim`, `OID4VP_SUBJECT_CLAIM` and
`OID4VP_SUBJECT_CLAIM_ISSUERS`), or turn `WALLET_FEDERATION_ENABLED` off —
which remains a clean boot with no wallet configuration present at all.

The **request path is unchanged**. A half-configured deployment that still
reaches it logs at `error` and returns the same uniform refusal a forged
credential gets; the boot gate replaces the operator's discovery channel and
changes nothing an anonymous caller can observe.

### Key-storage assurance (#308/#379)

An `OID4VP_ISSUER_ASSURANCE` entry may demand a minimum holder key storage with
`requiresKeyStorage: "hardware"`, optionally with a
`requiresKeyStorageAttackPotential` floor. Omitting the floor selects the strict
reading (`iso_18045_high`), because an unqualified `"hardware"` is asking for
eIDAS `high`'s secure cryptographic device.

The floor is refused unless `requiresKeyStorage` is `"hardware"`. It decides only
whether graded evidence reads as `hardware` or as `software`, and a `"software"`
requirement accepts either reading — so under `"software"` every floor in the
§D.2 vocabulary admits exactly the same evidence, and an operator who stated one
demanded nothing by it. A configuration that reads like a requirement and imposes
none is refused rather than ignored, the same way a floor stated with no
`requiresKeyStorage` at all is.

The evidence comes from `OID4VP_ATTESTING_ISSUERS` — the operator's record of
which issuance chains validate a wallet's key attestation per HAIP §4.5.1, and at
what grade. Recording an issuer there produces evidence, never a level: the realm
still has to name the issuer in its own `OID4VP_ISSUER_ASSURANCE` and accept it in
its own `OID4VP_TRUSTED_ISSUERS`.

**The recorded grade must clear the selected profile's own floor.** A profile
declaring `keyStorageAssurance: required` usually declares a minimum too —
`haip-1.0` requires `iso_18045_high` — and a deployment whose
`OID4VP_ATTESTING_ISSUERS` records nothing stronger than `iso_18045_basic` would
start and then refuse every presentation for attack potential below the minimum.
That is refused at startup instead, naming both the profile's floor and the
strongest grade recorded. The comparison takes the strongest, not the weakest: a
registry pairing a strong ecosystem with a weak one is a working deployment with
one ecosystem that will not reach the floor.

Key attestations conveyed **into a presentation** need wallet-provider trust
anchors, which have no configuration surface yet. Until they do, a conveyed
attestation is skipped rather than refused and the credential falls through to
the transitive path above — a wallet doing the more conformant thing must not be
worse off than one conveying nothing. It grants no more than the operator's
recorded claim, and the evidence still reports its source as `issuer-attested`.

Note that `oid4vp-1.0-base` declares `keyStorageAssurance: forbidden`, so on the
base profile this machinery establishes nothing and changes no behaviour. It is
reachable under `haip-1.0`, whose posture is `required` at `iso_18045_high`, and
which boots once the verifier identity, an attesting-issuer registry and the
status-list pair are all provisioned (#377, #379). See
[ADR-010](/reference/records/adr/010-acr-assurance-mapping/) §5.

Three variables answer three different questions and must not be conflated:
`OID4VP_VERIFIER_PROFILE` is _who are we, to a wallet?_, `OID4VP_TRUSTED_ISSUERS`
is _which issuers does a realm accept?_, and `OID4VP_ISSUER_JWKS` is _which key
does an issuer sign with?_. Configuring a key grants no trust, and allowlisting
an issuer with no configured key can never verify anything — both directions fail
closed.

The `response_uri` is derived from `JWT_ISSUER`, so it is always the same origin
the server publishes as its issuer identifier. So is the `request_uri` base, for
the same reason.

The three `OID4VP_VERIFIER_*` variables are a FOURTH question, and the only one
pointing outward: _how does QAuth prove who IT is to a wallet?_ Each has a
`_PATH` sibling. They are not token-issuance keys — the key configured here is
published nowhere, never reaches the JWT plugin, and cannot sign an access or ID
token, which `verifier-key-isolation.integration.test.ts` asserts. Unset all
three and the deployment runs the unsigned `redirect_uri` path, which is the
default; set SOME of them and the boot refuses, because a half-provisioned
verifier identity would otherwise fall back silently to a weaker one.

`OID4VP_WALLET_INVOCATION_ENDPOINT` accepts any wallet scheme — `openid4vp://`,
`haip://`, a vendor's `eudi-wallet://` or its `https://` universal link — but
**refuses to boot on a script-capable one** (`javascript:`, `data:`,
`vbscript:`, including case- and HTML-entity-encoded spellings). The value is
rendered into an `href`, so such a scheme would be a stored XSS payload served
to everyone who opens the sign-in screen; the render path re-checks it too.

## Assurance level and the `acr` claim

A wallet sign-in can tell a downstream application **how strong** the
authentication was. QAuth carries that as the OIDC `acr` (Authentication Context
Class Reference) claim of the ID token it issues to the client. The full decision
— including the research showing that no registered `acr` value for an eIDAS
Level of Assurance exists — is [ADR-010](/reference/records/adr/010-acr-assurance-mapping/).

### What a downstream application sees

| Authentication                                        | `acr` in the ID token                    |
| ----------------------------------------------------- | ---------------------------------------- |
| Password login                                        | **absent**                               |
| Wallet login, issuer not in `OID4VP_ISSUER_ASSURANCE` | **absent**                               |
| Wallet login, issuer assured `substantial`            | `http://eidas.europa.eu/LoA/substantial` |
| Wallet login, issuer assured `high`                   | `http://eidas.europa.eu/LoA/high`        |

(Values shown for the default `eidas-uri` style; under `loa-name` they are the
bare strings `substantial` and `high`.)

**The absence of `acr` is the signal for "no higher assurance was established".**
It is never emitted with a "low" value, so an RP may treat presence alone as "this
session came from an assured credential" and compare the value when it needs a
specific level:

```js
// Require an eIDAS "high" wallet credential for a sensitive operation.
if (idTokenClaims.acr !== 'http://eidas.europa.eu/LoA/high') {
  // Re-authenticate, or refuse.
}
```

`acr` is bound to the authorization code at `/oauth/authorize` time and rendered
at `/oauth/token`, so it reflects the authentication that actually backs the code
— not the moment the token was requested. Refresh rotation and RFC 8693 token
exchange issue no ID token, so neither can launder an `acr` value.

### Where the level comes from

Not from the wallet. OID4VP 1.0 §5 fixes the response type to `vp_token`, so
there is no wallet-signed assertion for a level to travel in, and HAIP 1.0 §1
states that the profile alone does not reach LoA `high`. The level is a property
of the **issuer**: which issuer signed the credential, under which trust anchor,
and which credential type it is. An operator states that in
`OID4VP_ISSUER_ASSURANCE`, per realm, and QAuth evaluates it against the
credential #234 validated — **after** the #236 trust gate has already refused an
untrusted issuer.

Listing an issuer in `OID4VP_ISSUER_ASSURANCE` does **not** make it trusted. The
two variables answer different questions and an issuer must appear in both.

### Reachable as of #240

`resolveWalletPresentation` now returns an authenticated user, so a completed
wallet login does produce a level and the resulting ID token carries `acr`. The
E2E suite asserts both its presence and its absence, and that the password login
still carries no `acr` with wallet federation on or off.

This requires `WALLET_FEDERATION_ENABLED=true`; with the flag off the routes are
never registered and no wallet login exists to produce a level.

## Security properties

- **Login CSRF.** The identifier form carries the same signed double-submit
  `__Host-` CSRF cookie the password form uses, checked before any presentation
  request is minted.
- **Browser binding.** A flow handle is unguessable, but unguessable is not bound:
  a handle can be mailed. A separate signed `__Host-qauth_wallet_flow` cookie is
  minted on the POST that creates the flow and required on every read, so an
  attacker cannot start a flow, present their own credential and hand the victim a
  URL that signs the victim in as the attacker.
- **Single use, and short.** The presentation request expires in five minutes and
  its `state` redeems exactly once, in one guarded `UPDATE`. Every terminal
  outcome deletes the flow record and the wallet signal, so nothing can be polled
  or replayed afterwards.
- **Session fixation.** A fresh session id is minted on every successful
  authentication, exactly as the password login does.
- **One refusal.** Expired request, wallet-reported error, unvalidatable
  presentation, untrusted issuer, unknown account and disabled account all render
  the same sentence. #236 requires that an untrusted issuer be indistinguishable
  from a malformed presentation; on a login screen, distinguishing "no such
  account" from "credential rejected" would hand any anonymous visitor an account
  oracle. The specific reason is logged server-side only.
- **CSP.** The polling script is the only inline script the server emits and it
  carries the per-request nonce; `script-src` stays `'self'` with no
  `'unsafe-inline'`. The QR code is inline SVG with presentation attributes, so no
  style relaxation is needed either.

## Accessibility and language

The screens follow the existing login/consent pattern: `lang="en"`, labels
wrapping their controls, `aria-describedby` on the identifier hint, `role="alert"`
on errors, an `aria-live="polite"` status region for the wait, an `aria-label` on
the QR image, and a `<noscript>` path that refreshes the same flow server-side.
QAuth has no i18n framework today; when one lands, these strings localize with the
rest of the sign-in copy.

## The authentication seam

`apps/auth-server/src/app/helpers/wallet-presentation.ts` is the single point
where a presentation becomes a session or a linked credential. Five gates run,
in this order, and none of them is optional:

1. **#234 — presentation validation.** Issuer signature, every Disclosure digest,
   the validity window, and the Key Binding JWT bound to this request's `nonce`
   and this Verifier's `client_id`.
2. **#236 — issuer trust.** A validated credential from an issuer the realm does
   not trust is a forgery with extra steps.
3. **#237 — assurance.** The realm's `OID4VP_ISSUER_ASSURANCE` policy is read
   AFTER the trust gate, never before: an untrusted issuer and an unassured
   trusted issuer both resolve to `low`, so reading a level first would say
   "authenticated at low assurance" where the answer is "not authenticated".
4. **#300 — subject resolution.** ADR-009 §1 requires verifying that the presented
   credential matches the binding stored for the **asserted** account; without
   that check anyone holding any valid credential could sign in as anyone.
5. **#235 — enrolment and claims.** `helpers/wallet-account.ts` turns the
   resolution into an account and writes the credential's claims as attributes.

Steps 1 and 2 are composed in one function, `verifyWalletPresentations`
(`@qauth-labs/fastify-plugin-federation`), precisely so a caller cannot wire up
only the first — the first produces a plausible-looking `ValidatedCredential`
with claims in it, which is exactly the object someone in a hurry would use.

### Where the bytes come from, and what they are checked against

The wallet posts to an endpoint nobody authenticated (`POST /oid4vp/response`,
OID4VP 1.0 §8.2 — a wallet has no client credentials). That endpoint decides
nothing: it redeems the single-use `state`, structurally parses the `vp_token`,
and **parks** the presented bytes under the `state` digest. Validation then runs
on the cookie-bound browser poll, where the session and the asserted identifier
exist — and where the expensive signature work is not on an anonymous surface.

Everything a presentation is CHECKED AGAINST — the `nonce`, the `client_id`, the
DCQL query, the realm — lives on the browser-side flow record. A wallet can
choose what it presents and nothing about what makes a presentation acceptable.

## Account linking (#238)

An existing user (typically a password account) can attach a wallet credential to
the account they are **already signed in to**, producing a second
`user_credentials` row (`provider_type='wallet'`) under the same `users.id`. That
is ADR-004's account-linking model and ADR-009 §5's `session-binding` strategy.

It has to be a separate, session-bound flow because ADR-009 §1's second bootstrap
case forbids the alternative:

> An account already exists without a wallet binding (typically a password
> account on the same email) — the presentation MUST NOT silently create one.
> Allowing it would let any holder of any trusted credential claim an existing
> account by asserting its email.

So `asserted-lookup` **refuses** such an account at login, and linking is how its
owner — proven by their session, not by the presentation — opts in.

Two entry points, both requiring a session: the server-rendered screens at
`/ui/wallet-link` (confirmation → QR → outcome, the same chrome as the sign-in
screens) and the JSON API at `POST /auth/link/wallet` for a first-party settings
UI. QAuth ships no account-management page today, so `/ui/wallet-link` is the
affordance a deployment links to from its own account screen.

### What gets written

| Column            | Value                                                                |
| ----------------- | -------------------------------------------------------------------- |
| `user_id`         | the session's `users.id`                                             |
| `provider_type`   | `wallet`                                                             |
| `external_sub`    | the identifier the account already owns — read from its password row |
| `credential_data` | `{ wallet_binding, issuer, vct }`                                    |

`external_sub` is deliberately the same value `PasswordProvider` fills (ADR-009
§1), which is what makes a later wallet login resolve back to **this** account:
both credentials key on one identifier, so either sign-in mints a token with the
identical `sub`. Under `issuer-scoped-claim` it is instead the digest of
`(validated issuer, disclosed claim)`.

`wallet_binding` is a digest over the validated issuer, the `vct` and the
configured `OID4VP_SUBJECT_BINDING_CLAIMS` values — never the claim values in the
clear. It is what a later `asserted-lookup` login re-derives and compares in
constant time.

Re-linking a re-issued credential **updates** the row the account already owns; a
row belonging to a different account is never overwritten.

### Duplicate detection is strategy-scoped, and usually unavailable

#238 originally asked for "reject linking a wallet already bound to a different
`users.id`". ADR-009's Negative consequences record that this lost its premise:
there is no stable, unique per-wallet identifier. So the check runs **only** under
`issuer-scoped-claim`, where `(validated issuer, disclosed claim)` supplies one.
Under `asserted-lookup` it is not performed, not approximated and not asserted —
a check that keyed on the asserted account identifier would tell an operator
their wallets are unique when they are not.

The shipped `uniqueIndex(realm_id, provider_type, external_sub)` still prevents
two rows sharing an `external_sub` under either strategy. That is a key
collision, not wallet duplicate detection.

### Security properties specific to linking

- **A session is the entire authority.** Every linking surface requires a live
  `__Host-qauth_session` cookie; there is no identifier field, because the account
  is the session's and a second answer could disagree with the cookie.
- **The session is re-read at completion**, and must be the SAME user who started
  the flow — a handle captured from a shared screen cannot be finished by a
  different signed-in user.
- **Modes do not cross.** A flow is `login` or `link`, and each completion path
  refuses the other's handle. Completing a link flow on the login path would sign
  a browser in as the linking user with no credential of that account checked.
- **CSRF.** The JSON `POST` takes the per-session `X-CSRF-Token` header (the same
  token `GET /consents` returns); the UI form takes the signed double-submit
  login-CSRF cookie.
- **One exception to the uniform refusal.** `conflict` is reported distinctly,
  because the caller is authenticated and acting on their own account, so it
  enumerates nothing they could not already establish. Every other failure renders
  the same sentence.

### Subject resolution (#300) and the account store

`@qauth-labs/server-federation`'s `subject/` module ships the
`SubjectResolutionStrategy` seam ADR-009 specifies: `asserted-lookup` (the
default), `issuer-scoped-claim` (opt-in per named issuer, with the mandatory
fallback), and `session-binding` (the linking path, #238). `key-thumbprint` and
`rp-pseudonym` are reserved ids that refuse with the gate that blocks them.

A deployment selects one with `OID4VP_SUBJECT_RESOLUTION` and configures the
entitlement check with `OID4VP_SUBJECT_BINDING_CLAIMS`; unset means "the active
`VerifierProfile`'s default", which is `asserted-lookup` for both shipped
profiles. `resolveSubjectResolution` folds the fail-closed assertions in, so a
half-configured selection throws rather than quietly building a weaker strategy —
and the seam turns that throw into the same uniform refusal, logging the reason.

#238 supplied the inputs the strategy was waiting for: `resolve()` consumes a
`ValidatedCredential` (now produced by the verification seam above) and a
`SubjectAccountLookup` — the account-store port that answers "which accounts in
this realm does this asserted identifier resolve to, and what wallet binding does
each carry". The adapter over `user_credentials` is
`apps/auth-server/src/app/helpers/wallet-account-lookup.ts`.

Two properties of that adapter are load-bearing. It returns rows across **every**
provider type, so a password account with no wallet binding stays visible and is
refused rather than looking like "no account" a caller might enrol over. And it
lets a database failure propagate, because the strategy contains it and turns it
into the same uniform refusal — swallowing it here would turn a broken database
into "no such account".

Note the boot posture, deliberately unchanged: selecting a strategy is **not** a
startup gate. A deployment that names a strategy and omits its settings fails at
`resolveSubjectResolution` on the request path — logged as an operator error and
rendered as a refusal, never as a distinct status an anonymous caller could
drive.

The login path **does** enrol, but only on `no-match`. That is ADR-009 §1's first
bootstrap case: no account exists for the asserted identifier, so the
presentation establishes the account and its wallet binding together
(`helpers/wallet-account.ts`, #235). `ambiguous` and `rejected` never enrol —
`rejected` in particular carries ADR-009's second bootstrap case, an account that
exists for the identifier with no matching wallet binding, and enrolling there
would be the account takeover the ADR names.

The same seam also resolves the assurance level (#237) — it returns an optional
`assuranceLevel` alongside the user, and everything downstream of it (the browser
session, the authorization code, the ID token's `acr` claim) is already wired for
it.

## VC claims normalization (#235)

A validated credential's claims become `user_attributes` rows with
`source='wallet'`, `verified=true`, and `expires_at` taken from the credential's
own `exp` (NULL when it carries none, so an attribute never outlives the
credential asserting it). `'wallet'` is the top of ADR-002's trust order, so a
verified wallet email outranks any `self_reported` one in
`helpers/email-claims.ts`.

Three properties are worth knowing before extending it:

- **The mapping is per credential format.** SD-JWT VC and ISO mdoc use different
  names for the same attribute — the EUDI PID's SD-JWT VC encoding carries
  `birthdate`, its mdoc encoding `birth_date` (ADR-009 Finding 1) — so
  `libs/server/federation/src/claims/` carries a claim-adapter registry with one
  adapter per format. `mso_mdoc` is deliberately absent and is REFUSED rather
  than served by the SD-JWT path.
- **The claim table is an allowlist.** `SD_JWT_VC_ATTRIBUTE_CLAIMS` names every
  claim that may become an attribute; anything else produces no row. Issuer trust
  bounds who may write, the table bounds what they may write. Claims left out on
  purpose — `nationalities` (an array), `address` (structured), `portrait` (a
  biometric), the attestation metadata — are recorded with their reason in
  `SD_JWT_VC_UNMAPPED_CLAIMS`.
- **`external_sub` is never derived from the credential.** It is whatever the
  subject-resolution strategy resolved. The wallet `credential_data` row records
  the format, the validated issuer, the credential type and the wallet binding —
  a digest, so the account is matchable without a second copy of the person's
  attributes sitting in the column.

## End-to-end tests and the mock wallet (#240)

The whole stack is exercised against a real Postgres, a real Redis and a mock
wallet in `apps/auth-server/src/app/wallet-federation.integration.test.ts`, run
by `pnpm nx test-integration auth-server` (Docker required) and by CI's
`integration` job. It covers first-time login, a returning user, the ADR-009 §1
takeover attempt, untrusted-issuer rejection, account linking, `acr` presence and
absence, the password-login regression, the fail-closed posture with no
`VerifierProfile`, and the `vp_token`-keyed-by-DCQL-id contract.

The wallet is `apps/auth-server/src/testing/mock-wallet.ts`. It is built on
`@qauth-labs/core-crypto` and `jose` and imports nothing from the verifier, so
the E2E is an interoperability test rather than a round trip through QAuth's own
encoder. It parses the authorization request off the wire, evaluates the DCQL
query, and dispatches presentation building through a per-format table with
`dc+sd-jwt` present and `mso_mdoc` deliberately absent — so an mdoc wallet is a
new table entry, not a rewrite.

The mock wallet also verifies a SIGNED request the way a real one would (#377):
it parses the `request_uri` reference, fetches the JAR, checks the `x5c` chain
against a trust anchor it holds **out of band** — never one the request carried —
and checks `client_id` against the digest of the leaf before verifying the
signature. That path is exercised by `helpers/wallet-login-request.test.ts`.

A `haip-1.0` suite runs alongside it (`wallet-federation-haip.integration.test.ts`,
#377 Phase C): the same wallet fetches and verifies the signed JAR, reads the
per-request encryption key out of its `client_metadata`, encrypts the whole
Authorization Response to it with `jose` directly, and posts one `response`
parameter — which the intake finds by the JWE `kid`, consumes, decrypts and
carries through to a session. It also proves what the encrypted mode adds: a
replayed `response` is refused because its row was consumed, a response
encrypted to a key QAuth never published is refused after consuming the row,
and the same presentation posted in the clear is refused. The boot-gate half
still asserts that a half-provisioned `haip-1.0` takes the deployment DOWN,
naming the key-storage assurance count rather than any count #377 cleared.

Interoperability with a REAL wallet is unverified, and which wallets implement
HAIP 1.0 is an open research question. The procedure for a manual pass — and the
place to record findings — is
[docs/wallet-interop-manual-validation.md](https://github.com/qauth-labs/qauth/blob/main/docs/wallet-interop-manual-validation.md).
