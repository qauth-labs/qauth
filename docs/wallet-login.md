# Wallet sign-in (OID4VP) — the browser flow

How an end user signs in with a wallet credential, what the server does at each
step, and what is deliberately not built yet. Implements
[ADR-004](./adr/004-wallet-agnostic-federation.md) and
[ADR-009](./adr/009-wallet-account-resolution.md) (issue #239).

> **Status: the screens ship, the sign-in does not complete.** Presentation
> validation (#234), issuer trust application (#236) and subject resolution
> (#300) are unbuilt, so the server refuses every presentation it receives — see
> [The authentication seam](#the-authentication-seam). The flow, the fail-closed
> gating and the refusal behaviour are real and tested; the final "you are signed
> in" step is not reachable in a deployment today.

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
| `POST /oid4vp/response`               | The `response_uri` the **wallet** posts to (issue #233) — not a browser surface   |

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
   inline, and under `haip-1.0` it would be a `request_uri` reference to a signed
   JAR. The page renders what the backend produced.

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
which QAuth's client-identifier module does not implement, and a signed request,
which waits on #298 (ES256/JAR). Shipping half of it would mean an entry point
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
- The profile's posture needs a signed request or an encrypted response — both
  wait on #298, so `haip-1.0` is refused today.
- The profile does not permit `dc+sd-jwt`, the one credential format QAuth ships
  an adapter for.
- `OID4VP_REQUESTED_VCT` is unset. A DCQL query with no type constraint asks a
  wallet for any credential it holds, which OID4VP 1.0 §15.6 warns Verifiers
  against.

## Configuration

| Variable                            | Default        | Notes                                                            |
| ----------------------------------- | -------------- | ---------------------------------------------------------------- |
| `WALLET_FEDERATION_ENABLED`         | `false`        | Registers the wallet provider and these routes                   |
| `OID4VP_VERIFIER_PROFILE`           | _(none)_       | `oid4vp-1.0-base` is the only value that works today             |
| `OID4VP_REQUESTED_VCT`              | _(none)_       | Comma-separated `vct` values; **no wallet flow without it**      |
| `OID4VP_WALLET_INVOCATION_ENDPOINT` | `openid4vp://` | The wallet Authorization Endpoint the QR and deep link target    |
| `OID4VP_TRUSTED_ISSUERS`            | _(empty)_      | Per-realm issuer allowlist (#236) — the opposite trust direction |

The `response_uri` is derived from `JWT_ISSUER`, so it is always the same origin
the server publishes as its issuer identifier.

`OID4VP_WALLET_INVOCATION_ENDPOINT` accepts any wallet scheme — `openid4vp://`,
`haip://`, a vendor's `eudi-wallet://` or its `https://` universal link — but
**refuses to boot on a script-capable one** (`javascript:`, `data:`,
`vbscript:`, including case- and HTML-entity-encoded spellings). The value is
rendered into an `href`, so such a scheme would be a stored XSS payload served
to everyone who opens the sign-in screen; the render path re-checks it too.

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
where a presentation becomes a session. Since #235 it is IMPLEMENTED — given a
validated credential it applies every gate below and writes the account — and it
still refuses in production, for one remaining reason.

The gates, in the order they run, because the order is the security property:

1. **#234 — presentation validation.** A `ValidatedCredential` means the issuer
   signature verified, every disclosure digest matched, the validity window
   includes now, and the holder proved possession of the bound key against this
   request's `nonce` and QAuth's `client_id`.
2. **#236 — issuer trust**, per realm, from `OID4VP_TRUSTED_ISSUERS`. A realm
   with no allowlist trusts nobody.
3. **#299 — verifier posture.** The credential's format must be one the active
   `VerifierProfile` permits.
4. **#300 / ADR-009 — subject resolution.** The user asserts an identifier and
   the presentation proves entitlement to it; the strategy matches the presented
   credential against the binding stored for the asserted account. Without that
   check anyone holding any valid credential signs in as anyone.
5. **#235 — enrolment and claims.** `helpers/wallet-account.ts` turns the
   resolution into an account and writes the credential's claims as attributes.

### What still refuses, and why

The `direct_post` route hands the seam no credential, because it cannot produce
one: validation needs the issuer's verification key, and QAuth has no
configuration that supplies key material (`createStaticIssuerKeyResolver` exists;
`OID4VP_TRUSTED_ISSUERS` names issuers, not keys). So `resolveWalletPresentation`
refuses on the first gate. When issuer keys become configurable, the route change
is to validate and pass `credential` — the seam itself does not change.

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

The `SubjectAccountLookup` port is implemented in
`apps/auth-server/src/app/helpers/wallet-account.ts` over `user_credentials`, as
#235. It is realm-scoped and deliberately returns matches across **every**
provider type: an account that already exists for the asserted identifier without
a wallet binding — typically a password account on the same email — must be
visible, or ADR-009's second bootstrap case would be reported as "no account
found" and enrolled over.

Note the boot posture, deliberately unchanged: selecting a strategy is still not
a startup gate. A deployment that configures none refuses wallet logins at
request time with the same refusal every other failure produces.

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
