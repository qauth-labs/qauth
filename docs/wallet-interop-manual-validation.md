# Manual validation against a real wallet

A checklist for validating QAuth's OID4VP verifier against a **real** wallet, and
a record of what is and is not known about which wallets can do it today. Issue
#240; complements the automated suites in
`apps/auth-server/src/app/wallet-federation.integration.test.ts` and
`apps/auth-server/src/app/wallet-federation-status.integration.test.ts` (the
revocation path, #297/#378).

> **This procedure has not been executed.** Nothing below is a report of a
> successful interop run. It is the procedure to follow when someone does one,
> plus the open questions that have to be answered first. Treat any claim of
> real-wallet interoperability that is not backed by a completed run of this
> checklist as unverified.

## Open research question — which wallets implement HAIP 1.0?

**Unresearched, as of 2026-07-20 and still open.** ADR-004 and issue #240 both
record this as an open question rather than an assumption:

- No wallet has been confirmed to implement **HAIP 1.0** (Final, 2025-12-24).
- [`waltid-identity`](https://github.com/walt-id/waltid-identity) is a candidate
  reference implementation to **evaluate**. Its HAIP 1.0 conformance is
  unverified; do not assume it.
- The EUDI Wallet reference implementation is the other obvious candidate and is
  equally unverified here.

Two things follow, and both are load-bearing:

1. A **base-profile** (`oid4vp-1.0-base`) manual pass is possible today: unsigned
   request, `redirect_uri` Client Identifier Prefix, unencrypted `direct_post`.
   That is the pass described below.
2. A **HAIP-profile** pass is blocked on **Phase C of #377** (encrypted
   `direct_post.jwt` responses), regardless of which wallet is used.

   This was previously attributed to #298. That attribution is **stale**: #298
   closed 2026-07-26 and its crypto shipped — ES256 signing, `ECDH-ES`/`A*GCM`
   JWE and per-request ephemeral keys all live in `@qauth-labs/core-crypto`.
   The request half is built too: #377 Phases A and B landed request-object
   signing, the `x509_hash` Client Identifier Prefix and `request_uri` (JAR)
   delivery. QAuth **can** sign a request JAR today —
   `crypto-capabilities.ts:115-118` derives `ES256` from the operator's
   provisioned P-256 key rather than hardcoding `false`.

   What remains is the response half: `crypto-capabilities.ts:125-135` still
   reports `responseEncryption: false`, because there is no `direct_post.jwt`
   intake to decrypt at. That single count is what `haip-1.0` refuses to boot
   on. See
   `apps/auth-server/src/app/wallet-federation-haip.integration.test.ts`, whose
   assertion names exactly that count and explicitly excludes the ones #377
   already cleared.

When someone evaluates a wallet, record the finding here: wallet, version, date,
which profile it negotiated, and what failed. A "we tried X and it did not work"
entry is worth as much as a success.

| Wallet       | Version | Date | Profile attempted | Outcome |
| ------------ | ------- | ---- | ----------------- | ------- |
| _(none yet)_ |         |      |                   |         |

## Before you start

Wallets are phone applications and QAuth's `response_uri` must be reachable from
the phone. `localhost` is not. Either deploy to a host the phone can reach, or
tunnel — and make sure `JWT_ISSUER` matches the externally reachable origin,
because the `response_uri` is derived from it.

You also need a credential the wallet actually holds. QAuth is a **Verifier**,
not an Issuer: it asks for a credential, it does not create one. Obtain an
SD-JWT VC from whatever issuance service the wallet supports, then configure
QAuth with that issuer's identifier and public key.

## Deployment configuration

```bash
WALLET_FEDERATION_ENABLED=true
OID4VP_VERIFIER_PROFILE=oid4vp-1.0-base
OID4VP_REQUESTED_VCT=<the vct of the credential the wallet holds>
OID4VP_WALLET_INVOCATION_ENDPOINT=openid4vp://      # or the wallet's own scheme
OID4VP_ISSUER_JWKS={"<issuer>":[{...public JWK...}]}
OID4VP_TRUSTED_ISSUERS={"master":["<issuer>"]}
OID4VP_SUBJECT_RESOLUTION=asserted-lookup
OID4VP_SUBJECT_BINDING_CLAIMS=<claims the credential always discloses>
# Optional, for the acr checks:
OID4VP_ISSUER_ASSURANCE={"master":{"<issuer>":{"level":"substantial"}}}
# Optional under this profile, for the revocation checks (#297). Both or
# neither — setting exactly one fails the boot:
OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH=/etc/qauth/status-list-anchors.pem
OID4VP_STATUS_LIST_URI_ALLOWLIST=https://<issuer host>/statuslists
```

Four variables answer four different questions and configuring one does not
imply another: `OID4VP_VERIFIER_PROFILE` is _who are we, to a wallet?_,
`OID4VP_ISSUER_JWKS` is _which key does an issuer sign with?_,
`OID4VP_TRUSTED_ISSUERS` is _which issuers does this realm accept?_, and the
`OID4VP_STATUS_LIST_*` pair is _which CA may vouch for a status issuer, and
where may status lists be fetched from?_.

Leaving the status pair unset means no revocation checking, which is what every
release before #378 did. `haip-1.0` declares `requireCredentialStatus: true` and
refuses to START without both.

## Checklist — base profile

Each item is pass/fail. Record the wallet's behaviour even when it matches.

### Request construction

- [ ] `GET /ui/wallet-login` renders, and asks for an account identifier. There
      is no usernameless wallet login (ADR-009 §1) — if the field is missing, the
      deployment is not on the shipped UI.
- [ ] Submitting an identifier renders a QR code **and** an "Open my wallet"
      deep link. Both encode the same invocation URI.
- [ ] Decode the QR. The URI carries `client_id`, `response_type=vp_token`,
      `response_mode=direct_post`, `response_uri`, `nonce`, `state`,
      `dcql_query`, `client_metadata` — and **no** `redirect_uri`
      (OID4VP 1.0 §8.2 forbids it alongside `response_uri`).
- [ ] `client_id` carries the `redirect_uri:` Client Identifier Prefix.
- [ ] `dcql_query` names exactly one Credential Query, with the `vct` from
      `OID4VP_REQUESTED_VCT`.

### Wallet behaviour

- [ ] The wallet opens from the QR / deep link without an error.
- [ ] The wallet shows a consent screen naming QAuth (from `client_metadata`)
      and the claims being requested.
- [ ] The wallet lets the user decline. Declining POSTs an `error` to
      `response_uri` (§8.2) and the browser shows the standard refusal.

### Response and sign-in

- [ ] Approving posts to `response_uri`, form-encoded, and the endpoint answers
      HTTP 200 with `{}`.
- [ ] The `vp_token` is a JSON object **keyed by DCQL Credential Query id**, each
      value an **array** of presentations (§8.1). A wallet emitting a bare string,
      or a draft-era `presentation_submission` envelope, is refused — record it,
      it is an interop finding rather than a QAuth bug.
- [ ] The waiting browser page advances on its own within one poll interval
      (three seconds) and lands on `return_to`.
- [ ] The session cookie is set and the user is signed in.

### What was written

- [ ] `user_credentials` has exactly ONE new row: `provider_type='wallet'`,
      `external_sub` equal to the **asserted, normalized identifier** — not a
      wallet key, a JWK thumbprint or a DID.
- [ ] `credential_data` contains no `cnf`, no `kty`, no `did:` and no claim
      values in the clear. It carries a binding **digest**.
- [ ] `user_attributes` has `source='wallet'`, `verified=true` rows for the
      claims the credential disclosed, and `expires_at` matching the credential's
      `exp` (NULL when it has none).

### Credential status, as the real issuer publishes it (#297/#378)

Record what the issuer actually does, not only whether QAuth accepts it. This is
an interoperability finding in its own right: a verifier that checks revocation
against issuers who publish none has bought nothing.

- [ ] Does the presented credential carry a `status` claim at all? If it does,
      is it a `status_list` (HAIP §6.1 requires that when `status` is present),
      and what is `status_list.uri`?
- [ ] Is that URI reachable over HTTPS and does it serve
      `application/statuslist+jwt`? A wallet ecosystem that publishes lists
      behind an interactive login or an unauthenticated-but-HTML endpoint cannot
      be revocation-checked at all.
- [ ] Whose certificate signs the Status List Token, and does it chain to a CA
      you can obtain and put in `OID4VP_STATUS_LIST_TRUST_ANCHORS`? Note the
      status issuer need not be the credential issuer.
- [ ] With both `OID4VP_STATUS_LIST_*` variables set, a live credential still
      signs in and the server log shows exactly one `credential status check`
      audit line per sign-in, with `cacheHit` `false` then `true`.
- [ ] Setting exactly ONE of the two variables makes the server refuse to
      **start**, and the message names the one that is missing.

### Returning user

- [ ] Signing in a second time with the same wallet and the same asserted
      identifier succeeds and creates **no** second account.
- [ ] Signing in with a **different person's** credential from the same issuer,
      asserting the first user's identifier, is **refused** — and writes nothing.
      This is ADR-009 §1's total-authentication-bypass case; if it succeeds, stop
      and file a security issue.

### Refusals (all must render the same single sentence)

- [ ] An issuer not in `OID4VP_TRUSTED_ISSUERS` is refused.
- [ ] An expired credential is refused.
- [ ] With the `OID4VP_STATUS_LIST_*` pair configured: a credential whose Token
      Status List bit is `INVALID` or `SUSPENDED` is refused (#297), and so is
      one whose status endpoint is unreachable or serves a token that will not
      verify. Fail-closed is the contract — none of these may pass. The precise
      reason appears only in the server log, on the `credential status check`
      audit line, and never on the wire.
- [ ] A status refusal writes **nothing**: no `user_credentials` row, no
      `user_attributes` rows, no session cookie. Check the database, not just the
      rendered page — this is the criterion #378 exists to establish.
- [ ] Every status check, **including the ones that pass**, produces one audit
      line. A revocation-rejection count with no denominator cannot tell "we
      started rejecting everything" from "traffic grew".
- [ ] Re-posting the same `state` a second time is refused (single use).
- [ ] Replaying a `vp_token` captured from an earlier flow against a **new**
      request is refused (the Key Binding JWT's `nonce` no longer matches).
- [ ] Opening the flow's URL in a **different browser** does not complete it (the
      wallet-flow binder cookie).
- [ ] None of the above is distinguishable from the others on the wire. Compare
      status codes and bodies, not just the rendered copy.

### Tokens

- [ ] `/oauth/authorize` → `/oauth/token` on the wallet session yields an ID
      token whose `sub` is the `users.id` created above.
- [ ] With `OID4VP_ISSUER_ASSURANCE` configured for the issuer, the ID token
      carries the expected `acr` (see
      [ADR-010](./adr/010-acr-assurance-mapping.md) for the vocabulary).
- [ ] Without it, the ID token carries **no** `acr` at all.
- [ ] A password login on the same deployment carries **no** `acr`, whatever
      `OID4VP_ISSUER_ASSURANCE` says.

### Account linking

- [ ] Sign in with a password, visit `/ui/wallet-link`, and complete a link with
      the wallet. A second `user_credentials` row appears under the same
      `users.id`.
- [ ] A later wallet sign-in resolves to that same account, and its ID token's
      `sub` equals the password session's.

## Checklist — HAIP profile (blocked on Phase C of #377)

Do not attempt until Phase C of #377 lands; `haip-1.0` refuses to boot before then,
which is itself worth confirming:

- [ ] Setting `OID4VP_VERIFIER_PROFILE=haip-1.0` makes the server refuse to
      start, and the message names the missing capabilities rather than falling
      back to the base profile.

When Phase C of #377 lands, the additional items are:

- [ ] The request is delivered as a **signed** JAR referenced by `request_uri`.
      **Built** (#377 Phase B) and exercised against the mock wallet in
      `apps/auth-server/src/app/helpers/wallet-login-request.test.ts`. What is
      untested is a REAL wallet accepting it — not the code.
- [ ] `client_id` carries the `x509_hash` prefix, and the wallet validates the
      `x5c` chain against a trust anchor **not** present in the header.
      **Built** (#377 Phase A/B), likewise mock-exercised only. Note the anchor
      exclusion is RFC 7515 practice, not a quoted HAIP MUST.
- [ ] The response arrives as `direct_post.jwt`, encrypted with ECDH-ES over
      P-256 and A128GCM or A256GCM, to the encryption key QAuth published in
      `client_metadata`.
- [ ] A credential carrying **no** `status` claim is refused, because
      `haip-1.0` declares `requireCredentialStatus: true`. Under the base profile
      the same credential is accepted.
- [ ] A key attestation (#308) is present and validated, and a credential
      without one is refused under `keyStorageAssurance: 'required'`.

## Reporting

File findings as issues against `qauth-labs/qauth`, linked to epic #231, and add
a row to the wallet table above. Include the wallet's build number: OID4VP
behaviour has changed between drafts and a version-less report cannot be acted
on.
