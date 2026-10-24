---
title: Experimental features
description: Every experimental item of QAuth, its switch, and the four conditions it must meet to become stable, generated from the registry in libs/shared/stability.
sidebar:
  order: 5
lastVerified: '2026-10-24'
---

<!-- Generated from libs/shared/stability by its tests. Do not edit by hand: change the registry and run `pnpm nx test shared-stability -- -u`. -->

An experimental item ships, but it is outside the stability promise of QAuth 1.0
([ADR-018 §4 and §5](/reference/records/adr/018-1-0-scope-and-stability/)). This page lists every
experimental item, generated from the registry in `libs/shared/stability`. An item joins the
registry in the pull request that adds its switch; an item that a decision record names before it
is built is listed with **Built: no**.

## What experimental means

- The item sits behind a switch, and the switch is off by default.
- Discovery does not mention the item unless the switch is on.
- The server logs a warning at boot for each item that is on.
- The item may change in a minor release, without a deprecation window. Read the release notes
  before you upgrade a deployment that turns one on.

The boot warning is one `warn` line per item, with the item's id and a link to its section
below:

```text
Experimental feature <id> is on. It may change in a minor release, without a deprecation window. See https://docs.qauth.dev/reference/experimental-features/#<id>
```

The configuration page marks the keys and values that switch an item on as experimental
([Configuration](/operate/configuration/)). For such a key, the warning of its item replaces the
warning of the key, so a deployment sees one line, and only once the item is on.

## Becoming stable

An item becomes stable in a minor release once four conditions hold (ADR-018 §5). Each
condition needs evidence: an RFC number, an issue, a link, or a path in the repository that exists,
such as a test file or a section of an audit report.

1. The spec it implements is an RFC or a Final specification.
2. It has seen external use in a beta.
3. The external audit covered it.
4. Conformance tests exist for it.

`node scripts/experimental-status.mjs` prints the four conditions of every item and names the
items that may become stable. With `--check-stable` it fails when an item marked stable lacks
evidence for a condition.

## Items

| Item                                                  | Built | Switch                                                                           | Spec  |
| ----------------------------------------------------- | ----- | -------------------------------------------------------------------------------- | ----- |
| [`fipa-challenge-endpoint`](#fipa-challenge-endpoint) | no    | `FIRST_PARTY_LOGIN_ENABLED=true`                                                 | draft |
| [`node-first-party`](#node-first-party)               | no    | `@qauth-labs/node/first-party`                                                   | draft |
| [`oid4vp-1.0-base`](#oid4vp-10-base)                  | yes   | `OID4VP_VERIFIER_PROFILE=oid4vp-1.0-base`, with `WALLET_FEDERATION_ENABLED=true` | final |
| [`attestation-client-auth`](#attestation-client-auth) | no    | none named yet                                                                   | draft |
| [`pass-through-leg`](#pass-through-leg)               | no    | `PASS_THROUGH_LEG_ENABLED=true`, with `AUTHORITY_TREE_ENABLED=true`              | draft |
| [`plugin-api`](#plugin-api)                           | no    | none named yet                                                                   | draft |

### fipa-challenge-endpoint

**The FiPA authorization challenge endpoint.** Headless sign-in for first-party native apps at `POST /oauth/authorize-challenge`. It stays experimental until FiPA is an RFC; the engine behind it is stable, because the hosted pages use it. PKCE is on by default there, and a per-client setting can switch it off: the single exception to mandatory PKCE.

- Decided in [ADR-017](/reference/records/adr/017-first-party-login/).
- Runs in: the auth server.
- Switch: `FIRST_PARTY_LOGIN_ENABLED=true`. A decision record names it; nothing reads it until the item is built.
- Spec: [OAuth 2.0 for First-Party Applications](https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/), status `draft`.
- Built: no. Stable: no.

| Condition                                                     | Holds | Evidence and notes                                    |
| ------------------------------------------------------------- | ----- | ----------------------------------------------------- |
| 1. The spec it implements is an RFC or a Final specification. | no    | FiPA is an Internet-Draft.                            |
| 2. It has seen external use in a beta.                        | no    | No beta has run outside the project.                  |
| 3. The external audit covered it.                             | no    | The external audit of ADR-018 §8 has not taken place. |
| 4. Conformance tests exist for it.                            | no    | —                                                     |

### node-first-party

**The `/first-party` subpath of `@qauth-labs/node`.** The Node.js SDK entry point that talks to the FiPA authorization challenge endpoint. It stays experimental with the endpoint, until FiPA is an RFC.

- Decided in [ADR-017](/reference/records/adr/017-first-party-login/).
- Runs in: an SDK.
- Switch: `@qauth-labs/node/first-party`. A decision record names it; nothing reads it until the item is built.
- Spec: [OAuth 2.0 for First-Party Applications](https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/), status `draft`.
- Built: no. Stable: no.

| Condition                                                     | Holds | Evidence and notes                                    |
| ------------------------------------------------------------- | ----- | ----------------------------------------------------- |
| 1. The spec it implements is an RFC or a Final specification. | no    | FiPA is an Internet-Draft.                            |
| 2. It has seen external use in a beta.                        | no    | No beta has run outside the project.                  |
| 3. The external audit covered it.                             | no    | The external audit of ADR-018 §8 has not taken place. |
| 4. Conformance tests exist for it.                            | no    | —                                                     |

### oid4vp-1.0-base

**The `oid4vp-1.0-base` verifier profile.** The OpenID for Verifiable Presentations 1.0 profile for wallet sign-in. It stays supported, but it allows looser options than HAIP 1.0, such as unsigned requests, so it stays outside the stability promise; `haip-1.0` is the stable profile.

- Decided in [ADR-018](/reference/records/adr/018-1-0-scope-and-stability/).
- Runs in: the auth server.
- Switch: `OID4VP_VERIFIER_PROFILE=oid4vp-1.0-base`, with `WALLET_FEDERATION_ENABLED=true`.
- Spec: [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), status `final`.
- Built: yes. Stable: no.

| Condition                                                     | Holds | Evidence and notes                                                                                                                             |
| ------------------------------------------------------------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. The spec it implements is an RFC or a Final specification. | yes   | <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html> OpenID4VP 1.0 is an OpenID Foundation Final Specification.               |
| 2. It has seen external use in a beta.                        | no    | No beta has run outside the project; the profile is validated against a mock wallet.                                                           |
| 3. The external audit covered it.                             | no    | The external audit of ADR-018 §8 has not taken place.                                                                                          |
| 4. Conformance tests exist for it.                            | no    | The conformance matrix maps part of OpenID4VP 1.0 (`docs/conformance/requirements/oid4vp-1_0.json`); it does not cover the profile as a whole. |

### attestation-client-auth

**Attestation-based client authentication.** Native apps authenticate to the token endpoint with a client attestation, phase F4 of ADR-017. It stays experimental unless the attestation draft is an RFC before 1.0 is cut.

- Decided in [ADR-017](/reference/records/adr/017-first-party-login/).
- Runs in: the auth server.
- Switch: none named yet.
- Spec: [OAuth 2.0 Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/), status `draft`.
- Built: no. Stable: no.

| Condition                                                     | Holds | Evidence and notes                                    |
| ------------------------------------------------------------- | ----- | ----------------------------------------------------- |
| 1. The spec it implements is an RFC or a Final specification. | no    | The attestation draft is an Internet-Draft.           |
| 2. It has seen external use in a beta.                        | no    | No beta has run outside the project.                  |
| 3. The external audit covered it.                             | no    | The external audit of ADR-018 §8 has not taken place. |
| 4. Conformance tests exist for it.                            | no    | —                                                     |

### pass-through-leg

**The pass-through leg of the Authority Tree.** Work on a platform that cannot issue a narrowed credential stays inside the tree: the broker vends the owner's own token. It is temporary and weaker by design, with no narrowing. The rest of the Authority Tree is stable.

- Decided in [ADR-016](/reference/records/adr/016-agent-platform-bindings/).
- Runs in: the auth server.
- Switch: `PASS_THROUGH_LEG_ENABLED=true`, with `AUTHORITY_TREE_ENABLED=true`. A decision record names it; nothing reads it until the item is built.
- Spec: [The pass-through leg, ADR-016 §4](https://docs.qauth.dev/reference/records/adr/016-agent-platform-bindings/), status `draft`.
- Built: no. Stable: no.

| Condition                                                     | Holds | Evidence and notes                                    |
| ------------------------------------------------------------- | ----- | ----------------------------------------------------- |
| 1. The spec it implements is an RFC or a Final specification. | no    | QAuth defines the leg itself, in ADR-016 §4.          |
| 2. It has seen external use in a beta.                        | no    | No beta has run outside the project.                  |
| 3. The external audit covered it.                             | no    | The external audit of ADR-018 §8 has not taken place. |
| 4. Conformance tests exist for it.                            | no    | —                                                     |

### plugin-api

**The plugin API.** The AuthMethod contract as plugins see it. It is public and documented, so others can write plugins, but it may change in a minor release. It becomes stable in 1.x, after QAuth's own plugins have matured on it; those first-party plugins are part of 1.0.

- Decided in [ADR-018](/reference/records/adr/018-1-0-scope-and-stability/).
- Runs in: the auth server.
- Switch: none named yet.
- Spec: [The AuthMethod contract, ADR-018](https://docs.qauth.dev/reference/records/adr/018-1-0-scope-and-stability/), status `draft`.
- Built: no. Stable: no.

| Condition                                                     | Holds | Evidence and notes                                                    |
| ------------------------------------------------------------- | ----- | --------------------------------------------------------------------- |
| 1. The spec it implements is an RFC or a Final specification. | no    | QAuth defines the contract itself; ADR-018 §4 makes it stable in 1.x. |
| 2. It has seen external use in a beta.                        | no    | No beta has run outside the project.                                  |
| 3. The external audit covered it.                             | no    | The external audit of ADR-018 §8 has not taken place.                 |
| 4. Conformance tests exist for it.                            | no    | —                                                                     |
