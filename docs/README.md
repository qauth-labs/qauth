# QAuth Documentation

QAuth is the open-source, self-hostable **OAuth 2.1 authorization server for MCP
servers and AI agents** (see [ADR-007](./adr/007-mcp-first-positioning.md)). This
is the entry point to the guides; the canonical, always-current API surface is the
interactive **Swagger UI at `/docs`** on any running instance.

> 🎉 **July 2026 — the T4 platform track is nearly through.** The MVP, the agent-native authorization layer (agent client type, RFC 8693 on-behalf-of delegation, scope modes, step-up, per-agent audit), the T3 production-hardening track and the T5 environment-aware posture ([ADR-008](./adr/008-environment-aware-authorization.md)) all shipped previously. Since then the ADR-002 identifier migration and post-quantum hybrid signing have landed, and wallet federation now completes a browser sign-in end-to-end — behind `WALLET_FEDERATION_ENABLED`, which is off by default. Start with the [agent-authorization guide](./agent-authorization.md), or the [wallet sign-in guide](./wallet-login.md) for T4.

## Getting started

| Guide                                            | What it covers                                                                                                                                                                       |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [**MCP Quickstart**](./mcp-quickstart.md)        | End-to-end: run QAuth, run a `mcp-guard`-protected MCP resource server, and complete the full discovery → register → `authorization_code` + PKCE → token handshake. **Start here.**  |
| [**Docker Guide**](./docker.md)                  | Running the stack (auth-server + Postgres + Redis) in development and production; environment variables; CIMD configuration.                                                         |
| [**Observability**](./observability.md)          | Structured logging + secret redaction, request-id tracking, auth-event logging, failed-login lockout, the Prometheus `GET /metrics` endpoint, and recommended Alertmanager rules.    |
| [**Browser Security**](./browser-security.md)    | The browser-facing hardening (T3): security headers (nonce-based CSP, HSTS, X-Frame-Options), CSRF double-submit protection, `__Host-` secure cookies, and XSS-safe HTML output.     |
| [**Wallet sign-in (OID4VP)**](./wallet-login.md) | The browser wallet-login flow (T4): the required asserted-identifier step (ADR-009), the QR / deep-link targeting decision, fail-closed profile gating, and how to turn the flow on. |

## OAuth 2.1 / OIDC

| Guide                                                                          | What it covers                                                                                                                                                                                      |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**OAuth 2.1 Flow**](./oauth-flow.md)                                          | Every endpoint with copy-paste `curl`: PKCE generation, `/oauth/authorize`, token exchange, refresh-token rotation, `client_credentials`, introspection, UserInfo, and Dynamic Client Registration. |
| [**ADR-006: OAuth grants & audience**](./adr/006-oauth-grants-and-audience.md) | Why `client_credentials` + `client_secret_basic` and per-client `aud` binding work the way they do.                                                                                                 |

## Post-quantum signing

> **Status:** implemented and merged (epic #241), **off by default**. Ed25519 / EdDSA
> remains the shipping default; hybrid requires `SIGNING_ALGORITHM_MODE=ed25519+ml-dsa-65`
> **and** `HYBRID_SIGNING_ENABLED=true` plus an ML-DSA key. Enabling it by default is
> gated on the pre-default-on checklist in the security gate review.

| Guide                                                                     | What it covers                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**Hybrid Signing — Verifier Guide**](./hybrid-signing-verifier-guide.md) | How token verifiers behave during the ADR-005 hybrid (Ed25519 + ML-DSA-65) rollout: the mixed `OKP`+`AKP` JWKS, the reference-token/introspection delivery default, the draft-revision churn risk, and a migration checklist. **No action is required for classical Ed25519-only verifiers.** |
| [**ADR-005: PQC Hybrid Signing**](./adr/005-pqc-hybrid-signing.md)        | The post-quantum roadmap, the detached-parallel construction, and the #243–248 implementation amendments.                                                                                                                                                                                     |
| [**Security Gate Review**](./security/005-pqc-hybrid-signing-review.md)   | The three-dimension security review of the merged PQC surface (CONDITIONAL PASS) and the pre-default-on checklist.                                                                                                                                                                            |

## Agent authorization

| Guide                                               | What it covers                                                                                                                                                                                                                                                                         |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**Agent Authorization**](./agent-authorization.md) | The agent-native layer (ADR-007 §2): the agent client type (`is_agent`), RFC 8693 Token Exchange / on-behalf-of delegation (`act` claim), agent scope modes (ReadOnly / Admin / Exec + the operator-set cap), step-up authentication before dangerous operations, and per-agent audit. |

## API reference

| Guide                                   | What it covers                                                                                                                                                                                                         |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**API Reference**](./api-reference.md) | Hand-written contract for every endpoint: first-party auth (`/auth/*`), OAuth 2.1 (`/oauth/*`), discovery, and client management (`/api/clients`), with request/response shapes, status codes, and the error envelope. |

The authoritative, always-current surface is the live OpenAPI / Swagger UI at
**`/docs`** on the running instance. Also:

- **Resource-server SDK** — [`@qauth-labs/mcp-guard`](../libs/fastify/plugins/mcp-guard/README.md)
  (Protected Resource Metadata, Bearer challenges, JWT/introspection validation).
- The client-management API (`GET/POST/PATCH/DELETE /api/clients`, regenerate-secret)
  is shipped — see [API Reference → Client management](./api-reference.md#client-management-apiclients).

## Code examples

| Guide                                   | What it covers                                                                                                                                                             |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**Code Examples**](./code-examples.md) | Copy-paste-ready clients — Node/TS (first-party register→login→protected call; machine `client_credentials`) and browser JS (`authorization_code` + PKCE with Web Crypto). |

- [`memory-mcp` example server](../libs/fastify/plugins/mcp-guard/examples/memory-mcp/server.ts) —
  a runnable, `mcp-guard`-protected resource server (the resource half of the
  quickstart).
- Copy-paste `curl` for every OAuth step in the [OAuth 2.1 Flow](./oauth-flow.md)
  guide.

## Environment-aware authorization

| Guide                                                                                        | What it covers                                                                                                                                                                                          |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**Environment-Aware Authorization**](./environment-authorization.md)                        | Operator/how-to guide: the `environment` (development / staging / production) policy dimension on clients/realms, the profile table, fail-safe defaults, and environment-gated developer API keys (T5). |
| [**ADR-008: Environment-aware authorization**](./adr/008-environment-aware-authorization.md) | The design decision behind the above — fail-safe reasoning, the `resolveEnvironmentPolicy` resolver, and prior-art comparison.                                                                          |

## Wallet federation (T4)

> **Status:** the verifier stack is merged — OID4VP 1.0 request generation and
> `direct_post` intake (#233), `VerifierProfile` (#299), per-realm issuer trust registry
> (#236), SD-JWT VC validation (#234), Token Status List revocation (#297), HAIP key
> attestations (#308), `acr` propagation (#237), claims normalization (#235), account
> linking (#238), subject resolution (#300), the sign-in UI (#239) and an E2E mock-wallet
> suite (#240). A browser **can complete a wallet sign-in today** — first-time enrolment,
> returning login, account linking and `acr` emission are covered end-to-end against a
> mock wallet speaking OID4VP 1.0 over the wire. It is **off by default**
> (`WALLET_FEDERATION_ENABLED=false`) and validated only on the `oid4vp-1.0-base`
> profile; the HAIP profile (#377) and a real-wallet pass (#376) are still open.
> See [wallet sign-in](./wallet-login.md).
>
> `WalletProvider.verify()` — the generic `CredentialProvider`-registry entry point —
> still throws by design (#232). The wallet login path does **not** go through it.

| Guide                                                                                 | What it covers                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**EUDI Regulatory Drift Log**](./eudi-regulatory-drift-log.md)                       | The standing re-verification record for the EU implementing regulations and specifications that ADR-004 and ADR-009 rest on: every pass, its sources and controls, and a verdict per item (confirmed / drifted / superseded).                                               |
| [**ADR-009: Wallet Account Resolution**](./adr/009-wallet-account-resolution.md)      | Which account an OID4VP presentation resolves to, and why `asserted-lookup` is the default. ⚠️ Findings partially superseded by CIR (EU) 2026/1730 and 2026/1731 — see its [Drift re-check (2026-07-26)](./adr/009-wallet-account-resolution.md#drift-re-check-2026-07-26). |
| [**ADR-004: Wallet-Agnostic VC Federation**](./adr/004-wallet-agnostic-federation.md) | How QAuth bridges OID4VP wallets to OAuth 2.1, and the spec-status corrections behind it.                                                                                                                                                                                   |
| [**ADR-010: eIDAS LoA → `acr` mapping**](./adr/010-acr-assurance-mapping.md)          | How an eIDAS level of assurance becomes an OIDC `acr` value, the assurance policy inputs, and what a relying party may infer from it.                                                                                                                                       |
| [**Wallet Interop Manual Validation**](./wallet-interop-manual-validation.md)         | The manual procedure for the real-wallet interoperability pass (#376) — what to run against a live EUDI-profile wallet and what counts as a pass.                                                                                                                           |

## Conformance & certification

| Guide                                                                   | What it covers                                                                                                                                                 |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**OIDF OP Certification Runbook**](./oidf-op-certification-runbook.md) | The procedure for running the OpenID Foundation OP conformance suite against a QAuth instance: profiles in scope, configuration, and how to record the result. |

## Architecture & decisions

- [Architecture Decision Records](./adr/README.md) — the design decisions behind
  QAuth, including [ADR-007: MCP-First Positioning](./adr/007-mcp-first-positioning.md)
  and [ADR-008: Environment-aware authorization](./adr/008-environment-aware-authorization.md).
- [MVP-PRD](../MVP-PRD.md) — product requirements, phase breakdown, schema.
- [Milestones](https://github.com/qauth-labs/qauth/milestones) — track status:
  **T0–T3 and T5 complete** (trust floor, MCP productization, agent-native authZ,
  OIDC conformance + hardening, environment-aware authZ). **T4 (federation + PQC)
  stands at 48 closed / 4 open**: the ADR-002 identifier migration is complete, the
  post-quantum hybrid layer is merged and default-off, and wallet federation
  completes a browser sign-in end-to-end behind `WALLET_FEDERATION_ENABLED`
  (off by default). **T6 (docs + developer dashboard)** is the active
  documentation track.
