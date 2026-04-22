# Architecture Decision Records (ADR)

This directory contains Architecture Decision Records (ADRs) for QAuth.

## What is an ADR?

An ADR is a document that captures an important architectural decision made along with its context and consequences.

## ADR Index

| ID                                            | Title                                                                       | Status   | Date       |
| --------------------------------------------- | --------------------------------------------------------------------------- | -------- | ---------- |
| [001](./001-jwt-key-management.md)            | JWT Key Management Strategy                                                 | Accepted | 2026-01-15 |
| [002](./002-identifier-abstraction.md)        | Identifier Abstraction — Email as Credential, Not Identity                  | Accepted | 2026-03-11 |
| [003](./003-credential-provider-interface.md) | CredentialProvider Abstraction for Authentication Methods                   | Accepted | 2026-03-11 |
| [004](./004-wallet-agnostic-federation.md)    | Wallet-Agnostic VC Federation via SIOPv2/OID4VP                             | Accepted | 2026-03-11 |
| [005](./005-pqc-hybrid-signing.md)            | Post-Quantum Cryptography — Hybrid Signing Roadmap                          | Accepted | 2026-03-18 |
| [006](./006-oauth-grants-and-audience.md)     | OAuth Grants — `client_credentials`, `client_secret_basic`, and `aud` Claim | Accepted | 2026-04-16 |

## ADR Template

When creating a new ADR:

1. Copy the template below
2. Name the file `NNN-short-title.md` (e.g., `002-database-strategy.md`)
3. Fill in the sections
4. Update this index

```markdown
# ADR-NNN: Title

**Status:** Proposed | Accepted | Deprecated | Superseded  
**Date:** YYYY-MM-DD  
**Authors:** Names

## Context

What is the issue that we're seeing that is motivating this decision?

## Decision

What is the change that we're proposing and/or doing?

## Consequences

What becomes easier or more difficult to do because of this change?

### Positive

### Negative

### Neutral

## Related

Links to related ADRs, RFCs, or issues.
```

## References

- [ADR GitHub Organization](https://adr.github.io/)
- [Michael Nygard's article on ADRs](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
