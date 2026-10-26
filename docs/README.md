# QAuth Documentation

The guides, the OAuth 2.1 / OIDC reference, and the rendered design records all
live on the documentation site: **[docs.qauth.dev](https://docs.qauth.dev)**.

This directory holds the engineering records that live in the repository
itself. The site's [design-records page](https://docs.qauth.dev/reference/records/)
renders the ADRs and the security records from these files, in place, so
`file:line` citations in closed issues and PRs keep resolving.

## Decisions and security

- [Architecture Decision Records](./adr/README.md): the design decisions behind
  QAuth.
- [Threat model](./security/threat-model.md): what QAuth promises, where
  untrusted input enters, and how findings are rated.
- [Security Gate Review — PQC Hybrid Signing](./security/005-pqc-hybrid-signing-review.md):
  the review of the post-quantum signing surface and its pre-default-on
  checklist.

## Standing records

- [Specification Pin Log](./spec-pin-log.md): what every moving specification
  is pinned to, on what basis, and when it is next due. A check fails the
  build on an overdue row.
- [EUDI Regulatory Drift Log](./eudi-regulatory-drift-log.md): the standing
  re-verification of the EU regulations that ADR-004 and ADR-009 rest on.
- [Spec-conformance matrix](./conformance/README.md): which normative
  requirements the tests prove, and which QAuth knowingly does not meet.
- [OIDF OP Certification Runbook](./oidf-op-certification-runbook.md): how to
  run the OpenID Foundation conformance suite.
- [Wallet Interop Manual Validation](./wallet-interop-manual-validation.md):
  the manual procedure for the pass against a real wallet.

## Archive

Superseded records, kept for history and no longer maintained:

- [MVP Product Requirements Document](./archive/mvp-prd.md): the original
  phase plan, replaced by
  [ADR-018](./adr/018-1-0-scope-and-stability.md) and the milestones.
- [Documentation findings, July 2026](./archive/documentation-findings-2026-07.md):
  defects found while building the docs site, each filed as an issue.

The other `*.md` files in this directory are short pointers to the guides'
new homes on the site. They keep old links working.
