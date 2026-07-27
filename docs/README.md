# QAuth Documentation

The guides, the OAuth 2.1 / OIDC reference, and the rendered design records all
live on the documentation site: **[docs.qauth.dev](https://docs.qauth.dev)**.
The canonical, always-current API surface is the interactive **Swagger UI at
`/docs`** on any running instance.

This directory now holds only the engineering records that live in the
repository itself — the site's [design-records
page](https://docs.qauth.dev/reference/records/) renders the ADRs and the
security review directly from these files, in place, so `file:line` citations
in closed issues and PRs keep resolving.

## Architecture & decisions

- [Architecture Decision Records](./adr/README.md) — the design decisions
  behind QAuth (also rendered at
  [docs.qauth.dev/reference/records](https://docs.qauth.dev/reference/records/)).
- [Security Gate Review — PQC Hybrid Signing](./security/005-pqc-hybrid-signing-review.md) —
  the three-dimension security review of the merged post-quantum signing
  surface (also rendered on the site).

## Standing records

- [EUDI Regulatory Drift Log](./eudi-regulatory-drift-log.md) — the standing
  re-verification record for the EU implementing regulations and
  specifications that ADR-004 and ADR-009 rest on.
- [OIDF OP Certification Runbook](./oidf-op-certification-runbook.md) — the
  operator runbook for driving the OpenID Foundation conformance suite.
