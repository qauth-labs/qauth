# Security policy

## Status first

QAuth is pre-1.0. The latest tag is a release candidate, and no release has
had an external security audit yet.

The project is developed with extensive AI assistance. Every change is
reviewed by a human before it merges. Even so, we cannot yet promise a high
level of security assurance. Run your own evaluation before you trust QAuth in
a sensitive or production deployment.

None of that makes reports unwelcome. A flaw found before 1.0 is far cheaper to
fix than the same flaw found after it.

## Reporting a vulnerability

Report privately through the repository's private vulnerability reporting:

<https://github.com/qauth-labs/qauth/security/advisories/new>

Do not open a public issue, discussion or pull request with the details. If the
private form is unavailable to you, open a public issue that only says you
have a report and asks for a channel.

A report is easiest to act on when it names:

- the commit on `main`, or the release candidate, you tested;
- the configuration in play, in particular any default-off switch you turned
  on: `WALLET_FEDERATION_ENABLED`, `HYBRID_SIGNING_ENABLED`, `ID_JAG_ENABLED`,
  or the `CIMD_*` settings;
- what the attacker controls at the start: an unauthenticated network
  position, a registered client, a user account, a wallet, a hosted document;
- a reproducer. A failing `vitest` test or a `curl` script against a local
  stack is ideal. A clear prose walkthrough is fine too.

[`docs/security/threat-model.md`](docs/security/threat-model.md) states what
QAuth promises, where untrusted input enters, what is out of scope, and how
severity is rated.

## Automated and AI-generated reports

Reports produced by automated scanners, including AI-based ones, are welcome
through the same private channel. The same rules apply to them:

- The report must carry a reproducer. A finding without one cannot be triaged.
- It is treated as unverified until a maintainer reproduces it.
- Severity is assigned by the maintainers against the threat model, not taken
  from the report.
- An unverified report is never published.
- A suggested patch is welcome. It is reviewed like any other change and needs
  a regression test.

## What to expect

QAuth is maintained by a small team. There is no on-call rotation, so these are
realistic expectations, not a service-level agreement:

| Stage                                                         | Expectation                        |
| ------------------------------------------------------------- | ---------------------------------- |
| Acknowledgement that the report arrived                       | usually within 7 days              |
| First assessment: is it a bug, is it in scope, rough severity | within 30 days                     |
| A fix                                                         | depends on severity; no fixed date |

If you have heard nothing after 14 days, reply on the advisory thread. Silence
is a dropped ball, not a policy.

## Supported versions

Only `main` and the latest pre-release receive fixes. There are no maintenance
branches and no backports. The 1.0 release will ship its own support policy.

## Coordinated disclosure

We fix first, then publish a security advisory in this repository. The
advisory names the affected versions, the fix and the reporter, unless the
reporter prefers not to be named. Thirteen advisories have been published this
way so far.
