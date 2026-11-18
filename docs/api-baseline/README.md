# API baselines

The OpenAPI document of each API family of [ADR-019](../adr/019-deployment-topology-and-trust-boundaries.md)
Decision 7, as a default deployment serves it (#525). Generated; never edit these by hand.

| File                     | What it is                                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------------- |
| `openapi-admin.json`     | The admin API. The admin listener is off by default (`ADMIN_API_ENABLED`), so it lists none |
| `openapi-account.json`   | The account API's operations the server serves, `/account/v1-rc.0`                          |
| `openapi-developer.json` | The developer API, `/developer/v1-rc.0`                                                     |

Each is the family's operations cut from its listener's document, with the family's own `info`,
contract version (`v1-rc.0`), server entry and security schemes. A listener serves the same
document at `<prefix>/openapi.json`, and the docs site publishes the maximal-flag copy beside its
`openapi.json` (`apps/docs-site/public/openapi-<family>.json`), where experimental operations are
listed and tagged.

Regenerate them after a change to a family route:

```bash
pnpm exec nx run auth-server:api-baseline     # these files and stable-surface/openapi.json
pnpm exec nx run auth-server:openapi-export   # those, and the docs site's documents
```

The stable-surface check ([`stable-surface/README.md`](../../stable-surface/README.md)) guards
them: CI regenerates each one and fails when it differs from the committed file, so an additive
change passes only with the baseline updated in the same pull request; and it compares each with
its copy at the last release through oasdiff, so a breaking change fails unless
`stable-surface/approved-breaks.json` approves it. Experimental operations are left out of that
comparison (ADR-018 §5). A family document enters the comparison with the first release that
contains it.

`openapi-admin.json` stays empty until an admin operation is promoted to `stable`. The promotion
has to make the default-flag export boot the admin listener with the experimental switches off;
the stable-surface README says why.
