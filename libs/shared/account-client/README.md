# @qauth-labs/shared-account-client

The typed client of the account API v1 (#588), for a backend that holds a person's access token
for the account audience, such as the account console's. Generated from the published contract,
`apps/docs-site/public/account/v1-rc.0/openapi.json`: no type of the API is written by hand.

```ts
import { createAccountClient } from '@qauth-labs/shared-account-client';

const account = createAccountClient({
  baseUrl: 'https://auth.example.com',
  accessToken: () => session.accessToken,
  fetch: (url, init) => fetch(url, init),
});

const page = await account.sessionsList({ query: { limit: 20 } });
if (page.status === 200) page.data.items; // Session[]

const change = await account.passwordChange({
  body: { currentPassword, newPassword },
});
if (change.status === 401 && change.data.code === 'insufficient_user_authentication') {
  // Send the person to the authorization endpoint with change.data.max_age, then repeat.
}
```

A result is typed by its status: the body the document declares for it. A status the document does
not declare for the operation, such as a proxy's 502 or a redirect, rejects with
`UnexpectedStatusError`; the client never follows a redirect, which would carry the token on. The
token goes under `Bearer`, or under `DPoP` with the proof `dpopProof` signs for each request.
`OPERATIONS` records what each operation asks of the token (`freshAuthentication`, `actChain`).
`fetch` is required: the client picks no transport of its own, so the backend decides how its
outbound traffic is sent and checked.

## What it holds

| Module                       | What                                                                                      |
| ---------------------------- | ----------------------------------------------------------------------------------------- |
| `generated/account-api.ts`   | Generated: a type per schema, the `Operations` table, `OPERATIONS`, `createAccountClient` |
| `lib/runtime.ts`             | The generic request code: URL, query, headers, the token, JSON, the declared-status check |
| `codegen/render-client.ts`   | The generator. It refuses a schema construct it cannot type rather than widening it       |
| `scripts/generate-client.ts` | Writes the generated module and formats it                                                |

## Regenerating

After the contract changes (`libs/shared/account-contract`):

```bash
pnpm exec nx run shared-account-contract:contract-export
pnpm exec nx run shared-account-client:generate
```

`codegen/render-client.test.ts` fails while the committed client differs from what the generator
writes from the committed document, and the `typecheck` target, whose inputs include the document,
builds the client in CI.

The generator is in-repo and has no dependency. It is its own, not the Interaction API client's:
shared libraries are leaves of the module graph, and this one reads what the account API adds (query
and header parameters, Merge Patch bodies, nullable values, the access token).
