# @qauth-labs/shared-interaction-client

The typed client of the Interaction API v1 (#590), for the reference ceremony app and for any UI
that replaces it. Generated from the published contract,
`apps/docs-site/public/interaction/v1-rc.0/openapi.json`: no type of the API is written by hand.

```ts
import { createInteractionClient } from '@qauth-labs/shared-interaction-client';

// On the ceremony app's server: the id alone reads the step (no personal data).
const server = createInteractionClient({ baseUrl: 'https://auth.example.com' });
const read = await server.interactionsGet({ interactionId });
if (read.status === 200 && read.data.step.type === 'urn:qauth:ia:new_password:v1-rc.0') {
  read.data.step.params.purpose; // 'register' | 'reset' | 'update_required'
}

// In the browser: same-origin, so the flow cookie travels with the request.
const browser = createInteractionClient();
const result = await browser.interactionsAnswer(
  { interactionId },
  { type: 'urn:qauth:ia:password:v1-rc.0', csrf, password }
);
if (result.status === 200 && result.data.result === 'redirect')
  location.assign(result.data.location);
```

A result is typed by its status: the body the document declares for it. A status the document does
not declare for the operation, such as a proxy's 502, rejects with `UnexpectedStatusError`. The
client speaks JSON only; a page without JavaScript posts its forms straight to the auth server.

## What it holds

| Module                         | What                                                                                          |
| ------------------------------ | --------------------------------------------------------------------------------------------- |
| `generated/interaction-api.ts` | Generated: a type per schema, the `Operations` table, `OPERATIONS`, `createInteractionClient` |
| `lib/runtime.ts`               | The generic request code: URL, headers, JSON, the declared-status check                       |
| `codegen/render-client.ts`     | The generator. It refuses a schema construct it cannot type rather than widening it           |
| `scripts/generate-client.ts`   | Writes the generated module and formats it                                                    |

## Regenerating

After the contract changes (`libs/shared/interaction-contract`):

```bash
pnpm exec nx run shared-interaction-contract:contract-export
pnpm exec nx run shared-interaction-client:generate
```

`codegen/render-client.test.ts` fails while the committed client differs from what the generator
writes from the committed document, and the `typecheck` target, whose inputs include the document,
builds the client in CI.

The generator is in-repo and has no dependency, like the repository's other generators: it reads
only the JSON Schema subset the contract uses.
