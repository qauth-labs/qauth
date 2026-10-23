# @qauth-labs/shared-events

The event contract (#456, ADR-018 §3 and §5, ADR-019 Decision 8): what a QAuth event looks like on
every delivery route, which event types exist, and the rules their payloads follow. Pure types and
schemas, with no I/O. The event store, the emitters and the delivery routes build on it.

The published reference is the docs page `reference/events` (generated from this library), and
the JSON Schema files under `apps/docs-site/public/schemas/events/`.

## What it holds

| Module                      | What                                                                                                     |
| --------------------------- | -------------------------------------------------------------------------------------------------------- |
| `lib/envelope.ts`           | The envelope: `id`, `type`, `time`, `realm`, `category`, `actor`, `subject`, `client`, `request`, `data` |
| `lib/identifier.ts`         | Event type identifiers, `urn:qauth:event:<name>:v<N>`, with `-rc.<M>` for a release candidate            |
| `lib/definition.ts`         | `defineEventType`, and what a registry entry holds                                                       |
| `lib/types/*.ts`            | The registered types, by area                                                                            |
| `lib/registry.ts`           | `EVENT_TYPES`, `getEventType`, `parseEvent`, `validateRegistry`                                          |
| `lib/payload-rules.ts`      | The payload rules and their scanner (`scanPayload`, `scanJsonSchema`)                                    |
| `lib/legacy.ts`             | Today's audit and log event names, mapped to registered types                                            |
| `lib/json-schema.ts`        | The published JSON Schema of the envelope and of each type                                               |
| `lib/docs-page.ts`          | The docs page, rendered from the registry                                                                |
| `scripts/export-schemas.ts` | Writes the schema files and the page. The library's only I/O; nothing imports it                         |

```ts
import { type EventDataOf, eventRequest, parseEvent } from '@qauth-labs/shared-events';

// Throws EventValidationError on an unknown type, a bad envelope, data that
// fails the type's schema, or data that breaks a payload rule.
const event = parseEvent(candidate);

type SignInData = EventDataOf<'urn:qauth:event:user.signed_in:v1-rc.0'>;

// The client controls the User-Agent and a forwarded address. eventRequest
// cuts and normalises them, so a long header cannot make the event fail.
const request = eventRequest({ traceId: req.id, ip: req.ip, userAgent: req.headers['user-agent'] });
```

## Adding an event type

1. Add a `defineEventType({ name, version: 1, rc: 0, ... })` entry to the file of its area under
   `src/lib/types/`, and list it in that file's array. Until QAuth 1.0.0 every type is a release
   candidate, so it carries `rc`. `since` is the release that will first ship it. Every `data`
   member has a description, and the schema is a `z.strictObject`.
2. Run `pnpm exec nx run shared-events:schema-export`. It writes the type's schema file and the
   docs page.
3. Register the new schema file in `stable-surface/surfaces.json`, like its neighbours: format
   `json-schema`, role `both`, stability `stable`. The test names the entry it expects.
4. `pnpm exec nx test shared-events` checks the entry, the payload rules and the generated files.

## The rules

The payload rules and the versioning rules are on the docs page, and the code enforces them:

- **Payload rules.** Ids, not names or addresses, unless the type declares the field in
  `personalData`. Never a password, code, OTP, token, key, assertion, signature, cookie, secret or
  link. Hidden identifiers are keyed HMACs. `validateRegistry` scans every type's schema, and
  `parseEvent` scans every event's `data`.
- **Release candidates.** Until QAuth 1.0.0 every type is `:v<N>-rc.<M>` and nothing about it is
  promised. A breaking change before then raises `rc` in place (`:v1-rc.0` becomes `:v1-rc.1`),
  so one identifier never names two schemas. The release that ships 1.0.0 drops `rc` from every
  type, and the registry test that requires it.
- **Versioning.** Within a major release, only additions: a new type, a new optional member, a new
  value of an open set (`extensibleEnum`). A breaking change registers `:v2` beside `:v1`; `:v1`
  is marked `deprecated` with `replacedBy`, both are emitted until the deprecation window ends,
  and `:v1` leaves only in a new major release. The stable-surface check compares each schema file
  with the last release, as `role: both`: it is a document QAuth emits and one that events stored
  under an earlier release must still match, so a new required member fails and a new optional
  member passes.

## Two published-schema choices

- Objects are open in the published JSON Schema (no `additionalProperties: false`), so a
  consumer built against one release accepts the optional members a later one adds. The Zod
  schemas stay closed: QAuth emits only declared members.
- An open set is `x-extensible-enum` in the published schema, so adding a value is not a break.
  `category` is the one closed set in the envelope.
