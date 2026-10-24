import type { EventTypeDefinition } from './definition';
import { eventVersionLabel } from './identifier';
import {
  dataJsonSchema,
  ENVELOPE_SCHEMA_FILE,
  envelopeJsonSchema,
  eventSchemaFile,
} from './json-schema';
import { LEGACY_EVENT_MAP } from './legacy';

/**
 * The docs page `reference/events.md`, rendered from the registry: the
 * envelope, the payload rules, the versioning rules and every registered
 * type. Generated, never edited by hand; the export script writes it and a
 * test fails when the committed page differs.
 */

/** The date the page's hand-written prose was last checked; change it with the prose. */
export const EVENTS_PAGE_LAST_VERIFIED = '2026-10-24';

/** Where the schema files are served, relative to the docs site root. */
const SCHEMA_PATH = '/schemas/events/';

type JsonObject = Record<string, unknown>;

const isObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const code = (value: string) => `\`${value}\``;

/**
 * A table cell: backslashes and pipes escaped, newlines flattened. The
 * backslash goes first, or a `\|` in the text would end the cell. A run of
 * whitespace that holds a newline becomes one space; matching whole runs
 * keeps this linear on a long run of spaces.
 */
export const tableCell = (value: string) =>
  value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\s+/g, (run) => (run.includes('\n') ? ' ' : run));

/** The heading anchor Starlight renders for an ASCII heading, as its slugger computes it. */
export function headingAnchor(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9 _-]/g, '')
    .replace(/ /g, '-');
}

/** The heading of one type's section. */
export function typeHeading(
  definition: Pick<EventTypeDefinition, 'name' | 'version' | 'rc'>
): string {
  return `${definition.name} ${eventVersionLabel(definition)}`;
}

/** A short, human reading of a JSON Schema node's type. */
export function describeType(node: unknown): string {
  if (!isObject(node)) return 'any';
  if (typeof node['const'] === 'string') return code(node['const']);
  const open = node['x-extensible-enum'];
  if (Array.isArray(open)) {
    return `one of ${open.map((value) => code(String(value))).join(', ')}, or a later value`;
  }
  const closed = node['enum'];
  if (Array.isArray(closed))
    return `one of ${closed.map((value) => code(String(value))).join(', ')}`;
  const anyOf = node['anyOf'];
  if (Array.isArray(anyOf)) return anyOf.map(describeType).join(' or ');
  switch (node['type']) {
    case 'string':
      switch (node['format']) {
        case 'date-time':
          return 'time (RFC 3339, UTC)';
        case 'uuid':
          return 'UUID';
        case 'ipv4':
          return 'IPv4 address';
        case 'ipv6':
          return 'IPv6 address';
        default:
          return 'string';
      }
    case 'integer':
      return 'integer';
    case 'boolean':
      return 'boolean';
    case 'array':
      return `array of ${describeType(node['items'])}`;
    case 'object':
      return 'object';
    default:
      return 'any';
  }
}

interface MemberRow {
  name: string;
  type: string;
  required: boolean;
  description: string;
}

/** The rows of an object's members; nested objects add a row per member, as `parent.child`. */
function memberRows(schema: JsonObject, prefix = ''): MemberRow[] {
  const properties = isObject(schema['properties']) ? schema['properties'] : {};
  const required = Array.isArray(schema['required']) ? schema['required'] : [];
  const rows: MemberRow[] = [];
  for (const [name, node] of Object.entries(properties)) {
    const child = isObject(node) ? node : {};
    rows.push({
      name: `${prefix}${name}`,
      type: describeType(child),
      required: required.includes(name),
      description: typeof child['description'] === 'string' ? child['description'] : '',
    });
    if (child['type'] === 'object' && isObject(child['properties']) && name !== 'data') {
      rows.push(...memberRows(child, `${prefix}${name}.`));
    }
  }
  return rows;
}

function memberTable(rows: readonly MemberRow[]): string {
  const lines = ['| Member | Type | Required | Meaning |', '| --- | --- | --- | --- |'];
  for (const row of rows) {
    lines.push(
      `| ${code(row.name)} | ${tableCell(row.type)} | ${row.required ? 'yes' : 'no'} | ${tableCell(row.description)} |`
    );
  }
  return lines.join('\n');
}

/** An event of the first registered type, as the envelope section shows it. */
export const EXAMPLE_EVENT = {
  id: '0199f2b4-7c3e-7a51-9d2b-3a6c8e1f0a42',
  type: 'urn:qauth:event:user.signed_in:v1-rc.0',
  time: '2026-10-22T09:30:00.123Z',
  realm: '0199f2b4-1a2b-7c3d-8e4f-5a6b7c8d9e0f',
  category: 'user',
  actor: { type: 'user', id: '0199f2b4-2b3c-7d4e-9f5a-6b7c8d9e0f1a' },
  subject: { type: 'user', id: '0199f2b4-2b3c-7d4e-9f5a-6b7c8d9e0f1a' },
  client: { id: 'notes-app' },
  request: { traceId: 'req-7f3a', ip: '203.0.113.7', userAgent: 'Mozilla/5.0' },
  data: { method: 'password' },
} as const;

function typeSection(definition: EventTypeDefinition): string {
  const data = dataJsonSchema(definition);
  const rows = memberRows(data);
  const facts = [
    `- Identifier: ${code(definition.type)}`,
    `- Category: ${code(definition.category)} · Severity: ${code(definition.severity)} · Since: ${definition.since}`,
    `- Subject: ${definition.subject ? `${code(definition.subject)}, when known` : 'none: the event never carries one'}`,
    `- Schema: [${eventSchemaFile(definition)}](${SCHEMA_PATH}${eventSchemaFile(definition)})`,
  ];
  if (definition.diff) {
    facts.push(
      `- Diff: ${code(`data.${definition.diff}`)} lists what changed, with every secret value masked ([Admin events](#admin-events))`
    );
  }
  if (definition.deprecated) {
    facts.push(
      `- Deprecated since ${definition.deprecated.since}, replaced by ${code(definition.deprecated.replacedBy)}`
    );
  }
  return [
    `### ${typeHeading(definition)}`,
    definition.description,
    facts.join('\n'),
    rows.length > 0 ? memberTable(rows) : '`data` has no members: the envelope carries the event.',
  ].join('\n\n');
}

function summaryTable(definitions: readonly EventTypeDefinition[]): string {
  const lines = ['| Type | Category | Severity | Since |', '| --- | --- | --- | --- |'];
  for (const definition of definitions) {
    lines.push(
      `| [${code(definition.type)}](#${headingAnchor(typeHeading(definition))}) | ${definition.category} | ${definition.severity} | ${definition.since} |`
    );
  }
  return lines.join('\n');
}

function legacyTable(): string {
  const lines = [
    '| Earlier name | Written to | Type | Implied `data` |',
    '| --- | --- | --- | --- |',
  ];
  for (const mapping of LEGACY_EVENT_MAP) {
    const implied = Object.entries(mapping.data ?? {})
      .map(([key, value]) => code(`${key}: ${value}`))
      .join(', ');
    lines.push(
      `| ${code(mapping.event)} | ${mapping.source === 'audit' ? 'audit log' : 'log line'} | ${code(mapping.type)} | ${implied || '—'} |`
    );
  }
  return lines.join('\n');
}

/** Render the whole page. */
export function renderEventsPage(definitions: readonly EventTypeDefinition[]): string {
  const envelope = envelopeJsonSchema();
  const sections = [
    `---
title: Events
description: The event envelope, the payload rules, the versioning rules and every registered event type, generated from the registry in libs/shared/events.
sidebar:
  order: 4
lastVerified: '${EVENTS_PAGE_LAST_VERIFIED}'
---`,
    `<!-- Generated by \`pnpm exec nx run shared-events:schema-export\` from libs/shared/events. Do not edit by hand. -->`,
    `An event records something that happened in QAuth: a sign-in, a refused token request, a new
client. Events exist so that automation outside QAuth can act on them
([ADR-018 §3](/reference/records/adr/018-1-0-scope-and-stability/)). ADR-018 names four routes
for them: signed webhooks in the Standard Webhooks format, a cursor-based event API, Shared Signals
Framework streams, and OpenTelemetry export. Every route carries the same event, in the envelope
below. The event types and their payload schemas are part of the 1.0 stability contract (ADR-018
§5).

This page is generated from the type registry in \`libs/shared/events\`, together with the JSON
Schema files it links.`,
    `## The envelope`,
    `Every event has these members. \`type\`, \`category\` and \`data\` depend on the type; the
others mean the same for every type. A member that does not apply is absent, never \`null\`.`,
    `\`\`\`json\n${JSON.stringify(EXAMPLE_EVENT, null, 2)}\n\`\`\``,
    memberTable(memberRows(envelope)),
    `- The \`id\` is a UUIDv7, assigned once when the event is recorded. A retry, a redelivery and
  every route repeat it, so a receiver drops duplicates by it. A webhook's \`webhook-id\` header is
  the event id, and an SSF Security Event Token's \`jti\` is derived from it.
- The \`subject\` is a plain id with no database link: it stays valid after the user or the client
  is deleted.
- A webhook body is the envelope. Standard Webhooks recommends a full-stop delimited \`type\`, a
  \`timestamp\` and \`data\`: the short name in the middle of the identifier is the delimited type,
  and \`time\` is the timestamp.
- The envelope's schema is [${ENVELOPE_SCHEMA_FILE}](${SCHEMA_PATH}${ENVELOPE_SCHEMA_FILE}).`,
    `## Payload rules`,
    `These rules hold for every event's \`data\`. They were written for the audit log
([ADR-011 §8](/reference/records/adr/011-enterprise-managed-authorization/),
[ADR-017 §11](/reference/records/adr/017-first-party-login/)) and apply to events.

1. **Ids, not names or addresses.** \`data\` names a user, a client or a record by its id. A type
   that needs a name, an email address, a phone number or an IP address declares that field in
   its registry entry. No type registered today does.
2. **Never a secret.** No password, code, OTP, token, key, assertion, signature, cookie, secret,
   or set-up or reset link, in any form. There is no exception. An admin event's diff shows a
   changed resource's own fields; there a secret field holds \`***\`, never its value.
3. **Hidden identifiers are keyed HMACs.** An identifier that must not be revealed, such as the
   address a failed sign-in typed, is carried as an HMAC under a server-side key, never as the
   value and never as a plain hash.

A scanner enforces the rules. The registry's tests fail when a type's schema declares a field
named like a secret, or like personal data the type has not declared. \`parseEvent\`, the check a
single event passes before it is stored or sent, applies them again: a field named like a secret,
or a value shaped like a token or a key, refuses the event. The scanner reads names, so a field that holds an
id, a type or a count of such a thing passes when its name ends in \`Id\`, \`Type\` or \`Count\`
(\`apiKeyId\`, \`issuedTokenType\`).`,
    `## Admin events`,
    `An admin event records a change an administrator, a service account or an operator made
([ADR-020 §3](/reference/records/adr/020-ui-surfaces-and-acceptance-criteria/),
[ADR-019 Decision 7](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)). Admin
events are always on: no environment key and no realm setting turns them off. Each is written in
the transaction of the change it records, so the change and its event commit together.

**The diff.** \`data.diff\` lists what the operation changed, one entry per field:

- \`path\` names the field, as a JSON Pointer (RFC 6901) into the changed resource, such as
  \`/smtp/host\`.
- \`before\` and \`after\` hold its value. \`before\` is absent when the field did not exist, and
  \`after\` when it no longer does; \`null\` means the field held \`null\`.
- Only changed fields are listed. A nested object present on both sides is diffed member by
  member. Any other value, an array included, is shown whole.

\`\`\`json
[
  { "path": "/displayName", "before": "Notes", "after": "Team notes" },
  { "path": "/smtp/password", "before": "***", "after": "***" },
  { "path": "/allowedScopes", "before": ["openid"], "after": ["openid", "profile"] }
]
\`\`\`

**Masking.** A secret field holds \`***\` on both sides, whatever its value. A field is secret
when the operation marks it, or when its name looks like a secret by the payload rules, marked or
not. A string shaped like a token or a key is masked wherever it sits. A changed secret is still
listed, so a rotation shows as \`***\` to \`***\`. The field names in a diff are the resource's
own, so the payload scanner reads a diff's values, not its names, and checks instead that every
field named like a secret holds \`***\`.

**Approvals.** \`data.approvals\` lists the approvals the operation ran on: both approvals of a
two-admin operation, each with the approver, the passkey credential it was given with, and who
created the approver's account.

**The hash chain.** The event store chains a realm's admin events: each stores the hash of the one
before it, and its own hash is SHA-256 over that hash and the event's canonical JSON (RFC 8785). A
changed event breaks the chain at that event, and a removed one at the event after it. The
chain's hashes are stored beside the event and are not part of the envelope.`,
    `## Versioning`,
    `An event type's identifier is \`urn:qauth:event:<name>:v<N>\`. The \`<name>\` is its short
name: lower-case \`snake_case\` segments joined by full stops, the resource first. \`<N>\` is the
major version of its \`data\`. Every QAuth-defined identifier carries a version (ADR-018 §5).

**Release candidates.** Until QAuth 1.0.0, every type is a release candidate and its identifier
ends in \`-rc.<M>\`, as in \`urn:qauth:event:user.signed_in:v1-rc.0\`. Nothing about a candidate
is promised. A breaking change before 1.0.0 raises \`<M>\` (\`:v1-rc.0\` becomes \`:v1-rc.1\`), so
an identifier never names two different schemas. The release that ships QAuth 1.0.0 drops the
suffix from every type: \`:v1\` is the version under the stability promise, and the rules below
apply from then on.

Within a major release, the contract changes only by addition:

- a new type, which is a new entry in the registry;
- a new optional member of a type's \`data\`, or of the envelope;
- a new value of an open set (\`x-extensible-enum\`, shown on this page as "or a later value").

Anything else is a breaking change: removing or renaming a member, changing its type, making a
member required, adding a required member, or narrowing what a member accepts. A breaking change
makes a new type with the next version, such as \`:v2\`. QAuth emits both versions for every
event until the deprecation window ends, so a receiver moves at its own pace. The old type is
marked deprecated and names its replacement. It is removed only in a new major release, no sooner
than 12 months after the deprecation (ADR-018 §5).

A receiver ignores members it does not know, and accepts a value of an open set it does not know.
The published schemas leave objects open for that reason. A closed set, such as \`category\`, does
not grow within a major release.

The stable-surface check compares each schema file with the last release and fails on a breaking
change that no one approved.`,
    `## Schemas`,
    `Each type has a JSON Schema (draft 2020-12) of its whole event: the envelope, with \`type\`,
\`category\` and \`data\` fixed to the type. They are served under \`${SCHEMA_PATH}\`, and each
file's \`$id\` is its URL. The envelope's own schema accepts an event of any type.`,
    `## Event types`,
    summaryTable(definitions),
    ...definitions.map(typeSection),
    `## Earlier event names`,
    `Before the event contract, QAuth wrote free-form event names to its audit log and its log
lines. Each becomes a registered type. Several earlier names become one type, and the name implied
some \`data\`. Since 0.2.0 the auth server records events and writes no audit row; the upgrade
copies every audit row into the event store with this map. A copied event gets the \`data\` its name
implies and the members of the old row that have the declared form. A required member an old row
cannot supply gets a fixed value: \`unknown\` for a code, \`false\` for a flag, an empty list, \`0\`
for a count or the nil UUID for an id. Log lines keep their names.`,
    legacyTable(),
  ];
  return `${sections.join('\n\n')}\n`;
}
