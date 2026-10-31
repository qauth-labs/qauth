import type { EventTypeDefinition, SsfMemberSource } from './definition';
import { headingAnchor, tableCell, typeHeading } from './docs-page';
import {
  INITIATING_ENTITIES_DOC,
  QAUTH_SSF_EVENTS,
  type SsfEventDefinition,
  ssfEventDefinition,
  ssfMappingOf,
} from './ssf-mapping';

/**
 * The docs page `reference/ssf-events.md` (#540), rendered from the registry:
 * which SSF event each security type is sent as, its subject and its
 * members, the security types with no SSF event, and the QAuth-defined
 * events. Generated, never edited by hand; the export script writes it and a
 * test fails when the committed page differs.
 */

/** The date the page's hand-written prose was last checked; change it with the prose. */
export const SSF_EVENTS_PAGE_LAST_VERIFIED = '2026-10-31';

const code = (value: string) => `\`${value}\``;

/** Where a type's section on the events page is. */
const eventsPageLink = (definition: EventTypeDefinition) =>
  `[${code(definition.name)}](/reference/events/#${headingAnchor(typeHeading(definition))})`;

/** The anchor of a QAuth-defined event's section on this page. */
const qauthEventAnchor = (event: SsfEventDefinition) => headingAnchor(event.name);

function ssfEventCell(uri: string): string {
  const event = ssfEventDefinition(uri);
  if (event === undefined) return code(uri);
  if (event.definedIn === 'QAuth') {
    return `[${code(event.name)}](#${qauthEventAnchor(event)}) (QAuth)`;
  }
  return `${code(event.name)} (${event.definedIn})`;
}

function subjectCell(definition: EventTypeDefinition): string {
  const mapping = ssfMappingOf(definition);
  switch (mapping?.subject ?? 'subject') {
    case 'client':
      return 'the event’s client, `uri` or `opaque`';
    case 'key':
      return 'the key, `opaque` with its `kid`';
    default:
      return definition.subject === 'client'
        ? 'the client, `uri` or `opaque`'
        : 'the user, `iss_sub`';
  }
}

function deliveredCell(definition: EventTypeDefinition): string {
  const mapping = ssfMappingOf(definition);
  if (mapping?.subject === 'key') return 'every stream of the realm that requested it';
  if (mapping?.clientOnly) return 'the stream of the event’s client, when it added the subject';
  return 'every stream that added the subject';
}

const json = (value: unknown) => code(JSON.stringify(value));

function memberSource(name: string, source: SsfMemberSource): string {
  if ('value' in source) return `${code(name)}: ${json(source.value)}`;
  if (source.map === undefined) return `${code(name)}: ${code(`data.${source.data}`)}`;
  const entries = Object.entries(source.map);
  if (entries.every(([, value]) => typeof value === 'string')) {
    const listed = entries.map(([key, value]) => `${code(key)} → ${json(value)}`).join(', ');
    return `${code(name)}: by ${code(`data.${source.data}`)} (${listed})`;
  }
  return `${code(name)}: by ${code(`data.${source.data}`)}`;
}

function membersCell(definition: EventTypeDefinition): string {
  const mapping = ssfMappingOf(definition);
  const members = Object.entries(mapping?.members ?? {}).map(([name, source]) =>
    memberSource(name, source)
  );
  members.push(
    mapping?.initiatingEntity === undefined
      ? '`initiating_entity` from the actor'
      : `${code('initiating_entity')}: ${json(mapping.initiatingEntity)}`
  );
  return members.join('; ');
}

function mappingTable(definitions: readonly EventTypeDefinition[]): string {
  const lines = [
    '| QAuth event type | SSF event | Subject | Delivered to | Members besides `event_timestamp` |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const definition of definitions) {
    const mapping = ssfMappingOf(definition);
    if (mapping === undefined) continue;
    lines.push(
      `| ${eventsPageLink(definition)} | ${ssfEventCell(mapping.event)} | ${subjectCell(definition)} | ${deliveredCell(definition)} | ${tableCell(membersCell(definition))} |`
    );
  }
  return lines.join('\n');
}

function notesList(definitions: readonly EventTypeDefinition[]): string {
  const notes = definitions
    .filter((definition) => ssfMappingOf(definition) !== undefined && definition.ssfNote)
    .map((definition) => `- ${eventsPageLink(definition)}: ${definition.ssfNote}`);
  return ['Notes on the mapping:', notes.join('\n')].join('\n\n');
}

function unmappedTable(definitions: readonly EventTypeDefinition[]): string {
  const lines = ['| QAuth event type | Why it has no SSF event |', '| --- | --- |'];
  for (const definition of definitions) {
    if (definition.ssf !== 'none') continue;
    lines.push(`| ${eventsPageLink(definition)} | ${tableCell(definition.ssfNote ?? '')} |`);
  }
  return lines.join('\n');
}

function qauthEventSection(event: SsfEventDefinition, definitions: readonly EventTypeDefinition[]) {
  const from = definitions
    .filter((definition) => ssfMappingOf(definition)?.event === event.uri)
    .map(eventsPageLink);
  const lines = ['| Member | Required | Meaning |', '| --- | --- | --- |'];
  lines.push(
    '| `event_timestamp` | yes | When the event happened, in seconds since the epoch (CAEP 1.0 §2). |'
  );
  lines.push(
    '| `initiating_entity` | no | Who invoked it, as CAEP 1.0 §2 names it; see [Common members](#common-members). |'
  );
  for (const [name, member] of Object.entries(event.members)) {
    lines.push(
      `| ${code(name)} | ${member.required ? 'yes' : 'no'} | ${tableCell(member.description)} |`
    );
  }
  return [
    `### ${event.name}`,
    [
      `- Identifier: ${code(event.uri)}`,
      `- Sent for: ${from.length > 0 ? from.join(', ') : 'no type yet'}`,
    ].join('\n'),
    event.description,
    lines.join('\n'),
  ].join('\n\n');
}

/** Render the whole page. */
export function renderSsfEventsPage(definitions: readonly EventTypeDefinition[]): string {
  const sections = [
    `---
title: SSF events
description: The Shared Signals Framework event each QAuth security event is sent as, with its subject and its members, generated from the registry in libs/shared/events.
sidebar:
  order: 5
lastVerified: '${SSF_EVENTS_PAGE_LAST_VERIFIED}'
---`,
    `<!-- Generated by \`pnpm exec nx run shared-events:schema-export\` from libs/shared/events. Do not edit by hand. -->`,
    `QAuth's [SSF transmitter](/operate/ssf-transmitter/) sends the events that record a security
change to receivers' streams, as Security Event Tokens (SETs, RFC 8417). Each is sent as a CAEP 1.0
or RISC 1.0 event where one says the same thing, and as a QAuth-defined event where none does.
Resource servers and relying parties use them to stop honouring a revoked session, grant or
credential before its tokens expire ([ADR-019 Decision 8](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)).

The [event registry](/reference/events/) marks every type that records a security change: a
session, a grant, a token, a credential, a key or an account that a receiver may have to act on.
Each security type declares the SSF event it is sent as, or that it has none; the registry's test
fails when one declares neither, so no feature adds a security event and forgets SSF. This page is
generated from those declarations.`,
    `## The SET`,
    `A SET carries one event and these claims:

- \`iss\`: the realm's issuer; \`aud\`: the receiver's \`client_id\`.
- \`jti\`: the event's id, and \`iat\`: the event's time, in seconds. A retry sends the same SET,
  so a receiver drops a duplicate by its \`jti\`.
- \`sub_id\`: the subject (SSF 1.0 §3, RFC 9493), as below.
- \`events\`: one member, keyed by the SSF event's URI.

It carries no \`sub\` and no \`exp\` (SSF 1.0 §4.1.2, §4.1.7). Its header names the signing key
(\`kid\`) and \`typ: secevent+jwt\`; the keys are at the transmitter's \`jwks_uri\`.`,
    `## Common members`,
    `Every mapped event carries \`event_timestamp\`, the time the event happened in seconds (CAEP
1.0 §2). It carries \`initiating_entity\` when QAuth knows who invoked it: ${INITIATING_ENTITIES_DOC}
A mapping may fix it instead, as the replay policy does.`,
    `## Subjects`,
    `- A user is \`iss_sub\`: the realm's issuer and the user's id.
- A client is \`uri\` when its \`client_id\` is an absolute URI, as an agent client's Client ID
  Metadata Document URL is, and \`opaque\` with the \`client_id\` otherwise.
- A key is \`opaque\` with its \`kid\`.

The transmitter's \`default_subjects\` is \`NONE\`: a stream receives an event only when it
requested the event and its receiver added the subject, except an event about a key, which every
stream of the realm that requested it receives. An event marked as going to the event's client
reaches only the stream whose receiver is that client: it tells of the user's dealings with that
one client, which another receiver has no need to see.

A receiver may add a user only when the user is related to it: the user has an active consent for
the receiver's client or a live refresh token it was issued, or, for a receiver that serves as a
resource server, a live refresh token whose audience names it. Any other user, and a user id that
does not exist, is refused with \`403\`, as SSF 1.0 §8.1.3.2 prescribes for a subject the receiver
may not add. A user subject lasts as long as its relation: the hourly \`ssf-subject-sweep\` job
deletes it once the relation has ended and every event about the user has reached the stream, so
the SET that tells of the end still arrives. A disabled user is related to no receiver, so after
\`account-disabled\` reaches a stream the sweep deletes the user's subject there, and
\`account-enabled\` reaches only a stream the sweep has not cleared yet: once the user is enabled,
the receiver adds them again. The [SSF transmitter](/operate/ssf-transmitter/) guide gives the
whole rule.`,
    `## Mapping`,
    mappingTable(definitions),
    notesList(definitions),
    `## Security events with no SSF event`,
    unmappedTable(definitions),
    `## QAuth-defined events`,
    `Where no CAEP 1.0 or RISC 1.0 event says what happened, QAuth defines one. Its identifier is
\`urn:qauth:secevent:<name>:v<N>\`, a URN rather than a URL so that it never looks like a standard
event, and versioned so that a standard one can later sit beside it (ADR-018 §5). Until QAuth 1.0.0
every QAuth-defined identifier is a release candidate, \`:v<N>-rc.<M>\`, and nothing about it is
promised: a breaking change raises \`<M>\`. The release that ships 1.0.0 drops the suffix. A
receiver ignores members it does not know (SSF 1.0 §4.2.3).`,
    ...QAUTH_SSF_EVENTS.map((event) => qauthEventSection(event, definitions)),
  ];
  return `${sections.join('\n\n')}\n`;
}
