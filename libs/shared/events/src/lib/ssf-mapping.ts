import { z } from 'zod';

import {
  type EventTypeDefinition,
  INITIATING_ENTITIES,
  type InitiatingEntity,
  type SsfEventMapping,
  type SsfJsonValue,
  type SsfMemberSource,
} from './definition';
import type { EventEnvelope } from './envelope';

/**
 * The Shared Signals Framework events QAuth's security types are sent as
 * (#540), and the rules a mapping follows. The registry entries say which
 * type maps to which event (`ssf` of a definition); this module knows the
 * events themselves: their URIs, their members and which members they
 * require, as CAEP 1.0 §3 and RISC 1.0 §2 define them, and the QAuth-defined
 * events for what no standard event describes.
 */

/** The base URI of CAEP 1.0 event types (CAEP 1.0 §3). */
export const CAEP_EVENT_BASE = 'https://schemas.openid.net/secevent/caep/event-type/';

/** The base URI of RISC 1.0 event types (RISC 1.0 §2). */
export const RISC_EVENT_BASE = 'https://schemas.openid.net/secevent/risc/event-type/';

export const CAEP_SESSION_REVOKED = `${CAEP_EVENT_BASE}session-revoked`;
export const CAEP_TOKEN_CLAIMS_CHANGE = `${CAEP_EVENT_BASE}token-claims-change`;
export const CAEP_CREDENTIAL_CHANGE = `${CAEP_EVENT_BASE}credential-change`;
export const CAEP_ASSURANCE_LEVEL_CHANGE = `${CAEP_EVENT_BASE}assurance-level-change`;
export const RISC_ACCOUNT_DISABLED = `${RISC_EVENT_BASE}account-disabled`;
export const RISC_ACCOUNT_ENABLED = `${RISC_EVENT_BASE}account-enabled`;

/**
 * A QAuth-defined SSF event identifier: `urn:qauth:secevent:<name>:v<N>`, with
 * `-rc.<M>` until QAuth 1.0.0 (ADR-018 §5). `<name>` is lower-case words
 * joined by hyphens, as CAEP names its events.
 */
export const QAUTH_SECEVENT_PATTERN =
  /^urn:qauth:secevent:([a-z][a-z0-9]*(?:-[a-z0-9]+)*):v([1-9][0-9]*)(?:-rc\.(0|[1-9][0-9]*))?$/;

/** The members every mapped event gets from the envelope, never from a mapping (CAEP 1.0 §2). */
export const SSF_COMPUTED_MEMBERS = ['event_timestamp', 'initiating_entity'] as const;

/** One member an SSF event defines. */
export interface SsfEventMember {
  /** What it holds. */
  readonly description: string;
  /** The JSON type its value has: a string, or an object. */
  readonly kind: 'string' | 'object';
  /** Whether the event requires it. */
  readonly required?: true;
  /** The only values it may take, when its definition lists them. */
  readonly values?: readonly string[];
}

/** An SSF event QAuth may send: where it is defined and its members. */
export interface SsfEventDefinition {
  /** The event type URI. */
  readonly uri: string;
  /** The short name the docs show, such as `session-revoked`. */
  readonly name: string;
  /** Where it is defined, such as `CAEP 1.0 §3.1`, or `QAuth` for a QAuth-defined event. */
  readonly definedIn: string;
  /** What the event says, for a QAuth-defined event; the standard's own text otherwise. */
  readonly description: string;
  /** Its members, beyond {@link SSF_COMPUTED_MEMBERS}. */
  readonly members: Readonly<Record<string, SsfEventMember>>;
}

const REASON_ADMIN: SsfEventMember = {
  kind: 'object',
  description:
    'A message for logging and auditing, as an object keyed by BCP 47 language tag (CAEP 1.0 §2). QAuth sends `en`.',
};

/** The CAEP 1.0 and RISC 1.0 events QAuth maps to. */
export const STANDARD_SSF_EVENTS: readonly SsfEventDefinition[] = Object.freeze<
  SsfEventDefinition[]
>([
  {
    uri: CAEP_SESSION_REVOKED,
    name: 'session-revoked',
    definedIn: 'CAEP 1.0 §3.1',
    description: 'The session identified by the subject has been revoked.',
    members: { reason_admin: REASON_ADMIN },
  },
  {
    uri: CAEP_TOKEN_CLAIMS_CHANGE,
    name: 'token-claims-change',
    definedIn: 'CAEP 1.0 §3.2',
    description: 'A claim in a token identified by the subject has changed.',
    members: {
      claims: {
        kind: 'object',
        description: 'The claims that changed, with their new values.',
        required: true,
      },
      reason_admin: REASON_ADMIN,
    },
  },
  {
    uri: CAEP_CREDENTIAL_CHANGE,
    name: 'credential-change',
    definedIn: 'CAEP 1.0 §3.3',
    description: 'A credential was created, changed, revoked or deleted.',
    members: {
      credential_type: {
        kind: 'string',
        description:
          'The kind of credential: one CAEP 1.0 lists, or one the transmitter and the receiver agree on.',
        required: true,
      },
      change_type: {
        kind: 'string',
        description: 'What happened to it.',
        required: true,
        values: ['create', 'revoke', 'update', 'delete'],
      },
      friendly_name: { kind: 'string', description: 'The credential’s friendly name.' },
      reason_admin: REASON_ADMIN,
    },
  },
  {
    uri: CAEP_ASSURANCE_LEVEL_CHANGE,
    name: 'assurance-level-change',
    definedIn: 'CAEP 1.0 §3.4',
    description: 'The authentication method changed since the user signed in.',
    members: {
      namespace: { kind: 'string', description: 'The namespace of the levels.', required: true },
      current_level: {
        kind: 'string',
        description: 'The current assurance level.',
        required: true,
      },
      previous_level: { kind: 'string', description: 'The previous assurance level.' },
      change_direction: {
        kind: 'string',
        description: 'Whether the level went up or down.',
        values: ['increase', 'decrease'],
      },
      reason_admin: REASON_ADMIN,
    },
  },
  {
    uri: RISC_ACCOUNT_DISABLED,
    name: 'account-disabled',
    definedIn: 'RISC 1.0 §2.3',
    description: 'The account identified by the subject has been disabled.',
    members: {
      reason: {
        kind: 'string',
        description: 'Why it was disabled.',
        values: ['hijacking', 'bulk-account'],
      },
    },
  },
  {
    uri: RISC_ACCOUNT_ENABLED,
    name: 'account-enabled',
    definedIn: 'RISC 1.0 §2.4',
    description: 'The account identified by the subject has been enabled.',
    members: {},
  },
]);

/** RFC 7009 token revocation: no CAEP event matches it one to one (#540). */
export const QAUTH_TOKEN_REVOKED = 'urn:qauth:secevent:token-revoked:v1-rc.0';

/** Emergency key retirement (ADR-019 Decision 9). */
export const QAUTH_KEY_EMERGENCY_RETIRED = 'urn:qauth:secevent:key-emergency-retired:v1-rc.0';

/**
 * The QAuth-defined SSF events. Each identifier is versioned, and is a
 * release candidate until QAuth 1.0.0: a breaking change raises `<M>`, and
 * the release that ships 1.0.0 drops the suffix (ADR-018 §5).
 */
export const QAUTH_SSF_EVENTS: readonly SsfEventDefinition[] = Object.freeze<SsfEventDefinition[]>([
  {
    uri: QAUTH_TOKEN_REVOKED,
    name: 'token-revoked',
    definedIn: 'QAuth',
    description:
      'A client revoked a token of the subject at the RFC 7009 revocation endpoint. The SET goes to the stream of that client only. QAuth defines it because no CAEP event matches: `session-revoked` would say the whole session ended, and `credential-change` is about a credential the subject authenticates with.',
    members: {
      token_type_hint: {
        kind: 'string',
        description:
          'The `token_type_hint` the client sent, such as `refresh_token`. Absent when it sent none.',
      },
    },
  },
  {
    uri: QAUTH_KEY_EMERGENCY_RETIRED,
    name: 'key-emergency-retired',
    definedIn: 'QAuth',
    description:
      'An operator retired a key of the realm that may be compromised (ADR-019 Decision 9). It left the JWKS at once and no verifier in the auth server accepts it. A verifier drops the key the SET names. The subject is the key, as an `opaque` identifier holding its `kid`, and every stream of the realm that requested the event receives it.',
    members: {
      kid: { kind: 'string', description: 'The `kid` of the retired key.', required: true },
      purpose: {
        kind: 'string',
        description: 'What the key was for, such as `token_signing`.',
      },
    },
  },
]);

const SSF_EVENTS_BY_URI: ReadonlyMap<string, SsfEventDefinition> = new Map(
  [...STANDARD_SSF_EVENTS, ...QAUTH_SSF_EVENTS].map((event) => [event.uri, event])
);

/** The definition of an SSF event QAuth knows, or `undefined`. */
export function ssfEventDefinition(uri: string): SsfEventDefinition | undefined {
  return SSF_EVENTS_BY_URI.get(uri);
}

/** The mapping of a type, or `undefined` when it has none (or `'none'`). */
export function ssfMappingOf(definition: EventTypeDefinition): SsfEventMapping | undefined {
  return typeof definition.ssf === 'object' ? definition.ssf : undefined;
}

const isJson = (value: unknown): value is SsfJsonValue => {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJson);
  if (typeof value === 'object') {
    return Object.getPrototypeOf(value) === Object.prototype && Object.values(value).every(isJson);
  }
  return false;
};

/** The schema of `data.<member>`, unwrapped from `optional`, and whether it is optional. */
function dataMember(
  definition: EventTypeDefinition,
  member: string
): { schema: z.ZodType; optional: boolean } | undefined {
  const shape = definition.data instanceof z.ZodObject ? definition.data.shape : {};
  if (!Object.hasOwn(shape, member)) return undefined;
  let schema = shape[member] as z.ZodType;
  let optional = false;
  while (schema instanceof z.ZodOptional) {
    optional = true;
    schema = schema.unwrap() as z.ZodType;
  }
  return { schema, optional };
}

/** The JSON type of a data member's values, when it is a string or an object. */
function dataKind(schema: z.ZodType): 'string' | 'object' | undefined {
  if (schema instanceof z.ZodString || schema instanceof z.ZodEnum) return 'string';
  if (schema instanceof z.ZodLiteral) {
    return [...schema.values].every((value) => typeof value === 'string') ? 'string' : undefined;
  }
  if (schema instanceof z.ZodObject) return 'object';
  return undefined;
}

/** A member kind with its article, for a problem line. */
const kindName = (kind: 'string' | 'object') => (kind === 'object' ? 'an object' : 'a string');

/** The JSON type of a value, as an SSF member's `kind` names it. */
const valueKind = (value: unknown): 'string' | 'object' | undefined =>
  typeof value === 'string'
    ? 'string'
    : value !== null && typeof value === 'object' && !Array.isArray(value)
      ? 'object'
      : undefined;

/** The values a data member can take, as `map` keys, when they form a closed set. */
function closedValues(schema: z.ZodType): string[] | undefined {
  if (schema instanceof z.ZodBoolean) return ['true', 'false'];
  if (schema instanceof z.ZodEnum) return schema.options.map(String);
  if (schema instanceof z.ZodLiteral) return [...schema.values].map(String);
  return undefined;
}

/**
 * Check one type's SSF mapping against the event it names.
 *
 * @returns one line per problem, without the type; empty when it is sound
 */
export function validateSsfMapping(definition: EventTypeDefinition): string[] {
  const problems: string[] = [];
  if (definition.ssfNote !== undefined && definition.ssf === undefined) {
    problems.push('ssfNote explains a mapping, so it needs ssf');
  }
  const mapping = definition.ssf;
  if (mapping === 'none' && (definition.ssfNote ?? '').trim() === '') {
    problems.push("ssf: 'none' needs an ssfNote saying why the type has no SSF event");
  }
  if (mapping === undefined || mapping === 'none') return problems;
  if (typeof mapping !== 'object' || mapping === null) {
    return [...problems, "ssf must be a mapping or 'none'"];
  }

  const event = ssfEventDefinition(mapping.event);
  if (event === undefined) {
    problems.push(
      QAUTH_SECEVENT_PATTERN.test(mapping.event)
        ? `ssf.event ${mapping.event} is not a QAuth-defined SSF event; list it in QAUTH_SSF_EVENTS`
        : `ssf.event must be a CAEP 1.0 or RISC 1.0 event, or urn:qauth:secevent:<name>:v<N>[-rc.<M>]`
    );
  } else if (event.definedIn === 'QAuth' && !QAUTH_SECEVENT_PATTERN.test(event.uri)) {
    problems.push(`ssf.event ${event.uri} must match urn:qauth:secevent:<name>:v<N>[-rc.<M>]`);
  }

  const subject = mapping.subject ?? 'subject';
  if (subject === 'subject' && definition.subject !== 'user' && definition.subject !== 'client') {
    problems.push('ssf.subject "subject" needs a type whose subject is a user or a client');
  } else if (subject === 'key') {
    const keyId = dataMember(definition, 'keyId');
    if (keyId === undefined || keyId.optional) {
      problems.push('ssf.subject "key" needs a required data.keyId');
    } else if (dataKind(keyId.schema) !== 'string') {
      // The SET names the key as an `opaque` identifier, a string: any other
      // keyId would leave every event of the type unsent.
      problems.push('ssf.subject "key" needs data.keyId to be a string');
    }
    // A key event reaches every stream of the realm: a type about a user or a
    // client must never widen its delivery that way.
    if (definition.subject !== undefined) {
      problems.push('ssf.subject "key" is for a type with no subject, as a realm key is');
    }
  } else if (subject !== 'subject' && subject !== 'client' && subject !== 'key') {
    problems.push('ssf.subject must be subject, client or key');
  }
  if (mapping.clientOnly !== undefined && mapping.clientOnly !== true) {
    problems.push('ssf.clientOnly is true or absent');
  }
  if (subject === 'key' && mapping.clientOnly) {
    problems.push('an event about a key goes to every stream of the realm, never to one client');
  }
  // A receiver may add any client of the realm as a subject: no relation is
  // checked for a client, as it is for a user. So an event about a client
  // reaches only that client's own stream, never every receiver that added it.
  if (
    (subject === 'client' || (subject === 'subject' && definition.subject === 'client')) &&
    mapping.clientOnly !== true
  ) {
    problems.push(
      'an event about a client goes to its own stream only: set ssf.clientOnly, since any receiver may add a client'
    );
  }
  if (
    mapping.initiatingEntity !== undefined &&
    !(INITIATING_ENTITIES as readonly string[]).includes(mapping.initiatingEntity)
  ) {
    problems.push(`ssf.initiatingEntity must be one of ${INITIATING_ENTITIES.join(', ')}`);
  }

  const members = mapping.members ?? {};
  for (const [name, source] of Object.entries(members)) {
    const at = `ssf.members.${name}`;
    if ((SSF_COMPUTED_MEMBERS as readonly string[]).includes(name)) {
      problems.push(`${at}: QAuth sets ${name} from the envelope; a mapping does not`);
      continue;
    }
    const member = event?.members[name];
    if (event !== undefined && member === undefined) {
      problems.push(`${at}: ${event.name} defines no such member`);
    }
    const values: unknown[] = [];
    if ('value' in source) {
      values.push(source.value);
    } else if ('data' in source && typeof source.data === 'string') {
      const data = dataMember(definition, source.data);
      if (data === undefined) {
        problems.push(`${at}: data.${source.data} is not a member of the type's data`);
      } else if (source.map === undefined && member !== undefined) {
        // Taken as it is: the data member's own values must fit the SSF
        // member, its JSON type and, when it lists them, its values.
        if (dataKind(data.schema) !== member.kind) {
          problems.push(
            `${at}: data.${source.data} is not ${kindName(member.kind)}, as ${name} is`
          );
        }
        if (member.values) {
          const closed = closedValues(data.schema);
          const outside =
            closed === undefined
              ? ['(an open set of values)']
              : closed.filter((value) => !member.values?.includes(value));
          if (outside.length > 0) {
            problems.push(
              `${at}: data.${source.data} may hold ${outside.join(', ')}, not one of ${member.values.join(', ')}; map it`
            );
          }
        }
      }
      if (data !== undefined && member?.required) {
        // A required member must be there on every event: from a required
        // data member, and through a map that lists every value it can take.
        if (data.optional) {
          problems.push(
            `${at}: a required member cannot come from the optional data.${source.data}`
          );
        }
        if (source.map !== undefined) {
          const closed = closedValues(data.schema);
          const missing =
            closed === undefined
              ? ['(an open set of values)']
              : closed.filter((value) => !Object.hasOwn(source.map ?? {}, value));
          if (missing.length > 0) {
            problems.push(
              `${at}: the map must list every value of data.${source.data}: ${missing.join(', ')}`
            );
          }
        }
      }
      if (source.map !== undefined) values.push(...Object.values(source.map));
    } else {
      problems.push(`${at}: a member source is { value } or { data, map? }`);
      continue;
    }
    for (const value of values) {
      if (!isJson(value)) problems.push(`${at}: a value must be plain JSON`);
      else if (member !== undefined && valueKind(value) !== member.kind) {
        problems.push(
          `${at}: ${JSON.stringify(value)} is not ${kindName(member.kind)}, as ${name} is`
        );
      } else if (member?.values && !(typeof value === 'string' && member.values.includes(value))) {
        problems.push(`${at}: ${JSON.stringify(value)} is not one of ${member.values.join(', ')}`);
      }
    }
  }
  if (event !== undefined) {
    for (const [name, member] of Object.entries(event.members)) {
      if (member.required && !Object.hasOwn(members, name)) {
        problems.push(`ssf.members.${name}: ${event.name} requires it`);
      }
    }
  }
  return problems;
}

/** How {@link initiatingEntityOf} reads the actor, for the docs page. */
export const INITIATING_ENTITIES_DOC =
  '`user` for a person acting on their own account, `admin` for an administrator (a person acting on an admin event, or an operator on the server host), and `system` for QAuth itself. A client acting for itself names none.';

/** The `initiating_entity` an event's actor stands for, when it names one (CAEP 1.0 §2). */
export function initiatingEntityOf(
  event: Pick<EventEnvelope, 'actor' | 'category'>
): InitiatingEntity | undefined {
  switch (event.actor?.type) {
    case 'user':
      return event.category === 'admin' ? 'admin' : 'user';
    case 'operator_cli':
      return 'admin';
    case 'system':
      return 'system';
    default:
      return undefined;
  }
}

/**
 * The members of the SSF event a mapped type's event is sent as: the mapped
 * members, then `event_timestamp` and `initiating_entity` (CAEP 1.0 §2).
 *
 * @returns the members, or `undefined` when a member the SSF event requires
 *   cannot be filled from this event, which is then not sent
 */
export function ssfEventMembers(
  mapping: SsfEventMapping,
  event: Pick<EventEnvelope, 'time' | 'actor' | 'category' | 'data'>
): Record<string, SsfJsonValue> | undefined {
  const time = Date.parse(event.time);
  if (!Number.isFinite(time)) return undefined;
  const members: Record<string, SsfJsonValue> = {};
  for (const [name, source] of Object.entries(mapping.members ?? {})) {
    const value = memberValue(source, event.data);
    if (value !== undefined) members[name] = value;
  }
  const definition = ssfEventDefinition(mapping.event);
  for (const [name, member] of Object.entries(definition?.members ?? {})) {
    if (member.required && !Object.hasOwn(members, name)) return undefined;
  }
  members['event_timestamp'] = Math.floor(time / 1000);
  const initiating = mapping.initiatingEntity ?? initiatingEntityOf(event);
  if (initiating !== undefined) members['initiating_entity'] = initiating;
  return members;
}

function memberValue(
  source: SsfMemberSource,
  data: Readonly<Record<string, unknown>>
): SsfJsonValue | undefined {
  if ('value' in source) return source.value;
  if (!Object.hasOwn(data, source.data)) return undefined;
  const value = data[source.data];
  if (source.map === undefined) return isJson(value) ? value : undefined;
  const key = String(value);
  return Object.hasOwn(source.map, key) ? source.map[key] : undefined;
}
