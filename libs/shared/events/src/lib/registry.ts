import { z } from 'zod';

import { adminDiffSchema, scanAdminDiff } from './admin-diff';
import { EVENT_SEVERITIES, type EventTypeDefinition, RELEASE_TAG_PATTERN } from './definition';
import { envelopeSchema, EVENT_CATEGORIES, SUBJECT_TYPES, typedEnvelopeSchema } from './envelope';
import {
  compareEventVersions,
  EVENT_NAME_PATTERN,
  EVENT_TYPE_PATTERN,
  eventVersionLabel,
  parseEventType,
} from './identifier';
import { type PayloadFinding, scanJsonSchema, scanPayload, scanValues } from './payload-rules';
import { validateSsfMapping } from './ssf-mapping';
import { ADMIN_EVENT_TYPES } from './types/admin';
import { CLIENT_EVENT_TYPES } from './types/client';
import { INTERACTION_EVENT_TYPES } from './types/interaction';
import { KEY_EVENT_TYPES } from './types/key';
import { OAUTH_EVENT_TYPES } from './types/oauth';
import { REQUEST_EVENT_TYPES } from './types/request';
import { SSF_EVENT_TYPES } from './types/ssf';
import { USER_EVENT_TYPES } from './types/user';
import { WALLET_EVENT_TYPES } from './types/wallet';

/**
 * The event type registry: every type QAuth emits, once. A new type is a new
 * entry here, added in the pull request of the feature that emits it.
 */
export const EVENT_TYPES = [
  ...USER_EVENT_TYPES,
  ...OAUTH_EVENT_TYPES,
  ...CLIENT_EVENT_TYPES,
  ...WALLET_EVENT_TYPES,
  ...INTERACTION_EVENT_TYPES,
  ...REQUEST_EVENT_TYPES,
  ...SSF_EVENT_TYPES,
  ...KEY_EVENT_TYPES,
  ...ADMIN_EVENT_TYPES,
] as const;

/** The identifier of every registered type, as a union. */
export type RegisteredEventType = (typeof EVENT_TYPES)[number]['type'];

/** The registry entry of one registered type. */
export type EventTypeOf<Type extends RegisteredEventType> = Extract<
  (typeof EVENT_TYPES)[number],
  { type: Type }
>;

/** The `data` of one registered type, as QAuth emits it. */
export type EventDataOf<Type extends RegisteredEventType> = z.infer<EventTypeOf<Type>['data']>;

const BY_TYPE: ReadonlyMap<string, EventTypeDefinition> = new Map(
  EVENT_TYPES.map((definition) => [definition.type, definition])
);

/** The registry entry of `type`, or `undefined` when no such type is registered. */
export function getEventType(type: string): EventTypeDefinition | undefined {
  return BY_TYPE.get(type);
}

/** Whether `type` is a registered event type. */
export function isRegisteredEventType(type: string): type is RegisteredEventType {
  return BY_TYPE.has(type);
}

/** The schema of one type's whole event: the envelope with its `type`, `category` and `data`. */
export function eventSchemaFor(definition: EventTypeDefinition) {
  return typedEnvelopeSchema(
    definition.type,
    definition.category,
    definition.data,
    `The ${definition.name} event, ${eventVersionLabel(definition)}. ${definition.description}`
  );
}

/** An event refused by {@link parseEvent}. */
export class EventValidationError extends Error {
  override readonly name = 'EventValidationError';

  constructor(
    message: string,
    /** Where and why, one line each. */
    readonly problems: readonly string[]
  ) {
    super(`${message}: ${problems.join('; ')}`);
  }
}

const describeIssues = (issues: readonly z.core.$ZodIssue[]) =>
  issues.map((issue) => `/${issue.path.map(String).join('/')}: ${issue.message}`);

const describeFindings = (findings: readonly PayloadFinding[]) =>
  findings.map((finding) => `/data${finding.path}: ${finding.message}`);

/** A member name as a JSON Pointer segment (RFC 6901). */
const escapeMember = (member: string) => member.replace(/~/g, '~0').replace(/\//g, '~1');

/**
 * Check an event before it is stored or sent: its envelope, its type (which
 * must be registered), its `data` against the type's schema, its subject
 * against the type's (a type without one takes none), its `data` against the
 * payload rules, and every other member for token- or key-shaped values.
 *
 * @returns the event, typed by the envelope
 * @throws {EventValidationError} on an unknown type or any problem above
 */
export function parseEvent(input: unknown) {
  const envelope = envelopeSchema.safeParse(input);
  if (!envelope.success) {
    throw new EventValidationError('not an event', describeIssues(envelope.error.issues));
  }
  const definition = getEventType(envelope.data.type);
  if (!definition) {
    throw new EventValidationError('unknown event type', [
      `${envelope.data.type} is not in the registry`,
    ]);
  }
  const typed = eventSchemaFor(definition).safeParse(input);
  if (!typed.success) {
    throw new EventValidationError(
      `not a valid ${definition.type} event`,
      describeIssues(typed.error.issues)
    );
  }
  const problems: string[] = [];
  const subject = typed.data.subject;
  if (subject && !definition.subject) {
    problems.push(`/subject: a ${definition.name} event has no subject`);
  } else if (subject && subject.type !== definition.subject) {
    problems.push(
      `/subject/type: a ${definition.name} event is about a ${definition.subject}, not a ${subject.type}`
    );
  }
  const { data, ...members } = typed.data;
  const diffMembers = definition.diff === undefined ? [] : [definition.diff];
  problems.push(
    ...scanValues(members).map((finding) => `${finding.path}: ${finding.message}`),
    ...describeFindings(
      scanPayload(data, { personalData: definition.personalData ?? [], valuesOnly: diffMembers })
    ),
    ...describeFindings(
      diffMembers.flatMap((member) => scanAdminDiff(data[member], `/${escapeMember(member)}`))
    )
  );
  if (problems.length > 0) {
    throw new EventValidationError(`not a valid ${definition.type} event`, problems);
  }
  return envelope.data;
}

/**
 * Check registry entries against the registry's rules. The registry's own
 * test runs it over {@link EVENT_TYPES}; it takes the entries as an argument
 * so the test can show that each rule fails a bad entry.
 *
 * @param dataJsonSchema the published JSON Schema of an entry's `data`, which
 *   the payload rules are checked against
 * @returns one line per problem; empty when every entry is sound
 */
export function validateRegistry(
  definitions: readonly EventTypeDefinition[],
  dataJsonSchema: (definition: EventTypeDefinition) => unknown
): string[] {
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const definition of definitions) {
    const at = definition.type ?? '(no type)';
    const parsed = typeof definition.type === 'string' ? parseEventType(definition.type) : null;
    if (!parsed || !EVENT_TYPE_PATTERN.test(definition.type)) {
      problems.push(`${at}: the identifier must match urn:qauth:event:<name>:v<N>[-rc.<M>]`);
    } else if (
      parsed.name !== definition.name ||
      parsed.version !== definition.version ||
      parsed.rc !== definition.rc
    ) {
      problems.push(
        `${at}: the identifier must be built from the name, the version and the candidate number`
      );
    }
    if (!EVENT_NAME_PATTERN.test(definition.name ?? '')) {
      problems.push(`${at}: the name must be snake_case segments joined by full stops`);
    }
    if (seen.has(definition.type)) problems.push(`${at}: registered twice`);
    seen.add(definition.type);
    if (!(definition.data instanceof z.ZodObject)) {
      problems.push(`${at}: the data schema must be a Zod object`);
    } else if (definition.data.def.catchall?._zod.def.type !== 'never') {
      problems.push(`${at}: the data schema must be closed (z.strictObject)`);
    }
    if (!(EVENT_CATEGORIES as readonly string[]).includes(definition.category)) {
      problems.push(`${at}: the category must be one of ${EVENT_CATEGORIES.join(', ')}`);
    }
    if (!(EVENT_SEVERITIES as readonly string[]).includes(definition.severity)) {
      problems.push(`${at}: the severity must be one of ${EVENT_SEVERITIES.join(', ')}`);
    }
    if (!RELEASE_TAG_PATTERN.test(definition.since ?? '')) {
      problems.push(`${at}: since must be the release it appeared in, such as v0.2.0`);
    }
    if (typeof definition.description !== 'string' || definition.description.trim() === '') {
      problems.push(`${at}: the description must say when QAuth emits it`);
    }
    if (
      definition.subject !== undefined &&
      !(SUBJECT_TYPES as readonly string[]).includes(definition.subject)
    ) {
      problems.push(`${at}: the subject must be one of ${SUBJECT_TYPES.join(', ')}`);
    }
    // Shared Signals (#540): a security type declares how it reaches SSF
    // streams, a mapping or 'none', so no area adds one and forgets SSF; and
    // only a security type declares it, so a mapping always means one.
    if (definition.security !== undefined && definition.security !== true) {
      problems.push(`${at}: security is true or absent`);
    }
    if (definition.security === true && definition.ssf === undefined) {
      problems.push(`${at}: a security type must declare its SSF mapping, or ssf: 'none'`);
    }
    if (definition.security !== true && definition.ssf !== undefined) {
      problems.push(`${at}: only a security type declares ssf`);
    }
    problems.push(...validateSsfMapping(definition).map((problem) => `${at}: ${problem}`));
    if (definition.diff !== undefined) {
      if (definition.category !== 'admin') {
        problems.push(`${at}: only an admin type carries a diff`);
      }
      const member =
        definition.data instanceof z.ZodObject ? definition.data.shape[definition.diff] : undefined;
      if (member !== adminDiffSchema) {
        problems.push(`${at}: data.${definition.diff} must be adminDiffSchema, as it is`);
      }
    }
    if (definition.data instanceof z.ZodObject) {
      let published: unknown;
      try {
        published = dataJsonSchema(definition);
      } catch (error) {
        problems.push(
          `${at}: the event cannot be published as JSON Schema: ${(error as Error).message}`
        );
      }
      for (const finding of scanJsonSchema(published, {
        personalData: definition.personalData ?? [],
      })) {
        problems.push(`${at}: data${finding.path}: ${finding.message}`);
      }
    }
  }

  // The versioning rules: a breaking change registers the next version beside
  // the old one, and the old one is deprecated in favour of it until it is
  // removed. Each version of a type, in order, names the one after it.
  const byName = new Map<string, EventTypeDefinition[]>();
  for (const definition of definitions) {
    byName.set(definition.name, [...(byName.get(definition.name) ?? []), definition]);
  }
  for (const versions of byName.values()) {
    const ordered = [...versions].sort(compareEventVersions);
    ordered.slice(0, -1).forEach((definition, index) => {
      const next = ordered[index + 1];
      // The same version twice is already reported as registered twice.
      if (compareEventVersions(definition, next) === 0) return;
      if (definition.deprecated?.replacedBy !== next.type) {
        problems.push(`${definition.type}: must be deprecated with replacedBy ${next.type}`);
      }
    });
  }
  for (const definition of definitions) {
    const at = definition.type;
    if (definition.deprecated) {
      const { replacedBy, since } = definition.deprecated;
      const replacement = parseEventType(replacedBy);
      if (!seen.has(replacedBy) || replacement?.name !== definition.name) {
        problems.push(`${at}: replacedBy must name a registered later version of the same type`);
      } else if (compareEventVersions(replacement, definition) <= 0) {
        problems.push(`${at}: replacedBy must name a later version`);
      }
      if (!RELEASE_TAG_PATTERN.test(since)) {
        problems.push(`${at}: deprecated.since must be a release, such as v1.2.0`);
      }
    }
  }
  return problems;
}
