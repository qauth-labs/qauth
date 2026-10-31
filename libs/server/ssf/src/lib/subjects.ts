import { z } from 'zod';

/**
 * Subject identifiers (RFC 9493, SSF 1.0 §3) and how QAuth's event subjects
 * map onto them (issue #410).
 *
 * The mapping, which every SET's `sub_id` follows (#540):
 *
 * - a user is `iss_sub`: the realm's issuer and the user's id;
 * - a client is `uri` when its `client_id` is an absolute URI (a Client ID
 *   Metadata Document URL, as agent clients have), and `opaque` with the
 *   `client_id` otherwise;
 * - a stream is `opaque` with its `stream_id` (SSF 1.0 §8.1.4.1).
 *
 * The same rules read backwards place a subject a receiver adds: `iss_sub`
 * with the realm's issuer names a user, `uri` and `opaque` name a client. A
 * subject in any other format, or with another issuer, is kept on the stream
 * and matches no event.
 */

const MEMBER_MAX = 255;
const URI_MAX = 2048;

const member = z.string().min(1).max(MEMBER_MAX);

const simpleSubjectSchemas = [
  z.strictObject({
    format: z.literal('account'),
    uri: z
      .string()
      .regex(/^acct:/)
      .max(URI_MAX),
  }),
  z.strictObject({ format: z.literal('email'), email: member }),
  z.strictObject({
    format: z.literal('iss_sub'),
    iss: z.string().min(1).max(URI_MAX),
    sub: member,
  }),
  z.strictObject({ format: z.literal('opaque'), id: member }),
  z.strictObject({ format: z.literal('phone_number'), phone_number: member }),
  z.strictObject({ format: z.literal('did'), url: z.string().min(1).max(URI_MAX) }),
  z.strictObject({ format: z.literal('uri'), uri: z.string().min(1).max(URI_MAX) }),
  // SSF 1.0 §3.4 and §3.5.
  z.strictObject({ format: z.literal('jwt_id'), iss: z.string().min(1).max(URI_MAX), jti: member }),
  z.strictObject({
    format: z.literal('saml_assertion_id'),
    issuer: z.string().min(1).max(URI_MAX),
    assertion_id: member,
  }),
] as const;

/** A subject identifier of one format (not `aliases` or `complex`). */
export const simpleSubjectSchema = z.discriminatedUnion('format', [...simpleSubjectSchemas]);

/** The members of a complex subject (SSF 1.0 §3.2). */
export const COMPLEX_SUBJECT_MEMBERS = [
  'user',
  'device',
  'session',
  'application',
  'tenant',
  'org_unit',
  'group',
] as const;

/**
 * A subject identifier a receiver may add: one of RFC 9493's formats, SSF
 * 1.0's `jwt_id` and `saml_assertion_id`, `aliases` of simple identifiers,
 * or a `complex` subject whose members are simple identifiers.
 */
export const subjectIdentifierSchema = z.union([
  simpleSubjectSchema,
  z.strictObject({
    format: z.literal('aliases'),
    identifiers: z.array(simpleSubjectSchema).min(1).max(8),
  }),
  z
    .strictObject({
      format: z.literal('complex'),
      ...Object.fromEntries(
        COMPLEX_SUBJECT_MEMBERS.map((name) => [name, simpleSubjectSchema.optional()])
      ),
    })
    .refine(
      (value) => COMPLEX_SUBJECT_MEMBERS.some((name) => name in value),
      'a complex subject names at least one member'
    ),
]);

export type SubjectIdentifier = z.infer<typeof subjectIdentifierSchema>;

type SimpleSubjectIdentifier = z.infer<typeof simpleSubjectSchema>;

/** The longest canonical form a subject may have: `ssf_stream_subjects.subject_key`. */
export const SUBJECT_KEY_MAX = 2048;

const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * A user id as the event store holds it: a UUID in lower case. Postgres
 * compares UUIDs in any case, but the event store and the fan-out compare a
 * subject's id as text.
 */
function canonicalUserId(sub: string): string {
  return UUID_SHAPE.test(sub) ? sub.toLowerCase() : sub;
}

/**
 * A receiver's subject in the form QAuth stores and compares it: the `sub` of
 * an `iss_sub` with the realm's issuer, a user id, in lower case when it is a
 * UUID, also inside `aliases` and `complex` subjects. Without it a user added
 * with an upper-case id would match none of the user's events, and the two
 * spellings would be two subjects. Any other identifier is kept as given: a
 * `sub` of another issuer, and a `client_id`, are compared as they are.
 *
 * @param issuer - The realm's issuer, the `iss` of its users' `iss_sub`.
 */
export function canonicalSubject(subject: SubjectIdentifier, issuer: string): SubjectIdentifier {
  const simple = <Subject extends SimpleSubjectIdentifier>(one: Subject): Subject =>
    one.format === 'iss_sub' && one.iss === issuer
      ? { ...one, sub: canonicalUserId(one.sub) }
      : one;
  switch (subject.format) {
    case 'aliases':
      return { ...subject, identifiers: subject.identifiers.map(simple) };
    case 'complex': {
      // The schema's members are built from a list, so the inferred type
      // names none of them.
      const members: Record<string, unknown> = { ...subject };
      for (const name of COMPLEX_SUBJECT_MEMBERS) {
        const member = members[name] as SimpleSubjectIdentifier | undefined;
        if (member !== undefined) members[name] = simple(member);
      }
      return members as SubjectIdentifier;
    }
    default:
      return simple(subject);
  }
}

/**
 * A subject's canonical form: JSON with every object's members sorted and no
 * white space, so the same subject added twice gives the same key.
 */
export function canonicalSubjectKey(subject: SubjectIdentifier): string {
  const sort = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(sort);
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(
        Object.keys(value)
          .sort()
          .map((key) => [key, sort((value as Record<string, unknown>)[key])])
      );
    }
    return value;
  };
  return JSON.stringify(sort(subject));
}

/** The longest event subject id (the envelope's `subject.id`). */
const EVENT_SUBJECT_ID_MAX = 255;

/** An event store subject: the envelope's `subject`. */
export interface EventSubject {
  readonly type: string;
  readonly id: string;
}

/** Whether `value` is an absolute URI with a scheme, as a CIMD `client_id` is. */
function isAbsoluteUri(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:/i.test(value) && URL.canParse(value);
}

/**
 * The subject identifier of an event store subject, or `undefined` for a
 * kind of subject that has none (an API key).
 *
 * @param issuer - The realm's issuer, the `iss` of its users' `iss_sub`.
 */
export function ssfSubjectOf(subject: EventSubject, issuer: string): SubjectIdentifier | undefined {
  switch (subject.type) {
    case 'user':
      return { format: 'iss_sub', iss: issuer, sub: subject.id };
    case 'client':
      return isAbsoluteUri(subject.id)
        ? { format: 'uri', uri: subject.id }
        : { format: 'opaque', id: subject.id };
    case 'ssf_stream':
      return { format: 'opaque', id: subject.id };
    default:
      return undefined;
  }
}

/**
 * The event store subject a receiver's subject stands for, by the rules of
 * {@link ssfSubjectOf} read backwards, or `null` when QAuth cannot place it.
 * An `opaque` identifier names a client, never a user or a stream: users are
 * named by `iss_sub`, and a stream's own events reach it without a subject.
 * A user's id is in lower case when it is a UUID, as the event store holds it
 * (see {@link canonicalSubject}).
 *
 * @param issuer - The realm's issuer: an `iss_sub` of another issuer is not
 *   one of this realm's users.
 */
export function eventSubjectOf(subject: SubjectIdentifier, issuer: string): EventSubject | null {
  const placed = ((): EventSubject | null => {
    switch (subject.format) {
      case 'iss_sub':
        return subject.iss === issuer ? { type: 'user', id: canonicalUserId(subject.sub) } : null;
      case 'uri':
        return { type: 'client', id: subject.uri };
      case 'opaque':
        return { type: 'client', id: subject.id };
      default:
        return null;
    }
  })();
  // An event's subject id is at most 255 characters: a longer one names none.
  return placed !== null && placed.id.length <= EVENT_SUBJECT_ID_MAX ? placed : null;
}
