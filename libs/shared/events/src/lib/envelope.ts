import { z } from 'zod';

import { EVENT_TYPE_PATTERN } from './identifier';

/**
 * The event envelope (ADR-018 §3 and §5, ADR-019 Decision 8): what every
 * QAuth event looks like, on all four delivery routes. A webhook body is the
 * envelope itself; the event API returns envelopes; an SSF Security Event
 * Token and an OpenTelemetry log record are built from one.
 *
 * The schemas here are closed (`strictObject`): QAuth emits only the members
 * they declare. The JSON Schema published from them leaves objects open,
 * because a minor release may add optional members and a consumer ignores
 * the ones it does not know (see `json-schema.ts`).
 */

/** Who an event is for: an end user's own activity, or an administrator's. */
export const EVENT_CATEGORIES = ['user', 'admin'] as const;
export type EventCategory = (typeof EVENT_CATEGORIES)[number];

/** The kinds of actor an event names. The set may grow in a minor release. */
export const ACTOR_TYPES = ['user', 'client', 'system', 'operator_cli'] as const;
export type ActorType = (typeof ACTOR_TYPES)[number];

/** The kinds of subject an event is about. The set may grow in a minor release. */
export const SUBJECT_TYPES = ['user', 'client', 'api_key'] as const;
export type SubjectType = (typeof SUBJECT_TYPES)[number];

/**
 * The metadata key that marks an enum as open. The JSON Schema export turns
 * such an enum into `x-extensible-enum`, which the stable-surface check lets
 * grow; a plain `enum` may not grow, because a consumer may not handle the new
 * value. The key itself never reaches the published schema.
 */
export const EXTENSIBLE_ENUM_META = 'qauthExtensibleEnum';

/**
 * An enum whose value set may grow in a minor release. QAuth emits only the
 * listed values; a consumer must accept others.
 */
export function extensibleEnum<const T extends readonly [string, ...string[]]>(values: T) {
  return z.enum(values).meta({ [EXTENSIBLE_ENUM_META]: true });
}

/** A public OAuth `client_id`, as tokens and the audit log carry it. */
export const clientIdSchema = z.string().min(1).max(255);

/** The actor: who or what caused the event. */
export const actorSchema = z
  .strictObject({
    type: extensibleEnum(ACTOR_TYPES).describe(
      '`user`: a person, signed in. `client`: an OAuth client acting for itself or, with `delegationChain`, as an agent for the subject. `system`: QAuth itself, such as a scheduled job. `operator_cli`: an operator on the server host, through a QAuth command-line tool.'
    ),
    id: z
      .string()
      .min(1)
      .max(255)
      .optional()
      .describe(
        "The actor's identifier: a user id, a client's `client_id`, or the operating-system user for `operator_cli`. Absent for `system`."
      ),
    delegationChain: z
      .array(clientIdSchema)
      .min(1)
      .max(16)
      .optional()
      .describe(
        'The RFC 8693 `act` chain of a delegated request, as `client_id` values: the acting agent first, then each earlier actor. Absent when nothing was delegated.'
      ),
  })
  .describe('Who or what caused the event.');

/** The subject: what the event is about. A plain id, never a foreign key. */
export const subjectSchema = z
  .strictObject({
    type: extensibleEnum(SUBJECT_TYPES).describe('What kind of thing the subject is.'),
    id: z
      .string()
      .min(1)
      .max(255)
      .describe(
        "The subject's identifier: a user id, a client's `client_id` or an API key id. It stays valid after the subject is deleted."
      ),
  })
  .describe('What the event is about.');

/** The OAuth client a request came through. */
export const clientSchema = z
  .strictObject({
    id: clientIdSchema.describe("The client's `client_id`."),
  })
  .describe('The OAuth client the request came through.');

/** The longest `traceId` and `userAgent` an event carries; {@link eventRequest} cuts to them. */
export const TRACE_ID_MAX = 128;
export const USER_AGENT_MAX = 1024;

/**
 * Whether an address matches the patterns the published schema carries. Zod's
 * own IPv6 check also accepts forms those patterns refuse, such as the
 * IPv4-mapped `::ffff:203.0.113.5`, and an event must validate against the
 * schema QAuth publishes.
 */
const matchesPublishedIpPattern = (value: string) =>
  z.regexes.ipv4.test(value) || z.regexes.ipv6.test(value);

/**
 * The HTTP request that caused the event. `ip` and `userAgent` are personal
 * data: they are present on events that a person's own request caused, where a
 * security log needs them (ADR-017 §11), and only there.
 */
export const requestSchema = z
  .strictObject({
    traceId: z
      .string()
      .min(1)
      .max(TRACE_ID_MAX)
      .optional()
      .describe(
        'The id under which QAuth logged the request: the `trace_id` of a problem document from the same request.'
      ),
    ip: z
      .union([z.ipv4(), z.ipv6()])
      .refine(matchesPublishedIpPattern, 'not an address in the published form')
      .optional()
      .describe(
        "The end user's IP address, as QAuth derived it from the request. An IPv4-mapped IPv6 address is written in its IPv4 form."
      ),
    userAgent: z
      .string()
      .max(USER_AGENT_MAX)
      .optional()
      .describe('The `User-Agent` header, cut to 1024 characters.'),
  })
  .describe('The HTTP request that caused the event.');

export type EventRequest = z.infer<typeof requestSchema>;

/** Cut a string to `max` UTF-16 units without splitting a surrogate pair. */
function cut(value: string, max: number): string {
  if (value.length <= max) return value;
  const end = /[\uD800-\uDBFF]/.test(value.charAt(max - 1)) ? max - 1 : max;
  return value.slice(0, end);
}

/**
 * The `request` member from what a request handler has. The client controls
 * all three values, so this sizes them rather than let an over-long header or
 * a malformed forwarded address make the event fail its schema and drop it:
 * `traceId` and `userAgent` are cut to their limits, an IPv4-mapped address
 * is written in its IPv4 form, and an address in any other unpublished form is
 * left out.
 *
 * @returns the member, or `undefined` when none of the three is present
 */
export function eventRequest(input: {
  readonly traceId?: string | null;
  readonly ip?: string | null;
  readonly userAgent?: string | null;
}): EventRequest | undefined {
  const request: { traceId?: string; ip?: string; userAgent?: string } = {};
  if (input.traceId) request.traceId = cut(input.traceId, TRACE_ID_MAX);
  if (input.ip) {
    const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(input.ip);
    const ip = mapped ? mapped[1] : input.ip;
    if (requestSchema.shape.ip.safeParse(ip).success) request.ip = ip;
  }
  if (input.userAgent) request.userAgent = cut(input.userAgent, USER_AGENT_MAX);
  return Object.keys(request).length > 0 ? request : undefined;
}

/** The descriptions of the members a per-type schema fixes. */
export const TYPE_DESCRIPTION =
  'The event type, `urn:qauth:event:<name>:v<N>`, or `:v<N>-rc.<M>` for a release candidate. The registry lists every type.';
export const CATEGORY_DESCRIPTION =
  "`user`: an end user's own activity. `admin`: an administrator's change. Fixed by the type.";
export const DATA_DESCRIPTION = "The type's own payload. Its schema is the type's.";

/**
 * The envelope's members, in the order they are documented and published.
 * `type`, `category` and `data` are the three a type fixes.
 */
function envelopeMembers<
  Type extends z.ZodType,
  Category extends z.ZodType,
  Data extends z.ZodType,
>(type: Type, category: Category, data: Data) {
  return {
    id: z
      .uuidv7()
      .describe(
        'The event id, a UUIDv7. One event keeps one id on every route and every retry, so a receiver drops duplicates by it. It is the `webhook-id` of a webhook and the source of an SSF `jti`.'
      ),
    type: type.describe(TYPE_DESCRIPTION),
    time: z.iso
      .datetime()
      .describe('When the event happened, as an RFC 3339 time in UTC. Not when it was delivered.'),
    realm: z.uuid().describe('The id of the realm the event happened in.'),
    category: category.describe(CATEGORY_DESCRIPTION),
    actor: actorSchema.optional(),
    subject: subjectSchema.optional(),
    client: clientSchema.optional(),
    request: requestSchema.optional(),
    data: data.describe(DATA_DESCRIPTION),
  };
}

/** The envelope of an event of any type, with `data` left open. */
export const envelopeSchema = z
  .strictObject(
    envelopeMembers(
      z.string().regex(EVENT_TYPE_PATTERN),
      z.enum(EVENT_CATEGORIES),
      z.record(z.string(), z.unknown())
    )
  )
  .describe('A QAuth event, of any type.');

export type EventEnvelope = z.infer<typeof envelopeSchema>;

/**
 * The envelope of one type's events: `type` and `category` fixed, `data` the
 * type's own schema.
 */
export function typedEnvelopeSchema<
  const Type extends string,
  const Category extends EventCategory,
  Data extends z.ZodType,
>(type: Type, category: Category, data: Data, description: string) {
  return z
    .strictObject(envelopeMembers(z.literal(type), z.literal(category), data))
    .describe(description);
}
