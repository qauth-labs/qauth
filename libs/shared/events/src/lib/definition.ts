import type { z } from 'zod';

import type { EventCategory, SubjectType } from './envelope';
import { eventTypeId } from './identifier';

/** The identifier a name, a version and a candidate number make, as a literal type. */
export type EventTypeIdOf<
  Name extends string,
  Version extends number,
  Rc extends number | undefined,
> = Rc extends number
  ? `urn:qauth:event:${Name}:v${Version}-rc.${Rc}`
  : `urn:qauth:event:${Name}:v${Version}`;

/**
 * How much attention an event asks for. `info`: normal operation. `warning`:
 * a refusal or a failure someone may need to look at. `critical`: a security
 * incident, or an emergency action an operator took.
 */
export const EVENT_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type EventSeverity = (typeof EVENT_SEVERITIES)[number];

/** A release tag, such as `v0.2.0`. */
export type ReleaseTag = `v${number}.${number}.${number}`;
export const RELEASE_TAG_PATTERN = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

/** A JSON value, as a Security Event Token carries one. */
export type SsfJsonValue =
  | string
  | number
  | boolean
  | null
  | readonly SsfJsonValue[]
  | { readonly [member: string]: SsfJsonValue };

/**
 * Where one member of a mapped SSF event comes from: a fixed value, or a
 * member of the event's `data`, taken as it is or through `map` (keyed by the
 * data value as a string, so `true` and `false` for a flag). A `data` member
 * the event leaves out, or a value `map` does not list, leaves the SSF member
 * out.
 */
export type SsfMemberSource =
  | { readonly value: SsfJsonValue }
  | { readonly data: string; readonly map?: Readonly<Record<string, SsfJsonValue>> };

/**
 * What names a mapped event's subject, the SET's `sub_id` (RFC 9493, SSF 1.0
 * §3), and so which streams receive it:
 *
 * - `subject`: the envelope's `subject`. A user is `iss_sub` with the realm's
 *   issuer, a client `uri` or `opaque` by its `client_id` (#410). Streams that
 *   added that subject receive it.
 * - `client`: the envelope's `client`, as a client subject. Streams that added
 *   that client receive it.
 * - `key`: the key `data.keyId` names, as an `opaque` identifier. Every stream
 *   of the realm that requested the event receives it, whatever subjects it
 *   added: a key concerns everyone who verifies the realm's tokens.
 */
export type SsfSubjectSource = 'subject' | 'client' | 'key';

/** Who invoked the event, as CAEP 1.0 §2 names it in `initiating_entity`. */
export const INITIATING_ENTITIES = ['admin', 'user', 'policy', 'system'] as const;
export type InitiatingEntity = (typeof INITIATING_ENTITIES)[number];

/**
 * How a type reaches Shared Signals Framework streams (#540): the SSF event
 * it is sent as, what names its subject, and the event's members.
 *
 * Every SET of a mapped type carries `event_timestamp`, the event's `time` in
 * seconds, and `initiating_entity` (CAEP 1.0 §2): `initiatingEntity` when the
 * mapping fixes it, otherwise read from the actor (a user is `user`, or
 * `admin` on an admin event; an operator on the server host is `admin`;
 * QAuth itself is `system`; a client acting for itself names none).
 */
export interface SsfEventMapping {
  /**
   * The SSF event type URI: a CAEP 1.0 or RISC 1.0 event, or a QAuth-defined
   * one, `urn:qauth:secevent:<name>:v<N>-rc.<M>` until QAuth 1.0.0.
   */
  readonly event: string;
  /** What names the subject; `subject` when absent. */
  readonly subject?: SsfSubjectSource;
  /**
   * Send it only to the stream of the event's own client (the envelope's
   * `client`), never to another receiver that added the same subject: the
   * event tells of the user's dealings with that one client.
   */
  readonly clientOnly?: true;
  /** `initiating_entity`, when it does not follow from the actor. */
  readonly initiatingEntity?: InitiatingEntity;
  /** The event's own members, such as `credential_type` and `change_type`. */
  readonly members?: Readonly<Record<string, SsfMemberSource>>;
}

/**
 * The slot for a type's Shared Signals Framework mapping (#540): the SSF
 * event it is sent as, or `'none'` for a security type with no SSF
 * counterpart. A security type must fill it, and only a security type may.
 */
export type SsfMapping = 'none' | SsfEventMapping;

/** A registered event type: its identifier, its payload schema and its facts. */
export interface EventTypeDefinition<
  Name extends string = string,
  Version extends number = number,
  Data extends z.ZodObject = z.ZodObject,
  Rc extends number | undefined = number | undefined,
> {
  /** `urn:qauth:event:<name>:v<N>`, or `urn:qauth:event:<name>:v<N>-rc.<M>`. */
  readonly type: EventTypeIdOf<Name, Version, Rc>;
  /** The short name, the middle part of `type`. */
  readonly name: Name;
  /** The major version of `data`, the `N` of `:vN`. */
  readonly version: Version;
  /**
   * The release-candidate number, the `M` of `:vN-rc.M`. Every type has one
   * until QAuth 1.0.0, and a breaking change before then raises it.
   */
  readonly rc?: Rc;
  /** One or two sentences: when QAuth emits it. */
  readonly description: string;
  readonly category: EventCategory;
  readonly severity: EventSeverity;
  /** The release the type first appeared in. */
  readonly since: ReleaseTag;
  /** The schema of the event's `data`. */
  readonly data: Data;
  /** What the envelope's `subject` is, when the event has one. */
  readonly subject?: SubjectType;
  /**
   * Fields of `data` this type may carry although they name a person or an
   * address (payload rule 1). Empty for every type today.
   */
  readonly personalData?: readonly string[];
  /**
   * The member of `data` that holds an admin diff (`adminDiffSchema`): a
   * changed resource's fields, before and after. The payload rules read that
   * member's values but not its field names, which are the resource's own;
   * the masking rule (`scanAdminDiff`) holds there instead. Only an `admin`
   * type has one.
   */
  readonly diff?: string;
  /**
   * Whether the type records a security change: a session, a grant, a token,
   * a credential, a key or an account that a receiver may have to act on. A
   * security type must declare `ssf`, a mapping or `'none'` (#540), so no area
   * adds one and forgets Shared Signals.
   */
  readonly security?: true;
  /** The SSF mapping slot; see {@link SsfMapping}. */
  readonly ssf?: SsfMapping;
  /**
   * Why the type maps as it does, when the mapping alone does not say, such
   * as why a security type has no SSF event. Shown on the SSF events page.
   */
  readonly ssfNote?: string;
  /**
   * Set when a breaking change replaced the type with a later version. Both
   * are emitted until the deprecation window ends (ADR-018 §5).
   */
  readonly deprecated?: { readonly since: ReleaseTag; readonly replacedBy: string };
}

/** What a registry entry is written from: everything but the derived `type`. */
export type EventTypeInput<
  Name extends string,
  Version extends number,
  Data extends z.ZodObject,
  Rc extends number | undefined = undefined,
> = Omit<EventTypeDefinition<Name, Version, Data, Rc>, 'type'>;

/**
 * Define an event type. The identifier is built from the name, the version and
 * the candidate number, so it always has the registry's shape.
 *
 * @throws {Error} when the name, the version or the candidate number is not well formed
 */
export function defineEventType<
  const Name extends string,
  const Version extends number,
  Data extends z.ZodObject,
  const Rc extends number | undefined = undefined,
>(input: EventTypeInput<Name, Version, Data, Rc>): EventTypeDefinition<Name, Version, Data, Rc> {
  const type = eventTypeId(input.name, input.version, input.rc) as EventTypeIdOf<Name, Version, Rc>;
  return Object.freeze({ type, ...input });
}
