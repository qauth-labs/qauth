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

/**
 * The slot for a type's Shared Signals Framework mapping. EVT-11 (#540) fills
 * it and gives the mapping its shape; until then no type has one. `'none'`
 * will record that a type has no SSF counterpart.
 */
export type SsfMapping = 'none' | { readonly event: string };

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
  /** The SSF mapping slot; see {@link SsfMapping}. */
  readonly ssf?: SsfMapping;
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
