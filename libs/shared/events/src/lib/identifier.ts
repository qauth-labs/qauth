/**
 * Event type identifiers (ADR-018 §5): every QAuth-defined identifier carries
 * a version, so a standard identifier can later sit beside it without breaking
 * 1.x. An event type is `urn:qauth:event:<name>:v<N>`, or
 * `urn:qauth:event:<name>:v<N>-rc.<M>` while it is a release candidate.
 *
 * - `<name>` is the short name: lower-case `snake_case` segments joined by
 *   full stops, resource first (`user.signed_in`, `client.secret_rotated`).
 *   It is the full-stop delimited, hierarchical type that Standard Webhooks
 *   recommends for a webhook payload.
 * - `<N>` is the major version of the type's `data` schema, from 1, with no
 *   leading zero. A breaking change to `data` makes a new type with the next
 *   version (see the versioning rules in the README).
 * - `-rc.<M>` marks a release candidate, in the form of QAuth's own release
 *   tags, with `<M>` from 0. Until QAuth 1.0.0 every type is one and nothing
 *   about it is promised, so a breaking change raises `<M>`. The release that
 *   ships 1.0.0 drops the suffix, and `:v1` is then under the promise.
 */

/** The prefix every event type identifier starts with. */
export const EVENT_TYPE_PREFIX = 'urn:qauth:event:';

/** The short name: two or more `snake_case` segments, joined by full stops. */
export const EVENT_NAME_PATTERN = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/;

/** A whole event type identifier, `urn:qauth:event:<name>:v<N>` with an optional `-rc.<M>`. */
export const EVENT_TYPE_PATTERN =
  /^urn:qauth:event:([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+):v([1-9][0-9]*)(?:-rc\.(0|[1-9][0-9]*))?$/;

/** An event type identifier, as the type system sees it. */
export type EventTypeId =
  | `urn:qauth:event:${string}:v${number}`
  | `urn:qauth:event:${string}:v${number}-rc.${number}`;

/** The version part of an identifier: a major version and, for a candidate, its number. */
export interface EventVersion {
  /** The major version of the type's `data` schema: 1 for `:v1` and `:v1-rc.0`. */
  readonly version: number;
  /** The release-candidate number: 0 for `:v1-rc.0`; absent for a released version. */
  readonly rc?: number;
}

/** The parts of an event type identifier. */
export interface ParsedEventType extends EventVersion {
  /** The short name, the middle part: `user.signed_in`. */
  readonly name: string;
}

/**
 * Split an event type identifier into its short name and version.
 *
 * @returns the parts, or `null` when `type` is not a well-formed identifier
 */
export function parseEventType(type: string): ParsedEventType | null {
  const match = EVENT_TYPE_PATTERN.exec(type);
  if (!match) return null;
  const version = Number(match[2]);
  return match[3] === undefined
    ? { name: match[1], version }
    : { name: match[1], version, rc: Number(match[3]) };
}

/** The version as an identifier ends with it: `v1`, or `v1-rc.0` for a candidate. */
export function eventVersionLabel({ version, rc }: EventVersion): string {
  return rc === undefined ? `v${version}` : `v${version}-rc.${rc}`;
}

/**
 * Order two versions: by major version, and within one major version each
 * candidate before the next and every candidate before the release.
 *
 * @returns a negative number when `a` comes first, a positive one when `b` does, 0 when equal
 */
export function compareEventVersions(a: EventVersion, b: EventVersion): number {
  if (a.version !== b.version) return a.version - b.version;
  const rcA = a.rc ?? Number.POSITIVE_INFINITY;
  const rcB = b.rc ?? Number.POSITIVE_INFINITY;
  return rcA === rcB ? 0 : rcA < rcB ? -1 : 1;
}

/**
 * Build an event type identifier from a short name, a version and, for a
 * release candidate, its number.
 *
 * @throws {Error} when the name, the version or the candidate number is not well formed
 */
export function eventTypeId(name: string, version: number, rc?: number): EventTypeId {
  if (!EVENT_NAME_PATTERN.test(name)) {
    throw new Error(
      `event name "${name}" must be snake_case segments joined by full stops, such as "user.signed_in"`
    );
  }
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new Error(`event version must be a positive integer, got ${version}`);
  }
  if (rc !== undefined && (!Number.isSafeInteger(rc) || rc < 0)) {
    throw new Error(`event release-candidate number must be a non-negative integer, got ${rc}`);
  }
  return `${EVENT_TYPE_PREFIX}${name}:${eventVersionLabel({ version, rc })}` as EventTypeId;
}
