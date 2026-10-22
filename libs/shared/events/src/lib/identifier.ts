/**
 * Event type identifiers (ADR-018 §5): every QAuth-defined identifier carries
 * a version, so a standard identifier can later sit beside it without breaking
 * 1.x. An event type is `urn:qauth:event:<name>:v<N>`.
 *
 * - `<name>` is the short name: lower-case `snake_case` segments joined by
 *   full stops, resource first (`user.signed_in`, `client.secret_rotated`).
 *   It is the full-stop delimited, hierarchical type that Standard Webhooks
 *   recommends for a webhook payload.
 * - `<N>` is the major version of the type's `data` schema, from 1, with no
 *   leading zero. A breaking change to `data` makes a new type with the next
 *   version (see the versioning rules in the README).
 */

/** The prefix every event type identifier starts with. */
export const EVENT_TYPE_PREFIX = 'urn:qauth:event:';

/** The short name: two or more `snake_case` segments, joined by full stops. */
export const EVENT_NAME_PATTERN = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/;

/** A whole event type identifier, `urn:qauth:event:<name>:v<N>`. */
export const EVENT_TYPE_PATTERN =
  /^urn:qauth:event:([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+):v([1-9][0-9]*)$/;

/** An event type identifier, as the type system sees it. */
export type EventTypeId = `urn:qauth:event:${string}:v${number}`;

/** The two parts of an event type identifier. */
export interface ParsedEventType {
  /** The short name, the middle part: `user.signed_in`. */
  readonly name: string;
  /** The major version of the type's `data` schema: 1 for `:v1`. */
  readonly version: number;
}

/**
 * Split an event type identifier into its short name and version.
 *
 * @returns the parts, or `null` when `type` is not a well-formed identifier
 */
export function parseEventType(type: string): ParsedEventType | null {
  const match = EVENT_TYPE_PATTERN.exec(type);
  if (!match) return null;
  return { name: match[1], version: Number(match[2]) };
}

/**
 * Build an event type identifier from a short name and a version.
 *
 * @throws {Error} when the name or the version is not well formed
 */
export function eventTypeId(name: string, version: number): EventTypeId {
  if (!EVENT_NAME_PATTERN.test(name)) {
    throw new Error(
      `event name "${name}" must be snake_case segments joined by full stops, such as "user.signed_in"`
    );
  }
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new Error(`event version must be a positive integer, got ${version}`);
  }
  return `${EVENT_TYPE_PREFIX}${name}:v${version}` as EventTypeId;
}
