import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * THE STEP'S CSRF VALUE (#616, ADR-019 Decision 6).
 *
 * Every answer to an interaction, and its cancel, carries the CSRF value the
 * step read returned. The proxy strips QAuth's cookies from `/ui/*`, so the
 * ceremony app can neither read the flow cookie nor mint the value: it embeds
 * the one it read with the step.
 *
 * The value is derived, never stored: HMAC-SHA-256 under a key of the
 * interaction's own (32 random bytes made with the record, kept in it and
 * never sent), over the record's revision and its current step. So it is
 *
 * - bound to the interaction: another interaction's key gives another value;
 * - bound to the step: each written state has a new revision, so the value of
 *   one step view is refused at the next, the same step after a refused
 *   answer included, which gets a new value;
 * - valid for one answer: the answer that is processed moves the revision on,
 *   and with it the value. An answer that is not processed (refused before the
 *   engine, throttled, or failed) writes nothing, so the page may send it
 *   again;
 * - the same on every read of one step view, so a read changes nothing and a
 *   page reloaded keeps a value that works.
 *
 * It travels in a JSON body or a form field, never in a URL (the contract has
 * no such parameter).
 */

/** CSRF key bytes; 32 bytes are 43 base64url characters, as the value is. */
const CSRF_KEY_BYTES = 32;

/** What separates the parts of the HMAC input: never in a step name or a number. */
const SEPARATOR = '\u0000';

/** The HMAC input's label, so the key derives nothing but CSRF values. */
const LABEL = 'urn:qauth:interaction:csrf:v1-rc.0';

/** Exactly what a CSRF value is: 32 bytes, base64url. */
const CSRF_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** A new CSRF key for a new interaction record. */
export function mintCsrfKey(): string {
  return randomBytes(CSRF_KEY_BYTES).toString('base64url');
}

/** What a CSRF value is derived from: the record's key, revision and current step. */
export interface CsrfSource {
  readonly csrfKey: string;
  readonly revision: number;
  readonly step: { readonly name: string };
}

/** The CSRF value of a record's current step view. */
export function interactionCsrf(record: CsrfSource): string {
  return createHmac('sha256', Buffer.from(record.csrfKey, 'base64url'))
    .update([LABEL, String(record.revision), record.step.name].join(SEPARATOR))
    .digest('base64url');
}

/**
 * Whether `presented` is the CSRF value of the record's current step view,
 * compared timing-safely. Anything that is not a well-formed value is not.
 */
export function matchesInteractionCsrf(record: CsrfSource, presented: unknown): boolean {
  if (typeof presented !== 'string' || !CSRF_PATTERN.test(presented)) return false;
  const expected = Buffer.from(interactionCsrf(record), 'base64url');
  const actual = Buffer.from(presented, 'base64url');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
