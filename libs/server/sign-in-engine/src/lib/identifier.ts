import { emailSchema, normalizeEmail } from '@qauth-labs/shared-validation';

/** The longest identifier, in UTF-8 bytes (ADR-017 Decision 3: `login_hint` is at most 254 bytes). */
export const IDENTIFIER_MAX_BYTES = 254;

/**
 * Check and normalise an identifier as a person gave it: a `login_hint`,
 * from the authorization request or from an answer. Today an identifier is
 * an email address (ADR-002, ADR-017 Decision 3): at most 254 bytes, the
 * full email syntax, then `normalizeEmail`, the one normalisation every input
 * gets. The step grammar's schema counts characters and checks only an `@`;
 * the bytes and the syntax are checked here.
 *
 * @returns the normalised identifier, or `null` when `value` is not one
 */
export function readIdentifier(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (value.length === 0 || Buffer.byteLength(value, 'utf8') > IDENTIFIER_MAX_BYTES) return null;
  if (!emailSchema.safeParse(value).success) return null;
  return normalizeEmail(value);
}
