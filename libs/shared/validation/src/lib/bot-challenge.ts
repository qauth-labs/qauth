/**
 * The operator's hosted bot-challenge provider (#643; ADR-017 Decision 7):
 * the forms its settings take, checked the same way at boot and where the
 * provider is built.
 */

/** The name QAuth reserves for its built-in proof of work. */
export const RESERVED_BOT_CHALLENGE_PROVIDER = 'pow';

/**
 * The name an operator gives a hosted provider, as the `captcha` step sends
 * it: a lower-case letter, then up to 31 lower-case letters, digits, `_` or
 * `-`. Never {@link RESERVED_BOT_CHALLENGE_PROVIDER}.
 */
export const BOT_CHALLENGE_PROVIDER_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;

/** A hosted provider's public site key, as the `captcha` step sends it. */
export const BOT_CHALLENGE_SITE_KEY_PATTERN = /^[A-Za-z0-9._-]{1,256}$/;

/** Why `value` is not a hosted provider's name; `undefined` when it is one. */
export function botChallengeProviderNameProblem(value: string): string | undefined {
  if (!BOT_CHALLENGE_PROVIDER_NAME_PATTERN.test(value)) {
    return 'must be a lower-case letter, then up to 31 lower-case letters, digits, _ or -';
  }
  if (value === RESERVED_BOT_CHALLENGE_PROVIDER) {
    return `must not be ${RESERVED_BOT_CHALLENGE_PROVIDER}, the built-in proof of work's`;
  }
  return undefined;
}

/**
 * Why `value` is not a hosted provider's verify URL: an absolute `https` URL
 * with no user name, password, query or fragment. `undefined` when it is one.
 * The message names no value, so a caller may prefix the variable's name.
 */
export function botChallengeVerifyUrlProblem(value: string): string | undefined {
  if (!URL.canParse(value) || new URL(value).protocol !== 'https:') {
    return 'must be an absolute https URL';
  }
  const url = new URL(value);
  if (url.username !== '' || url.password !== '') {
    return 'must not carry a user name or a password';
  }
  // `https://host/?` parses with an empty search, so the raw text is checked.
  if (value.includes('?') || value.includes('#')) {
    return 'must not carry a query or a fragment';
  }
  return undefined;
}
