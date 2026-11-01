import type { PolicyIssue } from './registry';

/**
 * Rules over a whole policy document (#529): what one field's type cannot
 * say, because it depends on another field or on whether a secret is set,
 * such as "the smtp transport needs a host and a password".
 *
 * The policy store runs every rule on every update, on the document the
 * update would store and the secrets it would leave set, and refuses the
 * update when any rule gives an issue. Nothing else runs them: a realm's
 * fill at boot and the realm file's import plan do not.
 */

/** What a rule may ask beside the document. */
export interface PolicyRuleContext {
  /**
   * Whether the secret field at `path` holds a value after the update: set
   * by it, or left set by an earlier one. Never the value.
   *
   * @throws PolicySecretStoreUnavailableError when the update leaves the
   *   secret alone and the store has no secret store to ask
   */
  readonly isSet: (path: string) => boolean;
  /**
   * The parsed document before the update: the realm's policies as they
   * read now. A rule compares it with the document it checks, so it can
   * leave alone what the update does not change, and refuse only what the
   * update brings in.
   */
  readonly previous: Readonly<Record<string, unknown>>;
  /**
   * Whether the secret field at `path` held a value before the update.
   *
   * @throws PolicySecretStoreUnavailableError as {@link isSet} does
   */
  readonly wasSet: (path: string) => boolean;
  /**
   * What the update does to the secret field at `path`: `set` gives it a
   * value, `cleared` removes its value, and `undefined` leaves it alone.
   */
  readonly written: (path: string) => 'set' | 'cleared' | undefined;
}

/**
 * A rule: the issues it finds in `policies`, a parsed policy document with
 * no secret in it, or none. An issue names a path and says what is wrong,
 * never a value.
 */
export type PolicyRule = (
  policies: Readonly<Record<string, unknown>>,
  context: PolicyRuleContext
) => readonly PolicyIssue[];
