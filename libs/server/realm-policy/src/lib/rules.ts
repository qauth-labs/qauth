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
   */
  readonly isSet: (path: string) => boolean;
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
