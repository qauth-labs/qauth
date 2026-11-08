/**
 * The settings metadata of the admin console (ADR-020 §5 criteria 1 and 2,
 * issue #589): for each setting a screen renders, the one-sentence
 * explanation, the docs link, the default, which way is stricter and what a
 * change of it needs. Generated from the schema it describes, never edited by
 * hand; the console imports it, since it cannot import a server library.
 */

/** Which way a setting's values are stricter, as the realm policy schema annotates it. */
export type SettingDirection =
  | 'lower-is-stricter'
  | 'higher-is-stricter'
  | 'true-is-stricter'
  | 'false-is-stricter'
  | 'ordered'
  | 'subset-is-stricter'
  | 'superset-is-stricter'
  | 'opaque';

/** When a change of a setting is a security operation (ADR-019 Decision 7). */
export type SettingSecurityWhen = 'never' | 'loosening' | 'any-change';

/** The scope class a change needs: `security` needs `qauth:admin:security` and an approval. */
export type SettingChangeClass = 'write' | 'security';

/** One realm policy setting. */
export interface RealmPolicySetting {
  /** The dotted path in the policies, such as `password.minScore`. */
  readonly path: string;
  /** What the setting does, in one sentence. */
  readonly summary: string;
  /** Where docs.qauth.dev explains it. */
  readonly docs: string;
  /**
   * The value of a realm whose environment did not seed it: what a screen
   * marks a value as differing from. `null` for a secret, which has none.
   */
  readonly default: unknown;
  /** A secret is write-only: a screen shows only whether it is set. */
  readonly secret: boolean;
  readonly direction: SettingDirection;
  /** For an `ordered` setting, its values from the loosest to the strictest. */
  readonly order?: readonly string[];
  readonly securityWhen: SettingSecurityWhen;
  /** What a change that tightens, loosens or does neither needs. */
  readonly class: {
    readonly tightening: SettingChangeClass;
    readonly loosening: SettingChangeClass;
    readonly neutral: SettingChangeClass;
  };
  /** The effects of a security change of it (`SECURITY_EFFECTS`); empty when it is never one. */
  readonly effects: readonly string[];
  /** The value describes the realm's environment, which a sandbox promotion leaves out. */
  readonly environmentBound: boolean;
}

/** The metadata file of the realm policy settings. */
export interface RealmPolicySettingsFile {
  /** The realm policy schema version it was generated from (`policySchemaVersion`). */
  readonly policySchemaVersion: string;
  readonly description: string;
  /** Every setting, in the schema's order. */
  readonly settings: readonly RealmPolicySetting[];
}
