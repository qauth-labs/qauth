/**
 * The configuration key registry's vocabulary (ADR-018 §5, ADR-019 Decision 10).
 *
 * Every environment key QAuth reads has one {@link ConfigKey} entry. The entry
 * is the contract: its tier says what may change and when, its role says who
 * owns the value, and the configuration page on the docs site is generated
 * from it.
 */

/**
 * How far a key is promised to stay as it is (ADR-018 §5).
 *
 * - `stable`: follows the deprecation policy. A rename keeps the old name
 *   working, with a warning, for at least 12 months, and the old name goes
 *   only in a new major release.
 * - `advanced`: may change in a minor release.
 * - `experimental`: may change at any time. The server warns at boot when one
 *   is set.
 */
export type KeyTier = 'stable' | 'advanced' | 'experimental';

/** The tiers in the order the configuration page lists them. */
export const KEY_TIERS: readonly KeyTier[] = ['stable', 'advanced', 'experimental'];

/**
 * Who owns a key's value (ADR-019 Decision 10).
 *
 * - `deployment`: the environment owns it, for the whole deployment.
 * - `realm-seed`: a realm policy. The environment only seeds a new realm's
 *   default; the realm row owns the value from then on. Until realm policies
 *   live on the realm row, the server reads these keys process-wide.
 */
export type KeyRole = 'deployment' | 'realm-seed';

/**
 * The area that owns a key: the part of QAuth whose pull requests add, tier
 * and document it.
 */
export type KeyOwner =
  | 'server'
  | 'observability'
  | 'storage'
  | 'realms'
  | 'tokens'
  | 'signing'
  | 'key-custody'
  | 'accounts'
  | 'sessions'
  | 'mail'
  | 'client-registration'
  | 'id-jag'
  | 'wallet-federation'
  | 'rate-limits'
  | 'developer-portal'
  | 'testing';

/**
 * What a key is when it is not set.
 *
 * - a string: the literal value the schema falls back to, written as it would
 *   be in the environment (`''` for an empty list).
 * - `null`: no default. Unset leaves the setting off or absent.
 * - `{ required: true }`: no default, and the process refuses to start
 *   without it.
 * - `{ computed }`: the default depends on other keys, in words. A secret's
 *   default is always written this way, so its value is never printed.
 */
export type KeyDefault =
  string | null | { readonly required: true } | { readonly computed: string };

/** A previous name of a key that still works, with a warning. */
export interface KeyAlias {
  /** The old name. */
  readonly name: string;
  /** The release that deprecated the old name. */
  readonly deprecatedSince: string;
}

/** One configuration key: the registry's entry for it. */
export interface ConfigKey {
  /** The environment variable name. */
  readonly name: string;
  readonly tier: KeyTier;
  readonly role: KeyRole;
  /**
   * The realm policy path a `realm-seed` key seeds, such as
   * `tokens.accessTokenLifespanSeconds`. `undefined` for a `deployment` key.
   */
  readonly seeds: string | undefined;
  /**
   * The value is a secret. The configuration page and the boot log never show
   * it, not even as a default.
   */
  readonly secret: boolean;
  readonly default: KeyDefault;
  /** The first release that reads the key, such as `0.1.0`. */
  readonly since: string;
  /** Previous names that still work. See `applyKeyAliases`. */
  readonly aliases: readonly KeyAlias[];
  /** One sentence for the configuration page. */
  readonly docs: string;
  readonly owner: KeyOwner;
  /**
   * Values of this key that are experimental while the key itself is not. The
   * server warns at boot when the key is set to one of them.
   */
  readonly experimentalValues: readonly string[];
  /**
   * The key exists for test and development stacks only, such as a switch
   * that turns off an SSRF guard so a test can reach a localhost server.
   */
  readonly developmentOnly: boolean;
}

/**
 * An entry as written in the registry files. The fields most keys leave at
 * their default are optional here and filled in by {@link defineKeys}.
 */
export type ConfigKeyInput = Omit<
  ConfigKey,
  'seeds' | 'secret' | 'aliases' | 'experimentalValues' | 'developmentOnly'
> &
  Partial<
    Pick<ConfigKey, 'seeds' | 'secret' | 'aliases' | 'experimentalValues' | 'developmentOnly'>
  >;

/** Fill in the optional fields of registry entries. */
export function defineKeys(inputs: readonly ConfigKeyInput[]): readonly ConfigKey[] {
  return inputs.map((input) =>
    Object.freeze({
      ...input,
      seeds: input.seeds,
      secret: input.secret ?? false,
      aliases: Object.freeze([...(input.aliases ?? [])]),
      experimentalValues: Object.freeze([...(input.experimentalValues ?? [])]),
      developmentOnly: input.developmentOnly ?? false,
    })
  );
}

/**
 * One configuration warning for the boot log. `main.ts` logs each one once,
 * after the logger exists.
 */
export interface ConfigWarning {
  /** The variable the warning is about. */
  readonly variable: string;
  /** What the operator should know or do, in one line. */
  readonly message: string;
}

/** A deprecated configuration name that this deployment still sets. */
export interface EnvDeprecationWarning extends ConfigWarning {
  /** The variable that replaces it. */
  readonly replacement: string;
}
