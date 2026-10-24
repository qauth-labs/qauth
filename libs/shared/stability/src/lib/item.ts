/**
 * The experimental-feature registry's vocabulary (ADR-018 §4 and §5).
 *
 * An experimental item ships but stays outside the stability promise. It sits
 * behind a switch that is off by default, the server warns at boot when the
 * switch is on, and it may change in a minor release without a deprecation
 * window. It becomes stable once the four promotion conditions of ADR-018 §5
 * hold, each with evidence.
 *
 * Pure types and constants, with no I/O.
 */

/**
 * How far the spec an item implements has come.
 *
 * - `draft`: an Internet-Draft, or a specification that is not final yet.
 * - `rfc`: published as an RFC.
 * - `final`: a Final specification, such as an OpenID Foundation Final.
 */
export type SpecStatus = 'draft' | 'rfc' | 'final';

/** Every spec status, in order. */
export const SPEC_STATUSES: readonly SpecStatus[] = ['draft', 'rfc', 'final'];

/** The spec an item implements. */
export interface ImplementedSpec {
  /** Its title, as its publisher writes it. */
  readonly name: string;
  /**
   * Where it is published, over `https`. For a draft, the page that follows
   * its revisions rather than one revision, so the link does not go stale.
   */
  readonly url: string;
  readonly status: SpecStatus;
}

/**
 * The four conditions of ADR-018 §5. An item becomes stable in a minor release
 * once all four hold.
 */
export const PROMOTION_CONDITIONS = [
  {
    id: 'spec-final',
    text: 'The spec it implements is an RFC or a Final specification.',
  },
  {
    id: 'external-beta',
    text: 'It has seen external use in a beta.',
  },
  {
    id: 'external-audit',
    text: 'The external audit covered it.',
  },
  {
    id: 'conformance-tests',
    text: 'Conformance tests exist for it.',
  },
] as const;

/** The id of one promotion condition. */
export type PromotionConditionId = (typeof PROMOTION_CONDITIONS)[number]['id'];

/**
 * What shows that one promotion condition holds.
 *
 * Each piece of evidence is one of:
 *
 * - an RFC number, `RFC 9449`;
 * - an issue or pull request of this repository, `#476`;
 * - a link, `https://…`;
 * - a path from the repository root that must exist, such as a test file or a
 *   section of an audit report: `docs/security/audit.md#wallet-sign-in`.
 *
 * See {@link evidenceKind}.
 */
export interface ConditionEvidence {
  /** Empty while the condition does not hold. */
  readonly evidence: readonly string[];
  /** One or two sentences: what exists so far, or what is still missing. */
  readonly note?: string;
}

/**
 * Where an item runs, which decides what its switch is.
 *
 * - `server`: the auth server. The switch is a configuration key.
 * - `sdk`: an SDK package. The switch is the import path an app imports.
 */
export type ItemSurface = 'server' | 'sdk';

/** One experimental item: the registry's entry for it. */
export interface ExperimentalItem {
  /**
   * Lower-case words joined by `-`, or `.` inside a version (`oid4vp-1.0-base`).
   * The boot warning names it, and the docs page has a section of that name.
   */
  readonly id: string;
  /** What it is, in a few words, as the docs page heads it. */
  readonly title: string;
  /** One or two sentences for the docs page: what it does and why it is experimental. */
  readonly description: string;
  /** The decision record that decided it, from the repository root: `docs/adr/017-first-party-login.md`. */
  readonly adr: string;
  readonly surface: ItemSurface;
  /**
   * The switch that turns the item on: a configuration key for a `server`
   * item, an import path for an `sdk` item. `null` while no record names it.
   * A built item always has one, added in the same pull request as the item.
   */
  readonly switchKey: string | null;
  /**
   * The value of {@link switchKey} that turns the item on: `true` for a
   * boolean switch, or the experimental value of a key whose other values are
   * stable. `null` for an import path.
   */
  readonly switchValue: string | null;
  /** Other settings the switch needs before it does anything, as `KEY=value`. */
  readonly requires: readonly string[];
  readonly spec: ImplementedSpec;
  /** It exists in code today. An item can be listed before it is built. */
  readonly built: boolean;
  /** It has become stable. Every condition then has evidence. */
  readonly stable: boolean;
  readonly conditions: Readonly<Record<PromotionConditionId, ConditionEvidence>>;
}

/** The form of an item id. Starlight's heading anchor of the id is the docs link's fragment. */
export const ITEM_ID_PATTERN = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;

/** The form of the `adr` path. */
export const ADR_PATH_PATTERN = /^docs\/adr\/\d{3}-[a-z0-9]+(?:-[a-z0-9]+)*\.md$/;

/** The form of a server switch: an environment variable name. */
export const CONFIG_KEY_PATTERN = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;

/** The form of an SDK switch: an import path of a QAuth package. */
export const IMPORT_PATH_PATTERN = /^@qauth-labs\/[a-z0-9-]+(?:\/[a-z0-9-]+)*$/;

/** The form of a `requires` entry: `KEY=value`. */
export const REQUIRED_SETTING_PATTERN = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*=\S+$/;
