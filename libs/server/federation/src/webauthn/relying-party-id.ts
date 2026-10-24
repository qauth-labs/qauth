import {
  InvalidRealmHostError,
  normaliseRealmHost,
  rpIdCoversHost,
} from '@qauth-labs/shared-validation';
import { getPublicSuffix } from 'tldts';

/**
 * The relying-party ID rules (ADR-019 Decision 2, ADR-017 Decision 14, issues
 * #467 and #553).
 *
 * A passkey is bound to the RP ID it was created under, and only a page whose
 * host is the RP ID or a name under it can use it.
 *
 * - The RP ID is the realm's exact host by default. Only that host can then ask
 *   for the realm's passkeys.
 * - A parent domain of the realm host (`example.com` for `auth.example.com`) is
 *   allowed only when the operator opts in (`allowParentDomainRpId`), and comes
 *   back with a warning the server logs at every boot: every host under the
 *   parent can then ask for assertions of the realm's passkeys, including hosts
 *   QAuth does not run. The parent must cover the host on a label boundary and
 *   must not be a public suffix (the Public Suffix List, through `tldts`).
 * - The RP ID is locked when the realm's first passkey is enrolled
 *   (`realms.webauthn_rp_id_locked_at`). A changed RP ID would orphan every
 *   passkey already enrolled, so a configuration that names another one
 *   refuses to boot, and the database refuses the change.
 */

/** Whether the RP ID is the realm's host or a parent domain of it. */
export type RelyingPartyIdScope = 'realm-host' | 'parent-domain';

/** The RP ID a realm runs its ceremonies under. */
export interface ResolvedRelyingPartyId {
  readonly rpId: string;
  readonly scope: RelyingPartyIdScope;
  /**
   * Set for a parent-domain RP ID, and only then: what the opt-in allows, for
   * the operator. Logged at every boot while the opt-in stands.
   */
  readonly warning: string | undefined;
}

/** What {@link resolveRelyingPartyId} reads. */
export interface RelyingPartyIdSettings {
  /** The realm's primary host, normalised. */
  readonly realmHost: string;
  /** The operator's RP ID, if any. Unset means the realm host. */
  readonly configured?: string;
  /**
   * The operator's explicit opt-in to a parent domain of the realm host.
   * Without it only the realm host itself is accepted.
   */
  readonly allowParentDomainRpId: boolean;
}

/**
 * Why an RP ID cannot be used.
 *
 * - `not-a-host` — not a host name, or an IP address.
 * - `unrelated` — neither the realm host nor a parent domain of it, so no page
 *   of the realm could run a ceremony under it.
 * - `parent-not-allowed` — a parent domain without the operator's opt-in.
 * - `public-suffix` — a name on the Public Suffix List, such as `com`, `co.uk`
 *   or a private-section entry, or a single label the list does not know.
 *   Names under a public suffix belong to unrelated parties, and browsers
 *   refuse one as an RP ID. Only `localhost` is kept, for development.
 */
export type RelyingPartyIdErrorReason =
  | 'not-a-host'
  | 'unrelated'
  | 'parent-not-allowed'
  | 'public-suffix';

/** An RP ID the realm cannot use. The message names the values: it is for the operator. */
export class RelyingPartyIdError extends Error {
  constructor(
    public readonly reason: RelyingPartyIdErrorReason,
    message: string,
    options?: { cause?: unknown }
  ) {
    super(message, options);
    this.name = 'RelyingPartyIdError';
    Object.setPrototypeOf(this, RelyingPartyIdError.prototype);
  }
}

/**
 * Whether `name` is a public suffix: the list's private section counts, as it
 * does in browsers, and a name the list does not know falls under its default
 * rule (`*`), so a single unknown label is one too.
 */
function isPublicSuffix(name: string): boolean {
  return getPublicSuffix(name, { allowPrivateDomains: true }) === name;
}

/**
 * Resolve a realm's RP ID from its host and the operator's settings.
 *
 * @throws RelyingPartyIdError when the configured value is not a host name, is
 * unrelated to the realm host, is a public suffix other than `localhost`, or
 * is a parent domain without `allowParentDomainRpId`.
 */
export function resolveRelyingPartyId(settings: RelyingPartyIdSettings): ResolvedRelyingPartyId {
  const configured = settings.configured?.trim();
  if (configured === undefined || configured === '') {
    return { rpId: settings.realmHost, scope: 'realm-host', warning: undefined };
  }

  let rpId: string;
  try {
    rpId = normaliseRealmHost(configured, 'primary');
  } catch (error) {
    if (!(error instanceof InvalidRealmHostError)) throw error;
    throw new RelyingPartyIdError(
      'not-a-host',
      `The RP ID "${configured}" is not a host name: ${error.message}. An RP ID is a bare domain name, such as auth.example.com, with no scheme, port or path.`,
      { cause: error }
    );
  }

  if (rpId === settings.realmHost) return { rpId, scope: 'realm-host', warning: undefined };

  if (!rpIdCoversHost(rpId, settings.realmHost)) {
    throw new RelyingPartyIdError(
      'unrelated',
      `The RP ID "${rpId}" is neither the realm host "${settings.realmHost}" nor a parent domain of it, so no page of the realm could use a passkey created under it.`
    );
  }
  if (rpId !== 'localhost' && isPublicSuffix(rpId)) {
    throw new RelyingPartyIdError(
      'public-suffix',
      `The RP ID "${rpId}" is a public suffix: the names under it belong to unrelated parties, and browsers refuse it as an RP ID. Use the realm host "${settings.realmHost}" or a registrable parent domain.`
    );
  }
  if (!settings.allowParentDomainRpId) {
    throw new RelyingPartyIdError(
      'parent-not-allowed',
      `The RP ID "${rpId}" is a parent domain of the realm host "${settings.realmHost}". It lets every host under "${rpId}" ask for assertions of the realm's passkeys, so it needs the operator's explicit opt-in.`
    );
  }
  return {
    rpId,
    scope: 'parent-domain',
    warning: parentDomainRpIdWarning(rpId, settings.realmHost),
  };
}

/** The warning a parent-domain RP ID carries (ADR-019 Decision 2). */
function parentDomainRpIdWarning(rpId: string, realmHost: string): string {
  return `The passkey RP ID is the parent domain "${rpId}" of the realm host "${realmHost}": every host under "${rpId}" can ask for assertions of this realm's passkeys, including hosts QAuth does not run. QAuth serves no app association files in this mode; they belong on "${rpId}".`;
}

/** The RP ID differs from the one the realm's passkeys are bound to. */
export class RelyingPartyIdLockedError extends Error {
  constructor(
    public readonly lockedRpId: string,
    public readonly configuredRpId: string
  ) {
    super(
      `The realm's passkeys are bound to the RP ID "${lockedRpId}", but the configured RP ID is "${configuredRpId}". The RP ID is locked once a realm has a passkey: another one would orphan every passkey enrolled under "${lockedRpId}".`
    );
    this.name = 'RelyingPartyIdLockedError';
    Object.setPrototypeOf(this, RelyingPartyIdLockedError.prototype);
  }
}

/**
 * Check the resolved RP ID against the realm's lock: the RP ID its first
 * passkey was enrolled under, or `null` while it has none.
 *
 * @throws RelyingPartyIdLockedError when the realm is locked to another RP ID.
 */
export function assertRelyingPartyIdUnlockedOrSame(
  lockedRpId: string | null,
  resolved: Pick<ResolvedRelyingPartyId, 'rpId'>
): void {
  if (lockedRpId !== null && lockedRpId !== resolved.rpId) {
    throw new RelyingPartyIdLockedError(lockedRpId, resolved.rpId);
  }
}
