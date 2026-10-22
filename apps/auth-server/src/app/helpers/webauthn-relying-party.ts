import {
  parentDomainRpIdWarning,
  RelyingPartyIdError,
  type ResolvedRelyingPartyId,
  resolveRelyingPartyId,
} from '@qauth-labs/fastify-plugin-federation';

/**
 * The default realm's passkey relying party (ADR-019 Decision 2, issue #467).
 *
 * The RP ID rules belong to the WebAuthn provider (`resolveRelyingPartyId` in
 * `@qauth-labs/server-federation`); this module applies them to the default
 * realm's host and the operator's `WEBAUTHN_RP_ID` settings, and words a
 * refusal in the variables the operator has to change. The boot step and the
 * association-file routes both read it, so they never disagree about the RP ID.
 */

/** The operator's passkey RP ID settings. */
export interface PasskeyRelyingPartySettings {
  /** `WEBAUTHN_RP_ID`, normalised; `undefined` means the realm host. */
  readonly rpId: string | undefined;
  /** `WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN`. */
  readonly allowParentDomain: boolean;
}

/** No `WEBAUTHN_RP_ID`: the realm's own host. */
export const REALM_HOST_RELYING_PARTY: PasskeyRelyingPartySettings = Object.freeze({
  rpId: undefined,
  allowParentDomain: false,
});

/** A realm's RP ID, with the boot warning a parent domain carries. */
export interface RealmRelyingParty extends ResolvedRelyingPartyId {
  readonly realmHost: string;
  /** Set for a parent-domain RP ID: logged at every boot. */
  readonly warning: string | undefined;
}

/** The passkey settings cannot give the realm an RP ID. The message names the variables. */
export class PasskeyRelyingPartyError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'PasskeyRelyingPartyError';
  }
}

/**
 * Resolve the RP ID of the realm whose primary host is `realmHost`.
 *
 * @throws PasskeyRelyingPartyError when `WEBAUTHN_RP_ID` is unrelated to the
 * realm host, a parent domain without `WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN`, or
 * a top-level domain.
 */
export function resolveRealmRelyingParty(
  realmHost: string,
  settings: PasskeyRelyingPartySettings
): RealmRelyingParty {
  let resolved: ResolvedRelyingPartyId;
  try {
    resolved = resolveRelyingPartyId({
      realmHost,
      configured: settings.rpId,
      allowParentDomain: settings.allowParentDomain,
    });
  } catch (error) {
    if (!(error instanceof RelyingPartyIdError)) throw error;
    const remedy =
      error.reason === 'parent-not-allowed'
        ? 'Set WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN=true to opt in, or unset WEBAUTHN_RP_ID to use the realm host.'
        : 'Unset WEBAUTHN_RP_ID to use the realm host.';
    throw new PasskeyRelyingPartyError(`WEBAUTHN_RP_ID: ${error.message} ${remedy}`, {
      cause: error,
    });
  }
  return { ...resolved, realmHost, warning: parentDomainRpIdWarning(resolved, realmHost) };
}

/**
 * Whether QAuth serves the platform association files for this realm: only
 * while the RP ID is the realm's own host. Under a parent-domain RP ID the
 * platforms fetch the files from the parent domain, which QAuth does not run
 * (ADR-017 Decision 14).
 */
export function servesAssociationFiles(relyingParty: RealmRelyingParty): boolean {
  return relyingParty.scope === 'realm-host';
}

/**
 * The origins a passkey ceremony started for a client accepts (ADR-017
 * Decision 14, issue #467): the realm's own origin, where the hosted pages
 * run, then the client's operator-set `webauthn_allowed_origins` (a native
 * app's `android:apk-key-hash:` origin, or a first-party web front-end under a
 * parent-domain RP ID). The realm origin comes from the realm's issuer, never
 * from the request (ADR-019 Decision 1). Each is checked against the RP ID
 * when the ceremony starts.
 */
export function passkeyCeremonyOrigins(
  realmIssuer: string,
  clientOrigins: readonly string[]
): string[] {
  return [...new Set([new URL(realmIssuer).origin, ...clientOrigins])];
}
