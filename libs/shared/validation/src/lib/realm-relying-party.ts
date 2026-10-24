/**
 * A realm's passkey relying party, read from its row (ADR-019 Decisions 1 and
 * 2, issue #553).
 *
 * A WebAuthn ceremony needs two values, and both come from the `realms` row,
 * never from the request:
 *
 * - the RP ID: `webauthn_rp_id` when the operator set one (a parent domain,
 *   under the opt-in), otherwise the realm's primary host. The primary host is
 *   the host of the realm's issuer, and both are permanent;
 * - the origin the realm's hosted pages run on, which the WebAuthn origin check
 *   expects in `clientDataJSON.origin`: the origin of the realm's issuer.
 *
 * The database layer returns the RP ID from the lock it takes at the first
 * enrolment, and the auth server reads it for each ceremony, so both use these
 * functions and cannot disagree.
 */
import { normaliseRealmHost } from './realm-host';

/** The `realms` fields a passkey relying party is read from. */
export interface RealmRelyingPartyFields {
  /** `realms.issuer`. NULL only on a realm the boot step has not completed. */
  readonly issuer: string | null;
  /** `realms.webauthn_rp_id`. NULL means the realm's primary host. */
  readonly webauthnRpId: string | null;
}

/**
 * The realm has no issuer yet, so it has no host, no RP ID and no origin. Such
 * a realm is unroutable until the boot step gives it one (#484), so this is a
 * server error, never a client's.
 */
export class RealmWithoutIssuerError extends Error {
  readonly code = 'REALM_WITHOUT_ISSUER';

  constructor() {
    super('Realm has no issuer, so it has no passkey RP ID or origin');
    this.name = 'RealmWithoutIssuerError';
    Object.setPrototypeOf(this, RealmWithoutIssuerError.prototype);
  }
}

function issuerUrl(realm: Pick<RealmRelyingPartyFields, 'issuer'>): URL {
  if (realm.issuer === null) throw new RealmWithoutIssuerError();
  return new URL(realm.issuer);
}

/**
 * The realm's passkey RP ID: `webauthn_rp_id`, or the primary host when it is
 * NULL. Always the port-less host form (`normaliseRealmHost`): a port in the
 * issuer never reaches the RP ID, which WebAuthn defines as a domain.
 *
 * @throws RealmWithoutIssuerError when the RP ID is the primary host and the
 * realm has no issuer yet.
 *
 * @example
 * ```typescript
 * resolveRpId({ issuer: 'https://auth.example.com:8443', webauthnRpId: null }); // 'auth.example.com'
 * resolveRpId({ issuer: 'https://auth.example.com', webauthnRpId: 'example.com' }); // 'example.com'
 * ```
 */
export function resolveRpId(realm: RealmRelyingPartyFields): string {
  if (realm.webauthnRpId !== null) return normaliseRealmHost(realm.webauthnRpId, 'primary');
  return normaliseRealmHost(issuerUrl(realm).hostname, 'primary');
}

/**
 * The origin a passkey ceremony on the realm's own pages comes from: scheme,
 * host and port of the realm's issuer, in the form a browser writes in
 * `clientDataJSON.origin` (lower case, default port dropped, no path).
 *
 * @throws RealmWithoutIssuerError when the realm has no issuer yet.
 *
 * @example
 * ```typescript
 * expectedOrigin({ issuer: 'https://auth.example.com:8443' }); // 'https://auth.example.com:8443'
 * expectedOrigin({ issuer: 'https://Auth.Example.com:443' });  // 'https://auth.example.com'
 * ```
 */
export function expectedOrigin(realm: Pick<RealmRelyingPartyFields, 'issuer'>): string {
  return issuerUrl(realm).origin;
}
