import { importPrivateSigningKey } from '@qauth-labs/core-crypto';
import { SignJWT } from 'jose';

import {
  VERIFIER_REQUEST_SIGNING_ALGORITHM,
  type VerifierSigningMaterial,
} from '../x509/verifier-signing-material';
import type { Oid4vpAuthorizationRequest } from './authorization-request';

/**
 * The SIGNED Authorization Request object — a JWT-Secured Authorization Request
 * (JAR, RFC 9101) carrying the OID4VP request parameters (issue #377, Phase B).
 *
 * HAIP 1.0 §5.1: *"Signed Authorization Requests MUST be used by utilizing
 * JWT-Secured Authorization Request (JAR) [RFC9101] with the `request_uri`
 * parameter."* Both halves are mandates. This module produces the JWT;
 * `encodeOid4vpRequestUri` produces the reference that delivers it, and refuses
 * to deliver a signed request any other way.
 *
 * ## What the wallet does with this, and what each header member is for
 *
 * The wallet fetches the JWT, reads `x5c`, checks that the chain terminates at a
 * trust anchor IT holds — not one the request carried — and then checks that
 * `client_id` equals the digest of `x5c[0]`. Only then does it verify the
 * signature. So the header is doing identity work, not decoration:
 *
 * - **`x5c`** carries the leaf first and the trust anchor NOT AT ALL. The anchor
 *   is what the wallet already trusts; shipping a copy would let a request vouch
 *   for itself. `VerifierSigningMaterial` can only be built by a chain that
 *   passed `resolveAnchoredSigningCertificate`, which refuses an anchor inside
 *   the chain outright, so the exclusion is a property of the value rather than
 *   a rule this module remembers to apply.
 * - **`alg: ES256`** is HAIP §7's floor and the only algorithm a P-256 leaf can
 *   satisfy. It is not caller-selectable: an algorithm the leaf key cannot
 *   produce is a request no wallet can verify.
 * - **`typ: oauth-authz-req+jwt`** is RFC 9101 §10.8's registered type for a
 *   request object. It is what lets a wallet refuse a JWT that was minted for
 *   some other purpose and replayed here.
 *
 * ## Signed with `jose` rather than `@qauth-labs/core-crypto`'s `sign()`
 *
 * Deliberate, and narrow. `sign()` is built for the tokens QAuth ISSUES: it
 * mandates `iss`, `aud` and `exp` because every access and ID token has all
 * three. A request object's claim set is defined by RFC 9101 §4 as *the
 * authorization request parameters*, and `aud` in particular has no OID4VP-wide
 * value — a wallet is not an OpenID Provider with an Issuer Identifier — so
 * stamping a guess would produce requests a conformant wallet rejects for
 * audience mismatch. The KEY still comes through `core-crypto`
 * (`importPrivateSigningKey`), so the crypto-agility seam that owns algorithm
 * selection is unbroken; only the claim shaping is local, which is exactly the
 * part `sign()` is opinionated about for a different reason.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9101 §4, §10.8
 * @see https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html §5.1
 */

/** `typ` of a JAR request object (RFC 9101 §10.8). */
export const OID4VP_REQUEST_OBJECT_TYP = 'oauth-authz-req+jwt';

/** Media type the request-object endpoint serves (RFC 9101 §10.8). */
export const OID4VP_REQUEST_OBJECT_MEDIA_TYPE = 'application/oauth-authz-req+jwt';

/**
 * Default request-object lifetime, in seconds.
 *
 * Matches `DEFAULT_OID4VP_REQUEST_TTL_MS` — the lifetime of the request STATE
 * the wallet will redeem — because the two bound the same exchange. A request
 * object that outlived its state would be a JWT a wallet can still fetch and
 * sign a presentation against, for a request QAuth will refuse on arrival.
 */
export const DEFAULT_REQUEST_OBJECT_LIFETIME_SECONDS = 5 * 60;

/** Inputs to {@link signOid4vpRequestObject}. */
export interface SignOid4vpRequestObjectOptions {
  /** The request to sign, exactly as {@link buildOid4vpAuthorizationRequest} built it. */
  readonly request: Oid4vpAuthorizationRequest;
  /** The validated verifier key and chain. */
  readonly material: VerifierSigningMaterial;
  /**
   * `aud` of the request object. OMITTED when absent, which is the default.
   *
   * RFC 9101 §4 inherits `aud` from a world where the recipient is an OpenID
   * Provider with an Issuer Identifier. OID4VP has no such value for a wallet,
   * and neither OID4VP 1.0 nor HAIP 1.0 names one, so QAuth emits no `aud`
   * rather than inventing a convention: an ecosystem whose wallets require a
   * specific audience states it here, and one that does not gets a request with
   * nothing extra to reject.
   */
  readonly audience?: string;
  /** Lifetime in seconds; defaults to {@link DEFAULT_REQUEST_OBJECT_LIFETIME_SECONDS}. */
  readonly lifetimeSeconds?: number;
  /** Reference time. Defaults to now; injectable so expiry is testable. */
  readonly now?: Date;
}

/**
 * Sign an OID4VP Authorization Request into a JAR request object (#377).
 *
 * @param options - see {@link SignOid4vpRequestObjectOptions}.
 * @returns the compact JWS, ready to be served from the request-object endpoint.
 * @throws Error when the leaf certificate is no longer inside its validity
 * window — see below.
 */
export async function signOid4vpRequestObject(
  options: SignOid4vpRequestObjectOptions
): Promise<string> {
  const { request, material } = options;
  const now = options.now ?? new Date();

  // The one check boot-time validation structurally cannot make: a process that
  // started while the leaf was valid is still running after it expired. Every
  // wallet refuses an expired chain, so continuing would turn a certificate
  // renewal an operator forgot into a total, silent presentation outage. Refused
  // here so the wallet-login path renders its uniform refusal and the operator
  // gets a server-side error naming the cause.
  if (material.leafNotAfter.getTime() <= now.getTime()) {
    throw new Error(
      "The OID4VP verifier's leaf certificate has expired, so a signed Authorization Request cannot be produced. Renew the chain configured for the verifier identity (#377); a wallet refuses an expired x5c chain, so signing anyway would fail every presentation."
    );
  }

  const issuedAt = Math.floor(now.getTime() / 1000);
  const lifetime = options.lifetimeSeconds ?? DEFAULT_REQUEST_OBJECT_LIFETIME_SECONDS;
  const key = await importPrivateSigningKey(
    material.privateKeyPem,
    VERIFIER_REQUEST_SIGNING_ALGORITHM
  );

  // RFC 9101 §4: the request object's claims ARE the authorization request
  // parameters. Spread rather than re-listed so a parameter added to
  // `Oid4vpAuthorizationRequest` cannot be signed-over in one place and dropped
  // in the other — a mismatch a wallet would report as a malformed request with
  // no clue which member went missing.
  const jwt = new SignJWT({ ...request })
    .setProtectedHeader({
      alg: VERIFIER_REQUEST_SIGNING_ALGORITHM,
      typ: OID4VP_REQUEST_OBJECT_TYP,
      x5c: [...material.x5c],
    })
    // RFC 9101 §4: `iss` is the client identifier. Under `x509_hash` that is the
    // digest of the very certificate `x5c[0]` carries, so the claim and the
    // header state the same identity and a wallet can check they agree.
    .setIssuer(request.client_id)
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + lifetime);

  return options.audience === undefined
    ? jwt.sign(key)
    : jwt.setAudience(options.audience).sign(key);
}
