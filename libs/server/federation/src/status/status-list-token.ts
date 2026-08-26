import { importPublicSigningKey, verifyWithHeader } from '@qauth-labs/core-crypto';

import { ValidatedIssuer } from '../trust/issuer-identity';
import { assertIssuerTrusted, type TrustRegistry } from '../trust/trust-registry';
import type { CredentialStatusRejectionReason } from './credential-status-rejection';
import { isStatusListBitWidth } from './status-list-bits';
import {
  certificateBindsIssuer,
  resolveStatusListSigningCertificate,
  type StatusListTrustAnchors,
} from './status-list-chain';
import {
  MAX_STATUS_LIST_TOKEN_BYTES,
  STATUS_LIST_TOKEN_TYP,
  type StatusListBitWidth,
} from './status-list-spec';

/**
 * Verifying a Status List Token (draft-14 §5.1 / §8.3, issue #297).
 *
 * ## The order of operations is the security property
 *
 * A Status List Token arrives as bytes from a URI a credential named. Every
 * field in it — including the `x5c` that says which key signed it — is hostile
 * until the signature is checked, and the signature cannot be checked until a
 * key has been chosen from those same hostile fields. That circularity is
 * unavoidable and is resolved the only way it can be: the UNVERIFIED header is
 * used to NOMINATE a key, the nomination is constrained to certificates that
 * chain to an operator-configured anchor, and nothing else in the token is read
 * until the signature over it has verified.
 *
 * Concretely, and in this order:
 *
 *  1. bound the token size, then split and decode the protected header ALONE;
 *  2. require `alg: ES256` (HAIP §7) — pinned from the header we are about to
 *     verify against, and passed to the verifier as the ONLY permitted
 *     algorithm, so the header cannot negotiate itself down;
 *  3. resolve `x5c` to an anchored, non-self-signed, in-validity leaf;
 *  4. verify the signature and `exp` with that leaf's key;
 *  5. only now read claims — and re-read `typ` from the AUTHENTICATED header,
 *     not the one decoded in step 1;
 *  6. bind: `sub` must equal the URI we fetched, and the leaf's `dNSName` SAN
 *     must cover `iss`.
 *
 * Step 5 is easy to get wrong by treating step 1's header as trustworthy. It is
 * not — an attacker controls it in full — and `typ` is precisely the member
 * that stops a credential, an ID token, or any other JWS the issuer's key ever
 * signed from being replayed here as a status list (RFC 8725 §3.11).
 *
 * ## `sub` binding is what makes the fetch meaningful
 *
 * draft-14 §5.1, restated as the §8.3 step 4a validation rule: the token's
 * `sub` MUST equal the credential's `status_list.uri`. Without it, an attacker
 * who can get QAuth to fetch ANY anchored status list — their own, listing
 * their own credential as valid — can point every credential at it. The
 * comparison is byte-exact against the URI as the credential wrote it, which is
 * why `StatusListReference.uri` is kept verbatim.
 *
 * ## Why `iss` is NOT compared to the credential's issuer
 *
 * A recurring review question, so the answer is recorded here rather than
 * rediscovered. draft-14 does not require the two to match, and this is not an
 * omission in the draft — the requirement existed and was deliberately removed
 * in draft -04 (*"remove requirement for matching iss claim in Referenced Token
 * and Status List Token"*). The §8.3 validation rules a Relying Party MUST
 * apply list `sub`, `iat`, `exp` and `ttl`; there is no `iss` rule among them,
 * and §5.1 does not even list `iss` as a claim of the Status List Token.
 *
 * Adding the comparison would be actively wrong, not merely redundant. §11.3
 * treats *"the Issuer of the Referenced Token is a different entity than the
 * Status Issuer"* as a first-class deployment and says the keys *"may be
 * cryptographically linked, e.g. by a Certificate Authority through an x.509
 * PKI … issued by the same Certificate Authority"* — which is exactly the
 * anchored `x5c` path plus the `dNSName` SAN binding this module implements.
 * Requiring `iss` equality would refuse precisely the topology the spec
 * recommends, so the checker's API is deliberately NOT widened to take the
 * credential's issuer.
 *
 * What stops cross-issuer impersonation instead is the pair of bindings that
 * are checked: `sub` must equal the `status_list.uri` written inside the
 * issuer-signed credential, so an attacker cannot redirect a revoked credential
 * at a status list of their choosing; and the leaf certificate's `dNSName` SAN
 * must cover the `iss` host, so an anchored certificate cannot sign for an
 * issuer it does not speak for.
 *
 * `iss` is nonetheless REQUIRED here even though §5.1 does not require it: the
 * SAN binding needs a name to bind against, and a token with no `iss` would
 * silently skip that check, so refusing it is the fail-closed reading. Be
 * honest about the cost — §5.1 lists only `typ`, `sub`, `iat` and `status_list`
 * as REQUIRED and its own non-normative example carries NO `iss` at all (nor
 * does the §5.2 CWT one), so this rejects a token the draft would call
 * conforming. It is a deliberate deployment-profile restriction, which §5.1
 * rule 4 permits — *"Application of additional restrictions and policies are at
 * the discretion of the Relying Party"* — and it is only safe to impose because
 * status issuers here must already be anchored by the operator, who can require
 * `iss` of them. An ecosystem that cannot must drop the SAN binding rather than
 * relax this to "absent means unchecked".
 */

/** Longest protected header accepted, in base64url characters. */
const MAX_PROTECTED_HEADER_LENGTH = 32 * 1024;

/** The only JWS algorithm a Status List Token may use (HAIP §7). */
const REQUIRED_STATUS_LIST_ALG = 'ES256';

/** The verified contents of a Status List Token, ready for a bit lookup. */
export interface VerifiedStatusList {
  /** `status_list.bits` — validated to 1, 2, 4 or 8. */
  readonly bits: StatusListBitWidth;
  /** `status_list.lst` — the base64url ZLIB payload, not yet decoded. */
  readonly lst: string;
  /** The verified `iss`, for audit. */
  readonly issuer: string;
  /**
   * `ttl` in seconds when the token carried one — the issuer's own cache
   * budget (draft-14 §5.1).
   */
  readonly ttlSeconds?: number;
  /** `exp` as epoch milliseconds when present. */
  readonly expiresAtMs?: number;
}

/** Outcome of {@link verifyStatusListToken}. */
export type StatusListTokenVerification =
  | { readonly outcome: 'verified'; readonly statusList: VerifiedStatusList }
  | { readonly outcome: 'rejected'; readonly reason: CredentialStatusRejectionReason };

/** Inputs for {@link verifyStatusListToken}. */
export interface VerifyStatusListTokenOptions {
  /** The compact JWS exactly as the endpoint served it. */
  readonly token: string;
  /** The credential's `status_list.uri`, verbatim; must equal the token `sub`. */
  readonly expectedUri: string;
  /** Operator-configured anchors the `x5c` chain must terminate at. */
  readonly anchors: StatusListTrustAnchors;
  /** Reference time for signature expiry and certificate validity. */
  readonly now: Date;
  /** Clock skew tolerance in seconds for `exp`. Defaults to zero. */
  readonly clockToleranceSeconds?: number;
  /**
   * When supplied, the verified `iss` must ALSO be trusted by this realm's
   * issuer registry (#236) — an additional constraint on top of the anchor
   * path, for deployments that pin status issuers by identity as well as by CA.
   * Omitting it leaves the anchor chain and the SAN binding as the gate.
   */
  readonly issuerTrustRegistry?: TrustRegistry;
}

/** Whether `value` is a plain, non-array object. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Decode the UNVERIFIED protected header of a compact JWS.
 *
 * Named for what it is. Every caller of this function is one `typ` check away
 * from a type-confusion bug, so the value it returns is used for exactly two
 * things — nominating a key and pinning `alg` — and re-read from the
 * authenticated header afterwards.
 */
function decodeUnverifiedProtectedHeader(token: string): Record<string, unknown> | undefined {
  const firstDot = token.indexOf('.');
  if (firstDot <= 0) return undefined;

  // A compact JWS has exactly three segments. Anything else is not one, and
  // counting here means the verifier is never handed a JWE or a flattened JSON
  // serialization to be confused by.
  if (token.split('.').length !== 3) return undefined;

  const encoded = token.slice(0, firstDot);
  if (encoded.length > MAX_PROTECTED_HEADER_LENGTH) return undefined;
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) return undefined;

  try {
    const parsed: unknown = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** Read the `status_list` claim into its validated shape. */
function readStatusListClaim(
  claims: Record<string, unknown>
): { bits: StatusListBitWidth; lst: string } | undefined {
  const statusList = claims['status_list'];
  if (!isRecord(statusList)) return undefined;

  const bits = statusList['bits'];
  const lst = statusList['lst'];
  if (!isStatusListBitWidth(bits)) return undefined;
  if (typeof lst !== 'string' || lst.length === 0) return undefined;

  return { bits, lst };
}

/**
 * Whether the verified `iss` passes the optional realm issuer registry (#236).
 *
 * `assertIssuerTrusted` throws by design — it is a gate, not a predicate — so
 * it is adapted here rather than reimplemented. Reimplementing the membership
 * test would duplicate the `ValidatedIssuer` re-check and the
 * backend-that-throws containment, which is exactly the drift that gate exists
 * to prevent.
 */
function passesIssuerRegistry(issuer: string, registry: TrustRegistry | undefined): boolean {
  if (registry === undefined) return true;
  try {
    assertIssuerTrusted(
      registry,
      ValidatedIssuer.fromValidatedPresentation({
        identifier: issuer,
        // The key came from a validated `x5c` chain, which is precisely what this
        // resolution method names.
        keyResolution: 'x5c',
      })
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify a Status List Token end to end (#297).
 *
 * Never throws: every failure is a `rejected` outcome carrying a server-side
 * reason. A throw here would become a 500 for an attacker-supplied document and
 * would make failure modes distinguishable by response code.
 *
 * @param options - see {@link VerifyStatusListTokenOptions}.
 * @returns the verified status list, or the reason it was refused.
 */
export async function verifyStatusListToken(
  options: VerifyStatusListTokenOptions
): Promise<StatusListTokenVerification> {
  const { token, expectedUri, anchors, now } = options;

  if (typeof token !== 'string' || token.length === 0) {
    return { outcome: 'rejected', reason: 'token-unverifiable' };
  }
  if (Buffer.byteLength(token, 'utf8') > MAX_STATUS_LIST_TOKEN_BYTES) {
    return { outcome: 'rejected', reason: 'token-unverifiable' };
  }

  const unverifiedHeader = decodeUnverifiedProtectedHeader(token);
  if (unverifiedHeader === undefined) {
    return { outcome: 'rejected', reason: 'token-unverifiable' };
  }
  if (unverifiedHeader['alg'] !== REQUIRED_STATUS_LIST_ALG) {
    return { outcome: 'rejected', reason: 'token-unverifiable' };
  }

  const chain = resolveStatusListSigningCertificate(unverifiedHeader['x5c'], anchors, now);
  if (chain.outcome === 'rejected') {
    // A chain that does not reach a configured anchor is an UNTRUSTED status
    // issuer, not a broken token; the audit stream distinguishes them even
    // though the client cannot.
    const reason: CredentialStatusRejectionReason =
      chain.reason === 'no-path-to-anchor' || chain.reason === 'anchor-in-chain'
        ? 'issuer-untrusted'
        : 'token-unverifiable';
    return { outcome: 'rejected', reason };
  }

  let claims: Record<string, unknown>;
  let protectedHeader: Record<string, unknown>;
  try {
    const key = await importPublicSigningKey(chain.publicKeyPem, REQUIRED_STATUS_LIST_ALG);
    const verified = await verifyWithHeader(token, key, {
      algorithms: [REQUIRED_STATUS_LIST_ALG],
      currentDate: now,
      ...(options.clockToleranceSeconds !== undefined
        ? { clockTolerance: options.clockToleranceSeconds }
        : {}),
    });
    claims = verified.claims;
    protectedHeader = verified.protectedHeader;
  } catch {
    // Bad signature, expired token, unusable key — one outcome, deliberately.
    return { outcome: 'rejected', reason: 'token-unverifiable' };
  }

  // Re-read from the AUTHENTICATED header. See the module JSDoc: the header
  // decoded above is attacker-controlled and was only ever a key nomination.
  if (protectedHeader['typ'] !== STATUS_LIST_TOKEN_TYP) {
    return { outcome: 'rejected', reason: 'token-unverifiable' };
  }

  if (claims['sub'] !== expectedUri) {
    return { outcome: 'rejected', reason: 'token-unverifiable' };
  }

  // draft-14 §5.1 makes `iat` mandatory. Enforced because a token with no
  // issuance time cannot be reasoned about for freshness at all.
  const iat = claims['iat'];
  if (typeof iat !== 'number' || !Number.isFinite(iat)) {
    return { outcome: 'rejected', reason: 'token-unverifiable' };
  }

  const issuer = claims['iss'];
  if (typeof issuer !== 'string' || issuer.length === 0) {
    return { outcome: 'rejected', reason: 'issuer-untrusted' };
  }
  if (!certificateBindsIssuer(chain.leaf, issuer)) {
    return { outcome: 'rejected', reason: 'issuer-untrusted' };
  }
  if (!passesIssuerRegistry(issuer, options.issuerTrustRegistry)) {
    return { outcome: 'rejected', reason: 'issuer-untrusted' };
  }

  const statusList = readStatusListClaim(claims);
  if (statusList === undefined) {
    return { outcome: 'rejected', reason: 'list-unreadable' };
  }

  const ttl = claims['ttl'];
  const exp = claims['exp'];

  return {
    outcome: 'verified',
    statusList: Object.freeze({
      bits: statusList.bits,
      lst: statusList.lst,
      issuer,
      // A non-positive or non-finite `ttl` is dropped rather than honoured:
      // draft-14 says it is a maximum cache age, and a negative maximum is not
      // a shorter cache, it is a malformed claim.
      ...(typeof ttl === 'number' && Number.isFinite(ttl) && ttl > 0
        ? { ttlSeconds: Math.floor(ttl) }
        : {}),
      ...(typeof exp === 'number' && Number.isFinite(exp) ? { expiresAtMs: exp * 1000 } : {}),
    }),
  };
}
