/**
 * SD-JWT VC (`dc+sd-jwt`) presentation validation (issue #234).
 *
 * The first — and today the only — implementation behind the credential-format
 * adapter boundary. It answers ONE question: is this Presentation
 * cryptographically sound, fresh, and bound to this request by its holder? It
 * answers nothing about trust, identity or accounts. See
 * `validated-credential.ts` for what the answer is allowed to mean.
 *
 * ## The four independent proofs
 *
 * A Presentation is `<Issuer-signed JWT>~<Disclosure>*~<KB-JWT>`, and each part
 * carries a different guarantee. All four are REQUIRED; each is a complete
 * bypass on its own if skipped:
 *
 *  1. **Issuer signature.** Without it every claim is attacker-authored, and
 *    `iss` is just a string anyone can type. The key comes from resolution
 *    (`issuer-key-resolution.ts`), never from the credential's own key material,
 *    and the algorithm comes from the caller's allowlist, never from the token's
 *    own header (RFC 9700 algorithm confusion).
 *  2. **Disclosure digests.** Selective disclosure works by the issuer signing
 *    HASHES and the holder revealing pre-images. If a Disclosure that hashes to
 *    nothing the issuer signed were accepted, a holder could add claims to their
 *    own credential — the SD-JWT equivalent of editing the payload. Digests must
 *    therefore match exactly, be claimed at most once, and none may be left over.
 *  3. **Holder binding.** The Key Binding JWT proves the presenter holds the key
 *    the issuer bound the credential to, and that they made THIS presentation for
 *    THIS Verifier (`aud`) in response to THIS request (`nonce`) over THIS exact
 *    payload (`sd_hash`). Without it, a captured Presentation replays: a
 *    correctly-signed credential intercepted anywhere would authenticate the
 *    interceptor.
 *  4. **Validity window.** An expired credential is a statement its issuer has
 *    stopped making. The window is read from the issuer-signed payload only, and
 *    a credential that made `exp`/`nbf` (or any other §3.2.2.2 claim) selectively
 *    disclosable is refused outright — see
 *    {@link NON_SELECTIVELY_DISCLOSABLE_CLAIMS}, without which such a credential
 *    would carry an expiry nobody enforced.
 *
 * ## Bounded before it is walked
 *
 * Everything here runs on an unauthenticated path — a wallet has no client
 * credentials, so anyone can POST. The intake (#233) bounds the Presentation's
 * length; this module additionally bounds the number of Disclosures and the
 * nesting depth of the claim structure, because a signed-but-hostile credential
 * would otherwise reach an unbounded recursion.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 * @see SD-JWT (selective disclosure) and SD-JWT VC (`vct`, `cnf`, `dc+sd-jwt`)
 */

import { createHash, timingSafeEqual } from 'node:crypto';

import { importPublicSigningJwk, type JwsAlgorithm } from '@qauth-labs/core-crypto';
import { compactVerify, type JWK } from 'jose';

import {
  canonicalizeIssuerIdentifier,
  type IssuerKeyResolutionMethod,
  ValidatedIssuer,
} from '../trust/issuer-identity';
import type { DcqlCredentialQuery } from './dcql';
import { rejectPresentation } from './presentation-rejection';
import type {
  CredentialValidityWindow,
  PresentationValidationContext,
  ValidatedCredential,
} from './validated-credential';
import {
  DEFAULT_KEY_BINDING_MAX_AGE_SECONDS,
  DEFAULT_PRESENTATION_CLOCK_TOLERANCE_SECONDS,
} from './validated-credential';

/**
 * The `typ` an SD-JWT VC's Issuer-signed JWT must declare.
 *
 * Equal to the Credential Format identifier by design (SD-JWT VC): the media
 * type and the OID4VP format identifier are the same string. Declared here
 * rather than imported from `credential-format.ts` so this module has no
 * dependency on the adapter registry that dispatches TO it; a test pins the two
 * constants equal.
 *
 * Checked strictly. A JOSE `typ` is how a verifier refuses to accept a token
 * minted for a different purpose (cross-token confusion), and the historical
 * `vc+sd-jwt` spelling is deliberately NOT accepted — it belongs to a superseded
 * revision, and quietly accepting both would make the profile untestable.
 */
export const SD_JWT_VC_TYP = 'dc+sd-jwt';

/** The `typ` a Key Binding JWT must declare (SD-JWT §4.3). */
export const KEY_BINDING_JWT_TYP = 'kb+jwt';

/**
 * Hash algorithms accepted for `_sd_alg`, mapped to their Node identifiers.
 *
 * IANA "Named Information Hash Algorithm" names, per SD-JWT. SHA-1 and MD5 are
 * absent and must stay absent: a digest is the ONLY thing binding a Disclosure
 * to the issuer's signature, so a collision there is a claim-injection primitive.
 */
const SD_HASH_ALGORITHMS: Readonly<Record<string, string>> = Object.freeze({
  'sha-256': 'sha256',
  'sha-384': 'sha384',
  'sha-512': 'sha512',
});

/** `_sd_alg`'s default when the credential omits it (SD-JWT §4.1.1). */
const DEFAULT_SD_HASH_ALGORITHM = 'sha-256';

/**
 * Upper bound on Disclosures in one Presentation.
 *
 * A DoS guard on an unauthenticated path, not a spec limit. Each Disclosure
 * costs a hash and a JSON parse; a credential type needing more than this is not
 * one QAuth is refusing to support, it is one nobody issues.
 */
export const MAX_DISCLOSURES = 64;

/**
 * Upper bound on the nesting depth of the claim structure walked during
 * disclosure resolution.
 *
 * The walk is recursive and its input — after the signature check — is still
 * attacker-influenced in the case that matters most: a compromised or hostile
 * issuer. A depth bound turns "stack overflow, process down" into "one rejected
 * credential".
 */
export const MAX_CLAIM_DEPTH = 32;

/**
 * Claims removed from the returned claim set.
 *
 * - `_sd` / `_sd_alg` — selective-disclosure machinery, meaningless once resolved.
 * - `cnf` — the holder's confirmation key. Consumed to verify key binding and
 *   then dropped: OID4VP §15.5–§15.6 treat wallet key material as a linkability
 *   defect, and ADR-009 forbids keying an account on it. Stripping it is what
 *   makes "do not use it" structural rather than a comment nobody reads.
 * - `iss` — the issuer identity belongs on `ValidatedCredential.issuer` as a
 *   nominally-typed `ValidatedIssuer`. A bare string left in the claims would be
 *   read as an issuer identity while carrying none of #236's guarantees.
 */
const STRIPPED_CREDENTIAL_CLAIMS = Object.freeze(['_sd', '_sd_alg', 'cnf', 'iss']);

/**
 * Registered claims SD-JWT VC §3.2.2.2 forbids from being selectively
 * disclosable.
 *
 * > The following registered JWT claims are used within the SD-JWT component of
 * > the SD-JWT VC and MUST NOT be included in the Disclosures, i.e., cannot be
 * > selectively disclosed.
 *
 * These are exactly the claims a VERIFIER acts on, which is why the prohibition
 * is a security rule rather than a formality. A credential with no plain `exp`
 * and a signed `exp` Disclosure would sail through {@link
 * assertWithinValidityWindow} — which reads the issuer-signed payload, where
 * there is nothing to enforce — and then surface `claims.exp` to a consumer that
 * would reasonably read it as an enforced expiry. `status` is the same trap for
 * revocation (#297): a selectively-disclosable status pointer is one the status
 * checker never sees. `iss`, `cnf` and `vct` are mandatory plain claims here, so
 * a Disclosure of those is already refused as an overwrite — they are listed
 * anyway so the set is the spec's, not a subset that happens to be reachable.
 *
 * `sub` and `iat` are deliberately ABSENT: §3.2.2.2 explicitly permits both in
 * Disclosures, and refusing them would reject compliant credentials.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/ §3.2.2.2
 */
export const NON_SELECTIVELY_DISCLOSABLE_CLAIMS: readonly string[] = Object.freeze([
  'iss',
  'nbf',
  'exp',
  'cnf',
  'vct',
  'vct#integrity',
  'status',
]);

/** One Disclosure, decoded and digested. */
interface ParsedDisclosure {
  /** The Disclosure exactly as received; the digest covers THESE bytes. */
  readonly encoded: string;
  /** `base64url(hash(ascii(encoded)))`. */
  readonly digest: string;
  /** Claim name for an object-property Disclosure; absent for an array element. */
  readonly claimName?: string;
  /** The disclosed value. */
  readonly value: unknown;
}

/** State threaded through the recursive disclosure walk. */
interface DisclosureWalkState {
  readonly byDigest: ReadonlyMap<string, ParsedDisclosure>;
  readonly used: Set<string>;
}

/** Reject anything that is not a plain JSON object. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Compare two strings without an early-exit branch on content.
 *
 * Used for the `nonce` and `aud` comparisons. Neither is a high-value secret on
 * its own — the wallet was told both — but the `nonce` is the freshness binding
 * of a single-use request, and a codebase that compares one authentication input
 * in constant time and the next with `===` teaches the wrong habit at exactly
 * the wrong boundary. Length is compared first because `timingSafeEqual` throws
 * on a length mismatch; length is not the secret.
 */
function constantTimeEquals(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Decode one base64url JOSE segment into a JSON object. */
function decodeJoseSegment(segment: string, label: string): Record<string, unknown> {
  let decoded: unknown;

  try {
    decoded = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch (error) {
    throw rejectPresentation('malformed-presentation', `${label} is not base64url JSON`, error);
  }

  if (!isPlainObject(decoded)) {
    throw rejectPresentation('malformed-presentation', `${label} is not a JSON object`);
  }

  return decoded;
}

/**
 * The three parts of an SD-JWT VC Presentation.
 *
 * The Key Binding JWT is REQUIRED here even though SD-JWT makes it optional in
 * general: this function only ever sees a Presentation returned to an OID4VP
 * `vp_token`, and such a Presentation without holder binding is a replayable
 * bearer credential. Refusing it is the whole point of proof (3) above.
 */
interface SplitPresentation {
  readonly issuerSignedJwt: string;
  readonly disclosures: readonly string[];
  readonly keyBindingJwt: string;
  /**
   * Everything up to and INCLUDING the `~` before the Key Binding JWT — the
   * exact byte range the KB-JWT's `sd_hash` covers (SD-JWT §4.3.1).
   */
  readonly keyBindingInput: string;
}

/** Split the compact serialization, requiring a Key Binding JWT. */
function splitPresentation(presentation: string): SplitPresentation {
  const segments = presentation.split('~');

  if (segments.length < 2) {
    throw rejectPresentation(
      'malformed-presentation',
      'not an SD-JWT compact serialization (no ~ separator)'
    );
  }

  const issuerSignedJwt = segments[0];
  const keyBindingJwt = segments[segments.length - 1];
  const disclosures = segments.slice(1, -1);

  if (keyBindingJwt === '') {
    throw rejectPresentation(
      'holder-binding-invalid',
      'the Presentation carries no Key Binding JWT, so nothing proves the presenter holds the credential'
    );
  }

  if (disclosures.some((disclosure) => disclosure === '')) {
    throw rejectPresentation(
      'malformed-presentation',
      'the Presentation contains an empty segment'
    );
  }

  if (disclosures.length > MAX_DISCLOSURES) {
    throw rejectPresentation(
      'malformed-presentation',
      `the Presentation carries ${disclosures.length} Disclosures, above the ${MAX_DISCLOSURES} bound`
    );
  }

  return {
    issuerSignedJwt,
    disclosures,
    keyBindingJwt,
    keyBindingInput: presentation.slice(0, presentation.lastIndexOf('~') + 1),
  };
}

/**
 * Read the algorithm from a JOSE protected header, pinned to the caller's
 * allowlist.
 *
 * The header value only ever SELECTS from the allowlist — it can never widen it.
 * A token declaring `none`, `HS256`, or any algorithm the deployment did not
 * permit is refused before a key is even looked for.
 */
function readPermittedAlgorithm(
  header: Record<string, unknown>,
  permitted: readonly JwsAlgorithm[],
  label: string
): JwsAlgorithm {
  const alg = header['alg'];

  if (typeof alg !== 'string') {
    throw rejectPresentation('malformed-presentation', `${label} declares no 'alg'`);
  }

  const match = permitted.find((candidate) => candidate === alg);

  if (match === undefined) {
    throw rejectPresentation(
      'malformed-presentation',
      `${label} declares algorithm '${alg}', which this deployment does not permit`
    );
  }

  return match;
}

/** Read the `x5c` chain out of a protected header, if it carries a usable one. */
function readCertificateChain(header: Record<string, unknown>): readonly string[] | undefined {
  const x5c = header['x5c'];

  if (!Array.isArray(x5c) || x5c.length === 0) return undefined;
  if (!x5c.every((entry): entry is string => typeof entry === 'string')) return undefined;

  return Object.freeze([...x5c]);
}

/** Digest one Disclosure exactly as received (SD-JWT §4.2.4). */
function digestDisclosure(encoded: string, hashAlgorithm: string): string {
  return createHash(hashAlgorithm).update(encoded, 'ascii').digest('base64url');
}

/**
 * Decode and digest every Disclosure.
 *
 * Rejects a Disclosure that is not `[salt, name, value]` or `[salt, value]`, one
 * that discloses a claim named `_sd` or `...` (which would let a holder inject
 * selective-disclosure machinery), and any two that digest identically.
 */
function parseDisclosures(
  encodedDisclosures: readonly string[],
  hashAlgorithm: string
): ReadonlyMap<string, ParsedDisclosure> {
  const byDigest = new Map<string, ParsedDisclosure>();

  for (const encoded of encodedDisclosures) {
    let decoded: unknown;

    try {
      decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    } catch (error) {
      throw rejectPresentation(
        'malformed-presentation',
        'a Disclosure is not base64url JSON',
        error
      );
    }

    if (!Array.isArray(decoded) || decoded.length < 2 || decoded.length > 3) {
      throw rejectPresentation(
        'malformed-presentation',
        'a Disclosure is not a 2- or 3-element JSON array'
      );
    }

    if (typeof decoded[0] !== 'string') {
      throw rejectPresentation('malformed-presentation', 'a Disclosure carries no string salt');
    }

    const digest = digestDisclosure(encoded, hashAlgorithm);

    if (byDigest.has(digest)) {
      throw rejectPresentation(
        'disclosure-digest-mismatch',
        'the Presentation carries the same Disclosure twice'
      );
    }

    if (decoded.length === 3) {
      const claimName = decoded[1];

      if (typeof claimName !== 'string') {
        throw rejectPresentation(
          'malformed-presentation',
          'an object-property Disclosure carries a non-string claim name'
        );
      }

      if (claimName === '_sd' || claimName === '...') {
        throw rejectPresentation(
          'disclosure-digest-mismatch',
          `a Disclosure attempts to disclose the reserved claim '${claimName}'`
        );
      }

      byDigest.set(digest, { encoded, digest, claimName, value: decoded[2] });
      continue;
    }

    byDigest.set(digest, { encoded, digest, value: decoded[1] });
  }

  return byDigest;
}

/** Mark a digest consumed, refusing a second claim on it. */
function consumeDigest(state: DisclosureWalkState, digest: string): ParsedDisclosure | undefined {
  const disclosure = state.byDigest.get(digest);

  if (disclosure === undefined) return undefined;

  if (state.used.has(digest)) {
    throw rejectPresentation(
      'disclosure-digest-mismatch',
      'the same digest is claimed in more than one place'
    );
  }

  state.used.add(digest);
  return disclosure;
}

/** Resolve selective disclosure over any claim value. */
function discloseValue(node: unknown, state: DisclosureWalkState, depth: number): unknown {
  if (depth > MAX_CLAIM_DEPTH) {
    throw rejectPresentation(
      'malformed-presentation',
      `the claim structure nests deeper than ${MAX_CLAIM_DEPTH} levels`
    );
  }

  if (Array.isArray(node)) return discloseArray(node, state, depth);
  if (isPlainObject(node)) return discloseObject(node, state, depth);
  return node;
}

/** Resolve `{"...": digest}` array elements (SD-JWT §4.2.2). */
function discloseArray(
  node: readonly unknown[],
  state: DisclosureWalkState,
  depth: number
): unknown[] {
  const result: unknown[] = [];

  for (const element of node) {
    if (isPlainObject(element) && Object.hasOwn(element, '...')) {
      if (Object.keys(element).length !== 1) {
        throw rejectPresentation(
          'malformed-presentation',
          "an array element carries '...' alongside other members"
        );
      }

      const digest = element['...'];

      if (typeof digest !== 'string') {
        throw rejectPresentation(
          'malformed-presentation',
          "an array element's '...' is not a string"
        );
      }

      const disclosure = consumeDigest(state, digest);

      // Not disclosed: the holder chose to withhold this element, which is the
      // whole point of selective disclosure. Omit it and carry on.
      if (disclosure === undefined) continue;

      if (disclosure.claimName !== undefined) {
        throw rejectPresentation(
          'disclosure-digest-mismatch',
          'an object-property Disclosure was presented as an array element'
        );
      }

      result.push(discloseValue(disclosure.value, state, depth + 1));
      continue;
    }

    result.push(discloseValue(element, state, depth + 1));
  }

  return result;
}

/** Resolve an object's `_sd` digests into claims (SD-JWT §4.2.1). */
function discloseObject(
  node: Record<string, unknown>,
  state: DisclosureWalkState,
  depth: number
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(node)) {
    if (key === '_sd' || key === '_sd_alg') continue;
    result[key] = discloseValue(value, state, depth + 1);
  }

  const sd = node['_sd'];

  if (sd === undefined) return result;

  if (!Array.isArray(sd)) {
    throw rejectPresentation('malformed-presentation', "'_sd' is not an array");
  }

  const seen = new Set<string>();

  for (const digest of sd) {
    if (typeof digest !== 'string') {
      throw rejectPresentation('malformed-presentation', "'_sd' carries a non-string digest");
    }

    if (seen.has(digest)) {
      throw rejectPresentation(
        'disclosure-digest-mismatch',
        "the same digest appears twice in one '_sd' array"
      );
    }

    seen.add(digest);

    const disclosure = consumeDigest(state, digest);
    if (disclosure === undefined) continue;

    if (disclosure.claimName === undefined) {
      throw rejectPresentation(
        'disclosure-digest-mismatch',
        "an array-element Disclosure was presented against an '_sd' digest"
      );
    }

    if (Object.hasOwn(result, disclosure.claimName)) {
      throw rejectPresentation(
        'disclosure-digest-mismatch',
        `a Disclosure would overwrite the already-present claim '${disclosure.claimName}'`
      );
    }

    result[disclosure.claimName] = discloseValue(disclosure.value, state, depth + 1);
  }

  return result;
}

/**
 * Resolve every Disclosure against the signed payload.
 *
 * The leftover check at the end is the one that matters most: a Disclosure whose
 * digest appears NOWHERE in the credential is a claim the issuer never signed.
 * Silently ignoring it — the natural implementation — is exactly how a holder
 * adds `"is_over_18": true` to their own credential.
 */
function resolveDisclosures(
  payload: Record<string, unknown>,
  byDigest: ReadonlyMap<string, ParsedDisclosure>
): Record<string, unknown> {
  const state: DisclosureWalkState = { byDigest, used: new Set<string>() };
  const disclosed = discloseObject(payload, state, 0);

  if (state.used.size !== byDigest.size) {
    throw rejectPresentation(
      'disclosure-digest-mismatch',
      'a presented Disclosure matches no digest in the credential; it was never signed by the issuer'
    );
  }

  return disclosed;
}

/**
 * Refuse a credential that made a §3.2.2.2 claim selectively disclosable.
 *
 * Compares the two payloads rather than inspecting Disclosures directly: the
 * top-level keys of the disclosed payload are the signed payload's keys (less
 * the `_sd` machinery) plus whatever the top-level `_sd` digests resolved to, so
 * a forbidden claim present AFTER the walk and absent BEFORE it can only have
 * arrived through a Disclosure. Doing it this way also keeps the check at the
 * top level only — the registered claims are properties of the SD-JWT payload,
 * and an application claim that happens to be named `exp` three levels down is
 * none of this rule's business.
 *
 * Runs on the verified payload, after the walk and before the returned claims
 * are assembled: nothing that reaches a caller has ever passed through here
 * unchecked.
 */
function assertNoForbiddenSelectiveDisclosure(
  signedPayload: Record<string, unknown>,
  disclosedPayload: Record<string, unknown>
): void {
  for (const claim of NON_SELECTIVELY_DISCLOSABLE_CLAIMS) {
    if (!Object.hasOwn(disclosedPayload, claim)) continue;
    if (Object.hasOwn(signedPayload, claim)) continue;

    throw rejectPresentation(
      'forbidden-selective-disclosure',
      `the credential makes '${claim}' selectively disclosable, which SD-JWT VC §3.2.2.2 forbids`
    );
  }
}

/** Read a numeric registered claim, rejecting a non-numeric one. */
function readNumericClaim(
  payload: Record<string, unknown>,
  claim: string,
  label: string
): number | undefined {
  const value = payload[claim];

  if (value === undefined) return undefined;

  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw rejectPresentation('malformed-presentation', `${label} '${claim}' is not a number`);
  }

  return value;
}

/**
 * Enforce the credential's validity window.
 *
 * Split into two outcomes rather than one "invalid period": an expired
 * credential means "come back with a fresh one", a not-yet-valid one usually
 * means a clock is wrong somewhere, and an operator debugging a wallet
 * integration cannot tell those apart from a single reason code.
 */
function assertWithinValidityWindow(
  window: CredentialValidityWindow,
  nowSeconds: number,
  toleranceSeconds: number
): void {
  if (window.expiresAt !== undefined && nowSeconds - toleranceSeconds >= window.expiresAt) {
    throw rejectPresentation('credential-expired', `the credential expired at ${window.expiresAt}`);
  }

  if (window.notBefore !== undefined && nowSeconds + toleranceSeconds < window.notBefore) {
    throw rejectPresentation(
      'credential-not-yet-valid',
      `the credential is not valid before ${window.notBefore}`
    );
  }
}

/** Pull the holder's confirmation JWK out of the credential's `cnf`. */
function readConfirmationJwk(payload: Record<string, unknown>): JWK {
  const cnf = payload['cnf'];

  if (!isPlainObject(cnf)) {
    throw rejectPresentation(
      'holder-binding-invalid',
      "the credential carries no 'cnf', so it is not bound to a holder key"
    );
  }

  const jwk = cnf['jwk'];

  if (!isPlainObject(jwk)) {
    throw rejectPresentation(
      'holder-binding-invalid',
      "the credential's 'cnf' carries no 'jwk'; no other confirmation method is supported"
    );
  }

  return jwk as JWK;
}

/** The outcome of Key Binding JWT verification. */
interface VerifiedKeyBinding {
  readonly algorithm: JwsAlgorithm;
}

/**
 * Verify the Key Binding JWT against the credential's `cnf` key (SD-JWT §4.3).
 *
 * Every failure here is `holder-binding-invalid`. That is deliberate: `aud`,
 * `nonce` and `sd_hash` are all OUR parameters, and telling a caller which one
 * it got wrong turns this into an oracle for the request it is trying to forge.
 */
async function verifyKeyBinding(
  split: SplitPresentation,
  confirmationJwk: JWK,
  context: PresentationValidationContext,
  nowSeconds: number,
  toleranceSeconds: number,
  hashAlgorithm: string
): Promise<VerifiedKeyBinding> {
  const segments = split.keyBindingJwt.split('.');

  if (segments.length !== 3) {
    throw rejectPresentation('holder-binding-invalid', 'the Key Binding JWT is not a compact JWS');
  }

  const header = decodeJoseSegment(segments[0], 'the Key Binding JWT header');
  const algorithm = readPermittedAlgorithm(
    header,
    context.signatureAlgorithms,
    'the Key Binding JWT'
  );

  if (header['typ'] !== KEY_BINDING_JWT_TYP) {
    throw rejectPresentation(
      'holder-binding-invalid',
      `the Key Binding JWT declares typ '${String(header['typ'])}' rather than '${KEY_BINDING_JWT_TYP}'`
    );
  }

  let holderKey;

  try {
    holderKey = await importPublicSigningJwk(confirmationJwk, algorithm);
  } catch (error) {
    throw rejectPresentation(
      'holder-binding-invalid',
      "the credential's confirmation key is unusable with the Key Binding JWT's algorithm",
      error
    );
  }

  let payload: Record<string, unknown>;

  try {
    const verified = await compactVerify(split.keyBindingJwt, holderKey, {
      algorithms: [algorithm],
    });
    payload = JSON.parse(Buffer.from(verified.payload).toString('utf8')) as Record<string, unknown>;
  } catch (error) {
    throw rejectPresentation(
      'holder-binding-invalid',
      'the Key Binding JWT does not verify against the credential confirmation key',
      error
    );
  }

  if (!isPlainObject(payload)) {
    throw rejectPresentation(
      'holder-binding-invalid',
      'the Key Binding JWT payload is not an object'
    );
  }

  const audience = payload['aud'];
  const audiences = typeof audience === 'string' ? [audience] : audience;

  if (
    !Array.isArray(audiences) ||
    !audiences.some(
      (candidate) =>
        typeof candidate === 'string' && constantTimeEquals(candidate, context.clientId)
    )
  ) {
    throw rejectPresentation(
      'holder-binding-invalid',
      'the Key Binding JWT was not made for this Verifier'
    );
  }

  const nonce = payload['nonce'];

  if (typeof nonce !== 'string' || !constantTimeEquals(nonce, context.nonce)) {
    throw rejectPresentation(
      'holder-binding-invalid',
      'the Key Binding JWT does not carry this request nonce'
    );
  }

  const sdHash = payload['sd_hash'];
  const expectedSdHash = createHash(hashAlgorithm)
    .update(split.keyBindingInput, 'ascii')
    .digest('base64url');

  if (typeof sdHash !== 'string' || !constantTimeEquals(sdHash, expectedSdHash)) {
    throw rejectPresentation(
      'holder-binding-invalid',
      'the Key Binding JWT sd_hash does not cover the presented credential and Disclosures'
    );
  }

  const issuedAt = payload['iat'];

  if (typeof issuedAt !== 'number' || !Number.isFinite(issuedAt)) {
    throw rejectPresentation(
      'holder-binding-invalid',
      "the Key Binding JWT carries no numeric 'iat'"
    );
  }

  if (issuedAt - toleranceSeconds > nowSeconds) {
    throw rejectPresentation(
      'holder-binding-invalid',
      'the Key Binding JWT is issued in the future'
    );
  }

  const maxAge = context.keyBindingMaxAgeSeconds ?? DEFAULT_KEY_BINDING_MAX_AGE_SECONDS;

  if (nowSeconds - issuedAt > maxAge + toleranceSeconds) {
    throw rejectPresentation(
      'holder-binding-invalid',
      `the Key Binding JWT is older than the ${maxAge}s ceiling`
    );
  }

  return { algorithm };
}

/**
 * Convert a confirmed issuer identity into the nominal {@link ValidatedIssuer}
 * that #236's trust gate accepts.
 *
 * This is the seam where a cryptographic guarantee becomes a type, and it is
 * only reachable AFTER the Issuer-signed JWS verified under the resolved key —
 * which is the entire precondition `fromValidatedPresentation` documents.
 *
 * Its own refusal (a non-canonicalizable identifier) is re-thrown as this
 * module's rejection type so that callers have exactly one error contract. The
 * client-facing error is identical either way, by construction.
 */
function assertValidatedIssuer(
  identifier: string,
  keyResolution: IssuerKeyResolutionMethod
): ValidatedIssuer {
  try {
    return ValidatedIssuer.fromValidatedPresentation({ identifier, keyResolution });
  } catch (error) {
    throw rejectPresentation(
      'issuer-key-unresolvable',
      'key resolution returned an issuer identifier that is not a usable issuer identity',
      error
    );
  }
}

/**
 * Check the credential type against what the DCQL Credential Query asked for.
 *
 * Fail-CLOSED when the query carries no `vct_values`: `buildCredentialQuery`
 * refuses to emit such a query, so its absence means the stored query was
 * tampered with or a migration went wrong — neither is a reason to accept an
 * unconstrained credential type.
 */
function assertRequestedCredentialType(vct: string, query: DcqlCredentialQuery): void {
  const values = query.meta?.['vct_values'];

  if (!Array.isArray(values) || values.length === 0) {
    throw rejectPresentation(
      'malformed-presentation',
      `Credential Query '${query.id}' constrains no 'vct_values'; refusing rather than accepting any credential type`
    );
  }

  if (!values.some((candidate) => candidate === vct)) {
    throw rejectPresentation(
      'malformed-presentation',
      `the credential's vct is not one Credential Query '${query.id}' asked for`
    );
  }
}

/**
 * Validate one SD-JWT VC Presentation.
 *
 * @param presentation - the compact serialization, exactly as the wallet sent it.
 * @param queryId - the DCQL Credential Query id it answers.
 * @param query - that Credential Query, for the `vct` constraint it carries.
 * @param context - bindings and policy — see {@link PresentationValidationContext}.
 * @returns the {@link ValidatedCredential} — a cryptographic finding, NOT an identity.
 * @throws PresentationValidationRejection on every refusal, carrying a distinct
 * server-side reason and the single non-enumerating client error.
 */
export async function validateSdJwtVcPresentation(
  presentation: string,
  queryId: string,
  query: DcqlCredentialQuery,
  context: PresentationValidationContext
): Promise<ValidatedCredential> {
  if (context.signatureAlgorithms.length === 0) {
    throw rejectPresentation(
      'malformed-presentation',
      'no signature algorithms are permitted, so no Presentation can be verified'
    );
  }

  // The two holder-binding parameters are compared with `constantTimeEquals`,
  // and two empty strings compare EQUAL. So an empty `client_id` or `nonce`
  // would not weaken the audience/freshness checks — it would delete them, and
  // any Presentation carrying an empty `aud`/`nonce` (or one a caller could
  // simply omit from its own request) would pass them. A context that cannot
  // bind is refused before anything is parsed, which is what makes
  // `PresentationValidationContext`'s "no default can silently disable a check"
  // true of the code rather than only of its documentation.
  if (context.clientId.length === 0 || context.nonce.length === 0) {
    throw rejectPresentation(
      'holder-binding-invalid',
      'the validation context carries an empty client_id or nonce, so the Key Binding JWT would be bound to nothing'
    );
  }

  const split = splitPresentation(presentation);
  const jwtSegments = split.issuerSignedJwt.split('.');

  if (jwtSegments.length !== 3) {
    throw rejectPresentation(
      'malformed-presentation',
      'the Issuer-signed JWT is not a compact JWS'
    );
  }

  const header = decodeJoseSegment(jwtSegments[0], 'the Issuer-signed JWT header');
  const algorithm = readPermittedAlgorithm(header, context.signatureAlgorithms, 'the credential');

  if (header['typ'] !== SD_JWT_VC_TYP) {
    throw rejectPresentation(
      'malformed-presentation',
      `the Issuer-signed JWT declares typ '${String(header['typ'])}' rather than '${SD_JWT_VC_TYP}'`
    );
  }

  const unverifiedPayload = decodeJoseSegment(jwtSegments[1], 'the Issuer-signed JWT payload');
  const claimedIssuer = unverifiedPayload['iss'];

  if (typeof claimedIssuer !== 'string' || claimedIssuer.length === 0) {
    throw rejectPresentation('malformed-presentation', "the credential carries no 'iss'");
  }

  const keyId = header['kid'];
  const certificateChain = readCertificateChain(header);
  let resolved;

  try {
    resolved = await context.resolveIssuerKey({
      issuer: claimedIssuer,
      algorithm,
      ...(typeof keyId === 'string' ? { keyId } : {}),
      ...(certificateChain === undefined ? {} : { x5c: certificateChain }),
    });
  } catch (error) {
    // Contained, exactly as `assertIssuerTrusted` contains a TrustRegistry
    // backend that throws: a resolver that cannot answer has established
    // nothing, and an escaping exception would be a 500 where every other
    // outcome is a uniform 401.
    throw rejectPresentation('issuer-key-unresolvable', 'the issuer key resolver failed', error);
  }

  if (resolved === undefined) {
    throw rejectPresentation(
      'issuer-key-unresolvable',
      'no verification key could be resolved for the issuer this credential claims'
    );
  }

  let verifiedPayload: Record<string, unknown>;

  try {
    const verified = await compactVerify(split.issuerSignedJwt, resolved.key, {
      algorithms: [algorithm],
    });
    verifiedPayload = JSON.parse(Buffer.from(verified.payload).toString('utf8')) as Record<
      string,
      unknown
    >;
  } catch (error) {
    throw rejectPresentation(
      'issuer-signature-invalid',
      'the Issuer-signed JWS does not verify under the resolved issuer key',
      error
    );
  }

  if (!isPlainObject(verifiedPayload)) {
    throw rejectPresentation(
      'malformed-presentation',
      'the verified credential payload is not an object'
    );
  }

  // From here on ONLY the verified payload is read. The unverified copy above
  // existed solely to find a key, and nothing it said is trusted.
  //
  // Including its `iss`: the key was looked up under an UNVERIFIED issuer, so
  // the identity the resolver confirmed is re-checked against the issuer the
  // SIGNED payload claims. Without this the two could diverge — a resolver with
  // a bug, or one keyed on `kid` alone, could confirm identity A for a
  // credential asserting identity B, and #236 would then make its trust
  // decision about the wrong issuer while the claims came from another.
  const confirmedIssuer = canonicalizeIssuerIdentifier(resolved.identifier);
  const signedIssuer = canonicalizeIssuerIdentifier(verifiedPayload['iss']);

  if (
    confirmedIssuer === undefined ||
    signedIssuer === undefined ||
    confirmedIssuer !== signedIssuer
  ) {
    throw rejectPresentation(
      'issuer-signature-invalid',
      'key resolution confirmed an issuer identity that is not the one the signed credential claims'
    );
  }

  const vct = verifiedPayload['vct'];

  if (typeof vct !== 'string' || vct.length === 0) {
    throw rejectPresentation('malformed-presentation', "the credential carries no 'vct'");
  }

  assertRequestedCredentialType(vct, query);

  const sdAlgClaim = verifiedPayload['_sd_alg'] ?? DEFAULT_SD_HASH_ALGORITHM;

  if (typeof sdAlgClaim !== 'string' || !Object.hasOwn(SD_HASH_ALGORITHMS, sdAlgClaim)) {
    throw rejectPresentation(
      'malformed-presentation',
      `'_sd_alg' names an unsupported hash algorithm (supported: ${Object.keys(SD_HASH_ALGORITHMS).join(', ')})`
    );
  }

  const hashAlgorithm = SD_HASH_ALGORITHMS[sdAlgClaim];
  const toleranceSeconds =
    context.clockToleranceSeconds ?? DEFAULT_PRESENTATION_CLOCK_TOLERANCE_SECONDS;
  const nowSeconds = Math.floor((context.now ?? new Date()).getTime() / 1000);

  const notBefore = readNumericClaim(verifiedPayload, 'nbf', 'the credential');
  const expiresAt = readNumericClaim(verifiedPayload, 'exp', 'the credential');
  const issuedAt = readNumericClaim(verifiedPayload, 'iat', 'the credential');

  const validity: CredentialValidityWindow = {
    ...(notBefore === undefined ? {} : { notBefore }),
    ...(expiresAt === undefined ? {} : { expiresAt }),
    ...(issuedAt === undefined ? {} : { issuedAt }),
  };

  assertWithinValidityWindow(validity, nowSeconds, toleranceSeconds);

  const confirmationJwk = readConfirmationJwk(verifiedPayload);
  const byDigest = parseDisclosures(split.disclosures, hashAlgorithm);
  const disclosedPayload = resolveDisclosures(verifiedPayload, byDigest);

  assertNoForbiddenSelectiveDisclosure(verifiedPayload, disclosedPayload);

  const keyBinding = await verifyKeyBinding(
    split,
    confirmationJwk,
    context,
    nowSeconds,
    toleranceSeconds,
    hashAlgorithm
  );

  const issuer = assertValidatedIssuer(resolved.identifier, resolved.keyResolution);

  const claims: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(disclosedPayload)) {
    if (STRIPPED_CREDENTIAL_CLAIMS.includes(key)) continue;
    claims[key] = value;
  }

  return {
    queryId,
    format: SD_JWT_VC_TYP,
    credentialType: vct,
    issuer,
    claims: Object.freeze(claims),
    validity: Object.freeze(validity),
    assurance: Object.freeze({
      credentialType: vct,
      issuerKeyResolution: resolved.keyResolution,
      issuerSignatureAlgorithm: algorithm,
      keyBindingAlgorithm: keyBinding.algorithm,
      disclosedClaimCount: byDigest.size,
      statusChecked: false,
    }),
  };
}
