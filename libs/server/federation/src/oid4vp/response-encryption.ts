/**
 * Encrypted Authorization Responses — the `direct_post.jwt` intake and the
 * at-rest handling of the key that decrypts them (issue #377 Phase C, HAIP §5).
 *
 * HAIP 1.0 §5.1 mandates `direct_post.jwt`, and §5 mandates that the Verifier
 * *"supply ephemeral encryption public keys specific to each Authorization
 * Request"*. That one word — specific — is the whole design: the pair is minted
 * per request, published in `client_metadata`, and thrown away with the request
 * state. There is nothing here for an operator to provision, which is why the
 * deployment's ability to run this path is a property of the BUILD rather than
 * of the configuration (see `deriveCryptoCapabilities` in `apps/auth-server`).
 *
 * ## Correlation, and why it is the `kid`
 *
 * Under `direct_post` the wallet echoes the `state` in the clear and that is the
 * lookup key. Under `direct_post.jwt` there is no cleartext anything: the whole
 * response is ONE `response` parameter carrying a JWE. The only request-scoped
 * value the wallet is REQUIRED to expose outside the ciphertext is the JWE
 * `kid` — OID4VP 1.0 §8.3: *"If the selected public key contains a `kid`
 * parameter, the JWE MUST include the same value in the `kid` JWE Header
 * Parameter ... This enables the Verifier to easily identify the specific public
 * key that was used to encrypt the response."* — and §5.1 requires every
 * published JWK to carry one. So the `kid` is guaranteed present and
 * request-scoped, and it is read BEFORE decryption to find the row.
 *
 * Two consequences, both load-bearing:
 *
 *  1. §5.1 promises uniqueness only *"within the context of the request"*, which
 *     is not enough to key a table. QAuth mints its own from 128 bits of CSPRNG
 *     output and enforces global uniqueness in the schema — never a counter,
 *     never a function of the `state`.
 *  2. The `kid` is ATTACKER-CONTROLLED. OID4VP 1.0 §14.5: *"Because an encrypted
 *     Authorization Response has no additional integrity protection, an attacker
 *     might be able to alter Authorization Response parameters and generate a
 *     new encrypted Authorization Response for the Verifier."* It is therefore
 *     an OPAQUE INDEX and nothing else — a wrong value finds no row and is
 *     refused, and no trust is ever derived from it. The binding that IS trusted
 *     is the `state` inside the decrypted payload, checked against the row
 *     (§5.3 makes the request/response `state` binding a MUST).
 *
 * The alternative designs were considered and refused. A per-request
 * `response_uri` invents a URL space and leaks the correlator into access logs
 * and referrers; trial-decrypting against every live key turns an unauthenticated
 * POST into unbounded ECDH work.
 *
 * ## The private half at rest
 *
 * No specification requires protecting it — OID4VP, HAIP and RFC 7516/7518/9101
 * are silent — so it is stored PLAINLY by default, beside the `nonce` that is
 * already in the clear on the same row for its own stated reason. What this
 * module adds is an OPT-IN envelope for deployments whose threat model includes
 * a read-only database leak, keyed by one operator-supplied secret and bounded
 * to this one column. It is deliberately not a general column-encryption
 * framework.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html §5.1, §8.3, §14.5
 */

import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto';

import {
  decryptJwe,
  importEncryptionPrivateJwk,
  JWE_CONTENT_ENCRYPTION_ALGORITHMS,
  JWE_KEY_AGREEMENT_ALGORITHMS,
} from '@qauth-labs/core-crypto';
import { decodeProtectedHeader, type JWK } from 'jose';

import { MAX_VP_TOKEN_LENGTH, Oid4vpTransportRejection } from './direct-post';
import { hashOid4vpState } from './request-state';

/**
 * `enc` values QAuth advertises in `encrypted_response_enc_values_supported`
 * (OID4VP 1.0 §5.1).
 *
 * Taken from the crypto layer's own allowlist rather than restated, so the set a
 * wallet is told to pick from is BY CONSTRUCTION the set `decryptJwe` will
 * accept. Advertising an algorithm the decrypt path pins away would produce a
 * response QAuth asked for and cannot open.
 */
export const OID4VP_ENCRYPTED_RESPONSE_ENC_VALUES: readonly string[] = Object.freeze([
  ...JWE_CONTENT_ENCRYPTION_ALGORITHMS,
]);

/**
 * Bound on the `response` parameter accepted at the edge.
 *
 * The same reasoning as {@link MAX_VP_TOKEN_LENGTH}, one layer out: the endpoint
 * is unauthenticated by construction, so nothing but this stands between an
 * anonymous POST and a JOSE parse. Sized above the `vp_token` bound because the
 * ciphertext CONTAINS a `vp_token` plus base64 and AEAD overhead — a bound below
 * it would refuse responses to requests QAuth itself is willing to accept.
 */
export const MAX_ENCRYPTED_RESPONSE_LENGTH = MAX_VP_TOKEN_LENGTH + 16 * 1024;

/**
 * Bound on the `kid` read out of an untrusted JWE protected header.
 *
 * Matches the `response_encryption_kid` column width. QAuth's own kid is 22
 * characters (128 bits, base64url); anything materially longer is not a value
 * this Verifier ever published, so it is refused before it reaches a query.
 */
export const MAX_ENCRYPTION_KID_LENGTH = 64;

/** How the ephemeral private JWK is stored at rest. */
export type Oid4vpEphemeralKeyProtection = 'plain' | 'aes-256-gcm';

/** The default: the JWK document itself, unwrapped. */
export const EPHEMERAL_KEY_PROTECTION_PLAIN = 'plain' satisfies Oid4vpEphemeralKeyProtection;

/** The opt-in envelope, used only when the deployment supplies a secret. */
export const EPHEMERAL_KEY_PROTECTION_AES_256_GCM =
  'aes-256-gcm' satisfies Oid4vpEphemeralKeyProtection;

/** Required length of the opt-in at-rest secret, in bytes. */
export const EPHEMERAL_KEY_PROTECTION_SECRET_BYTES = 32;

/** AES-GCM nonce length in bytes — the 96 bits NIST SP 800-38D recommends. */
const GCM_IV_BYTES = 12;

/** AES-GCM authentication tag length in bytes. */
const GCM_TAG_BYTES = 16;

/**
 * Envelope version prefix.
 *
 * Present so a future scheme can be introduced without a reader having to guess
 * from the shape of the payload which one it is looking at, and so an envelope
 * written by a newer build is REFUSED by an older one rather than misparsed.
 */
const ENVELOPE_VERSION = '1';

/**
 * The Authorization Response parameters carried INSIDE the JWE
 * (OID4VP 1.0 §8.3).
 *
 * Note `vpToken` is the ENCODED form: the payload is JSON, so a conformant
 * wallet sends `vp_token` as a JSON object rather than as the JSON *string* the
 * form-encoded mode carries. It is re-serialized here so exactly one structural
 * parser (`parseVpToken`) sees it, on both response modes.
 */
export interface EncryptedAuthorizationResponse {
  /** The `state` from the request. REQUIRED — §5.3 makes the binding a MUST. */
  readonly state: string;
  /** JSON-encoded `vp_token`, when the wallet answered with one. */
  readonly vpToken: string | undefined;
  /** Wallet-reported error code (§8.2), when it refused instead. */
  readonly error: string | undefined;
}

/**
 * Read the `kid` out of an encrypted Authorization Response WITHOUT decrypting
 * it (OID4VP 1.0 §8.3).
 *
 * Every byte this touches is attacker-supplied, and the function is written to
 * be honest about that: it bounds the input, parses only the protected header,
 * and returns an opaque string. It performs no key operation, so a flood of
 * garbage costs a base64 decode and a JSON parse rather than an ECDH.
 *
 * The returned value is a LOOKUP INDEX and nothing more. See the module JSDoc
 * for why (§14.5) — nothing downstream may treat a matching `kid` as evidence
 * that the response belongs to the request it found.
 *
 * @param response - the raw `response` form parameter.
 * @returns the `kid`, bounded and non-empty.
 * @throws Oid4vpTransportRejection when the parameter is oversized, not a JOSE
 * object, or carries no usable `kid`.
 */
export function readEncryptedResponseKid(response: string): string {
  if (response.length > MAX_ENCRYPTED_RESPONSE_LENGTH) {
    throw new Oid4vpTransportRejection(
      `encrypted response exceeds the ${MAX_ENCRYPTED_RESPONSE_LENGTH}-character bound`
    );
  }

  let header: Record<string, unknown>;

  try {
    header = decodeProtectedHeader(response) as Record<string, unknown>;
  } catch {
    throw new Oid4vpTransportRejection('encrypted response has no readable JOSE protected header');
  }

  const kid = header['kid'];

  if (typeof kid !== 'string' || kid.length === 0) {
    throw new Oid4vpTransportRejection(
      "encrypted response carries no 'kid' JWE header parameter (OID4VP 1.0 §8.3)"
    );
  }

  if (kid.length > MAX_ENCRYPTION_KID_LENGTH) {
    throw new Oid4vpTransportRejection(
      `encrypted response 'kid' exceeds the ${MAX_ENCRYPTION_KID_LENGTH}-character bound`
    );
  }

  return kid;
}

/**
 * Decrypt an Authorization Response and read its parameters (§8.3).
 *
 * The algorithm pins come from the crypto layer's allowlists, so the JWE's own
 * `alg`/`enc` are compared against policy and never used to select a primitive.
 * Every failure — wrong key, tampered ciphertext, refused algorithm, malformed
 * payload — is normalized into the ONE non-enumerating transport rejection, with
 * the specific cause carried for the server log only.
 *
 * @param response - the raw `response` form parameter.
 * @param privateJwk - this request's ephemeral private JWK, already unwrapped
 * from its at-rest form.
 * @returns the Authorization Response parameters. UNVERIFIED: the `state` still
 * has to be checked against the row (see
 * {@link assertEncryptedResponseStateMatches}).
 * @throws Oid4vpTransportRejection on any failure.
 */
export async function decryptOid4vpAuthorizationResponse(
  response: string,
  privateJwk: JWK
): Promise<EncryptedAuthorizationResponse> {
  if (response.length > MAX_ENCRYPTED_RESPONSE_LENGTH) {
    throw new Oid4vpTransportRejection(
      `encrypted response exceeds the ${MAX_ENCRYPTED_RESPONSE_LENGTH}-character bound`
    );
  }

  let payload: Record<string, unknown>;

  try {
    const privateKey = await importEncryptionPrivateJwk(privateJwk);
    ({ payload } = await decryptJwe(response, privateKey, {
      keyManagementAlgorithms: JWE_KEY_AGREEMENT_ALGORITHMS,
      contentEncryptionAlgorithms: JWE_CONTENT_ENCRYPTION_ALGORITHMS,
    }));
  } catch (error) {
    throw new Oid4vpTransportRejection(
      `encrypted response did not decrypt (${error instanceof Error ? error.message : 'unknown failure'})`
    );
  }

  const state = payload['state'];

  if (typeof state !== 'string' || state.length === 0) {
    // §5.3 makes echoing `state` a MUST, and it is the ONLY thing binding this
    // ciphertext to the request whose key opened it. A response without one is
    // refused rather than accepted on the strength of the `kid` that found the
    // row — see §14.5 in the module JSDoc.
    throw new Oid4vpTransportRejection(
      "decrypted Authorization Response carries no 'state' (OID4VP 1.0 §5.3)"
    );
  }

  const error = payload['error'];
  const rawVpToken = payload['vp_token'];

  return {
    state,
    // The JWE payload is JSON, so a conformant wallet sends `vp_token` as an
    // OBJECT. The string form is accepted too — it is what a wallet that reused
    // its form-encoding path emits, it is unambiguous, and refusing it would buy
    // no security while breaking interoperability. Either way exactly one
    // structural parser sees the result.
    vpToken:
      typeof rawVpToken === 'string'
        ? rawVpToken
        : rawVpToken === undefined || rawVpToken === null
          ? undefined
          : JSON.stringify(rawVpToken),
    error: typeof error === 'string' && error.length > 0 ? error : undefined,
  };
}

/**
 * Bind a decrypted response to the request state its `kid` found (§5.3).
 *
 * This is the check the `kid` cannot make. An encrypted Authorization Response
 * has no integrity protection tying it to a request (§14.5), so until this
 * passes, all that is known is that SOMEONE encrypted something to a key QAuth
 * published — which anyone who read `client_metadata` could do.
 *
 * Compared as digests, and time-safely: the stored column is a digest, the
 * incoming `state` is a bearer credential, and a byte-wise early exit on the
 * comparison of the two would leak the stored value one character at a time to a
 * caller who can already choose the plaintext.
 *
 * @param state - the `state` from the decrypted payload.
 * @param expectedStateHash - `state_hash` from the redeemed row.
 * @throws Oid4vpTransportRejection when they do not match.
 */
export function assertEncryptedResponseStateMatches(
  state: string,
  expectedStateHash: string
): void {
  const presented = Buffer.from(hashOid4vpState(state), 'utf8');
  const expected = Buffer.from(expectedStateHash, 'utf8');

  if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) {
    throw new Oid4vpTransportRejection(
      "decrypted Authorization Response carries a 'state' that is not the one this request was issued with (OID4VP 1.0 §5.3)"
    );
  }
}

/**
 * Narrow an untrusted at-rest marker to a scheme this build can read.
 *
 * Fail-closed: an unrecognised value yields `undefined` and the caller refuses,
 * rather than defaulting to `plain` and handing a ciphertext to a JSON parser.
 *
 * @param value - the `response_encryption_key_protection` column.
 */
export function parseEphemeralKeyProtection(
  value: string | null | undefined
): Oid4vpEphemeralKeyProtection | undefined {
  if (value === EPHEMERAL_KEY_PROTECTION_PLAIN) return EPHEMERAL_KEY_PROTECTION_PLAIN;
  if (value === EPHEMERAL_KEY_PROTECTION_AES_256_GCM) return EPHEMERAL_KEY_PROTECTION_AES_256_GCM;
  return undefined;
}

/** A serialized ephemeral private JWK plus the marker saying how to read it. */
export interface ProtectedEphemeralKey {
  /** The value for `response_encryption_private_jwk`. */
  readonly value: string;
  /** The value for `response_encryption_key_protection`. */
  readonly protection: Oid4vpEphemeralKeyProtection;
}

/** Inputs shared by {@link protectEphemeralKey} and {@link unprotectEphemeralKey}. */
export interface EphemeralKeyProtectionOptions {
  /**
   * The row's `kid`, bound into the envelope as Additional Authenticated Data.
   *
   * Not decoration: without it an operator with write access to the table could
   * move one row's ciphertext onto another row, and the AEAD would happily open
   * it. With it, a relocated envelope fails to authenticate.
   */
  readonly kid: string;
  /**
   * The deployment's at-rest secret, or `undefined` when it configured none —
   * which is the default and selects {@link EPHEMERAL_KEY_PROTECTION_PLAIN}.
   */
  readonly secret?: Uint8Array | undefined;
}

/** Refuse a secret that is not exactly one AES-256 key. */
function assertSecretUsable(secret: Uint8Array): void {
  if (secret.length !== EPHEMERAL_KEY_PROTECTION_SECRET_BYTES) {
    throw new Error(
      `The OID4VP ephemeral-key at-rest secret must be exactly ${EPHEMERAL_KEY_PROTECTION_SECRET_BYTES} bytes (AES-256); received ${secret.length}.`
    );
  }
}

/**
 * Serialize an ephemeral private JWK for storage, encrypting it when — and only
 * when — the deployment supplied a secret.
 *
 * @param jwk - the private JWK from `exportEncryptionPrivateJwk`.
 * @param options - see {@link EphemeralKeyProtectionOptions}.
 * @returns the column value and the marker that says how to read it back.
 * @throws Error when a supplied secret is the wrong length — a CONFIGURATION
 * fault, raised loudly rather than silently falling back to plaintext.
 */
export function protectEphemeralKey(
  jwk: JWK,
  options: EphemeralKeyProtectionOptions
): ProtectedEphemeralKey {
  const serialized = JSON.stringify(jwk);

  if (options.secret === undefined) {
    return { value: serialized, protection: EPHEMERAL_KEY_PROTECTION_PLAIN };
  }

  assertSecretUsable(options.secret);

  const iv = randomBytes(GCM_IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', options.secret, iv, {
    authTagLength: GCM_TAG_BYTES,
  });
  cipher.setAAD(Buffer.from(options.kid, 'utf8'));

  const ciphertext = Buffer.concat([cipher.update(serialized, 'utf8'), cipher.final()]);

  return {
    value: [
      ENVELOPE_VERSION,
      iv.toString('base64url'),
      ciphertext.toString('base64url'),
      cipher.getAuthTag().toString('base64url'),
    ].join('.'),
    protection: EPHEMERAL_KEY_PROTECTION_AES_256_GCM,
  };
}

/**
 * Read a stored ephemeral private JWK back, using the marker the row carries
 * rather than the deployment's CURRENT setting.
 *
 * That distinction is the reason the marker exists at all: turning the opt-in on
 * or off is a config change, and rows written moments before it must stay
 * readable for the few minutes they remain redeemable.
 *
 * @param stored - the `response_encryption_private_jwk` column.
 * @param protection - the row's marker, already narrowed.
 * @param options - see {@link EphemeralKeyProtectionOptions}.
 * @returns the private JWK.
 * @throws Error when the row cannot be read with the configured secret. The
 * caller renders this as the uniform transport refusal: it is a server-side
 * data or configuration failure, and it is only reachable AFTER redemption, so
 * distinguishing it on the wire would be an oracle for a live `state`.
 */
export function unprotectEphemeralKey(
  stored: string,
  protection: Oid4vpEphemeralKeyProtection,
  options: EphemeralKeyProtectionOptions
): JWK {
  if (protection === EPHEMERAL_KEY_PROTECTION_PLAIN) {
    return parseStoredJwk(stored);
  }

  if (options.secret === undefined) {
    throw new Error(
      'This request state stores its ephemeral encryption key encrypted, and no at-rest secret is configured. The secret that wrote it must stay configured until every row written under it has expired.'
    );
  }

  assertSecretUsable(options.secret);

  const parts = stored.split('.');

  if (parts.length !== 4 || parts[0] !== ENVELOPE_VERSION) {
    throw new Error(
      'Stored ephemeral encryption key is not a recognised at-rest envelope version.'
    );
  }

  const decipher = createDecipheriv(
    'aes-256-gcm',
    options.secret,
    Buffer.from(parts[1] as string, 'base64url'),
    { authTagLength: GCM_TAG_BYTES }
  );
  decipher.setAAD(Buffer.from(options.kid, 'utf8'));
  decipher.setAuthTag(Buffer.from(parts[3] as string, 'base64url'));

  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(parts[2] as string, 'base64url')),
    decipher.final(),
  ]).toString('utf8');

  return parseStoredJwk(plaintext);
}

/** Parse a stored JWK document, refusing anything that is not a JSON object. */
function parseStoredJwk(serialized: string): JWK {
  let parsed: unknown;

  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error('Stored ephemeral encryption key is not valid JSON.');
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Stored ephemeral encryption key is not a JSON object.');
  }

  return parsed as JWK;
}
