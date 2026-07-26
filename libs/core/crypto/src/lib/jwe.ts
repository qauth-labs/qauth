/**
 * Compact JWE encryption and decryption for the OID4VP `direct_post.jwt`
 * encrypted-response mode (#298, HAIP §5).
 *
 * Scope is deliberately ONE cipher suite: `ECDH-ES` (direct key agreement) on
 * P-256, with `A128GCM` or `A256GCM` content encryption. That is exactly what
 * the profile mandates, and every algorithm outside it — key wrapping, `dir`,
 * `RSA1_5`, the AES-CBC-HMAC family — stays unreachable rather than
 * merely discouraged. A JWE stack is only as strong as its narrowest
 * allowlist.
 */
import { compactDecrypt, CompactEncrypt, type CompactJWEHeaderParameters } from 'jose';

import {
  JWE_CONTENT_ENCRYPTION_ALGORITHMS,
  JWE_KEY_AGREEMENT_ALGORITHMS,
  type JweContentEncryptionAlgorithm,
  type JweKeyAgreementAlgorithm,
} from './algorithms';
import type { EncryptionKey } from './encryption-keys';
import { CryptoDecryptionError } from './errors';

/**
 * Protected-header members a caller may NEVER supply via
 * {@link EncryptJweOptions.header}.
 *
 * The mirror of `RESERVED_PROTECTED_HEADER_MEMBERS` in `signing.ts`, and
 * reserved for the same class of reason — each one, if caller-controlled,
 * subverts an invariant this module is responsible for:
 *
 * - `alg` is pinned to `ECDH-ES`; a caller override is the algorithm-confusion
 *   lever.
 * - `enc` is owned by the typed {@link EncryptJweOptions.enc} field, so the
 *   allowlist check cannot be bypassed by writing it into the bag instead.
 * - `epk` is the EPHEMERAL public key the key agreement generates internally; a
 *   supplied one would either be ignored (and silently mislead) or, worse,
 *   substitute an attacker's contribution to the agreed secret.
 * - `crit` would impose must-understand semantics this layer does not implement.
 * - `zip` enables compression before encryption — the CRIME/BREACH shape, where
 *   ciphertext length leaks plaintext similarity. RFC 8725 §3.5 says do not.
 */
export const RESERVED_JWE_PROTECTED_HEADER_MEMBERS = ['alg', 'enc', 'epk', 'crit', 'zip'] as const;

/** Options for {@link encryptJwe}. */
export interface EncryptJweOptions {
  /**
   * Content encryption algorithm. REQUIRED and explicit — there is no default,
   * because "which AEAD did this deployment actually use" should be visible at
   * the call site rather than inherited from a library constant that can change
   * under it.
   */
  enc: JweContentEncryptionAlgorithm;
  /**
   * `kid` of the RECIPIENT's key, so the recipient can select the right private
   * half. For `direct_post.jwt` this is the `kid` of the per-request ephemeral
   * key the Verifier published in client metadata.
   */
  kid?: string;
  /**
   * Extra protected-header members. The members in
   * {@link RESERVED_JWE_PROTECTED_HEADER_MEMBERS} are REJECTED (never silently
   * dropped — a dropped header member the caller believes took effect is how a
   * header-injection bug becomes invisible).
   */
  header?: Record<string, unknown>;
}

/** Options for {@link decryptJwe}. */
export interface DecryptJweOptions {
  /**
   * Permitted JWE `alg` values. REQUIRED, non-empty, and every member must be in
   * {@link JWE_KEY_AGREEMENT_ALGORITHMS}.
   *
   * Required rather than defaulted for the same reason
   * `VerifyOptions.algorithms` is: the pin is the control, and a control with a
   * default is a control someone forgets to think about. The `alg` of the
   * INCOMING JWE is attacker-controlled and is only ever compared against this
   * list — never used to select a primitive.
   */
  keyManagementAlgorithms: readonly JweKeyAgreementAlgorithm[];
  /**
   * Permitted JWE `enc` values. REQUIRED, non-empty, and every member must be in
   * {@link JWE_CONTENT_ENCRYPTION_ALGORITHMS}. Same reasoning as above.
   */
  contentEncryptionAlgorithms: readonly JweContentEncryptionAlgorithm[];
}

/** A successfully decrypted JWE. */
export interface DecryptedJwe {
  /** The decrypted JSON payload. Authenticated by the AEAD tag. */
  payload: Record<string, unknown>;
  /**
   * The JWE PROTECTED header, authenticated as Additional Authenticated Data by
   * the AEAD tag. Returned only AFTER decryption succeeds, so it can never be
   * confused with the unverified header of an undecrypted token.
   */
  protectedHeader: Record<string, unknown>;
}

/**
 * Reject a caller-supplied protected header carrying a reserved member.
 *
 * @throws Error naming the offending member.
 */
function assertNoReservedJweHeaderMembers(header: Record<string, unknown>): void {
  for (const member of RESERVED_JWE_PROTECTED_HEADER_MEMBERS) {
    if (Object.hasOwn(header, member)) {
      throw new Error(
        `JWE protected-header member '${member}' is reserved and cannot be set via ` +
          `EncryptJweOptions.header (reserved: ${RESERVED_JWE_PROTECTED_HEADER_MEMBERS.join(', ')}).`
      );
    }
  }
}

/**
 * Assert a caller-pinned algorithm list is non-empty and wholly inside this
 * library's allowlist.
 *
 * The EMPTY case matters more than it looks: `jose` treats an absent restriction
 * as "any algorithm", and an empty array is what a caller building the list from
 * config gets when the config is missing. Refusing it turns a
 * silently-unrestricted decrypt into a startup-visible error.
 *
 * @throws Error if the list is empty or contains an unsupported identifier.
 */
function assertPinnedAlgorithms(
  label: string,
  pinned: readonly string[],
  allowed: readonly string[]
): void {
  if (pinned.length === 0) {
    throw new Error(
      `DecryptJweOptions.${label} must list at least one algorithm; an empty list would ` +
        `place no restriction on the JWE at all.`
    );
  }
  for (const alg of pinned) {
    if (!allowed.includes(alg)) {
      throw new Error(
        `Unsupported JWE algorithm '${alg}' in ${label} (supported: ${allowed.join(', ')}).`
      );
    }
  }
}

/**
 * Encrypt a JSON payload into a compact JWE using `ECDH-ES` on P-256.
 *
 * A FRESH sender-ephemeral key pair is generated per call by the key agreement
 * and published as `epk` in the protected header; the agreed secret is used
 * directly as the content encryption key (RFC 7518 §4.6 direct mode). Two calls
 * with identical inputs therefore produce different ciphertexts, which is the
 * required behaviour, not an inconvenience.
 *
 * @param payload - JSON payload (for `direct_post.jwt`, the Authorization
 * Response parameters).
 * @param recipientPublicKey - Recipient's `ECDH-ES` P-256 public key.
 * @param options - See {@link EncryptJweOptions}.
 * @returns The compact JWE (five dot-separated segments).
 * @throws Error if `enc` is unsupported or `options.header` carries a reserved
 * member.
 */
export async function encryptJwe(
  payload: Record<string, unknown>,
  recipientPublicKey: EncryptionKey,
  options: EncryptJweOptions
): Promise<string> {
  // Runtime allowlist check as well as the compile-time union: this is a public
  // API of a security library and a JS caller (or a value crossing a JSON
  // boundary) is not type-checked.
  if (!JWE_CONTENT_ENCRYPTION_ALGORITHMS.includes(options.enc)) {
    throw new Error(
      `Unsupported JWE content encryption algorithm '${options.enc}' ` +
        `(supported: ${JWE_CONTENT_ENCRYPTION_ALGORITHMS.join(', ')}).`
    );
  }
  const extraHeader = options.header ?? {};
  assertNoReservedJweHeaderMembers(extraHeader);

  const protectedHeader: CompactJWEHeaderParameters = {
    ...extraHeader,
    ...(options.kid !== undefined ? { kid: options.kid } : {}),
    // `alg` and `enc` are spread LAST so the canonical values always win —
    // belt-and-braces behind the reserved-member rejection above.
    alg: 'ECDH-ES',
    enc: options.enc,
  };

  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader(protectedHeader)
    .encrypt(recipientPublicKey);
}

/**
 * Decrypt a compact JWE produced by {@link encryptJwe} (or by any conformant
 * peer) and return its JSON payload.
 *
 * The caller's pinned `keyManagementAlgorithms` / `contentEncryptionAlgorithms`
 * are the ONLY thing that decides which primitives may run. The incoming JWE's
 * own `alg` / `enc` are attacker-controlled and are compared against those pins,
 * never consulted to choose a code path.
 *
 * Every failure throws {@link CryptoDecryptionError}. The CRYPTOGRAPHIC ones —
 * wrong key, tampered ciphertext or tag, rejected `alg`/`enc`, malformed
 * serialization — are mutually indistinguishable; see that class for why, and
 * for why the two post-decryption structural failures are allowed to differ.
 *
 * @param jwe - Compact JWE.
 * @param recipientPrivateKey - Recipient's `ECDH-ES` P-256 private key.
 * @param options - Pinned algorithms — see {@link DecryptJweOptions}.
 * @returns The decrypted payload and the AEAD-authenticated protected header.
 * @throws Error if the pinned algorithm lists are empty or name an unsupported
 * algorithm — a CONFIGURATION fault, raised before any ciphertext is touched and
 * kept distinct from {@link CryptoDecryptionError} so it cannot be mistaken for
 * a bad message.
 * @throws CryptoDecryptionError on any decryption failure.
 */
export async function decryptJwe(
  jwe: string,
  recipientPrivateKey: EncryptionKey,
  options: DecryptJweOptions
): Promise<DecryptedJwe> {
  assertPinnedAlgorithms(
    'keyManagementAlgorithms',
    options.keyManagementAlgorithms,
    JWE_KEY_AGREEMENT_ALGORITHMS
  );
  assertPinnedAlgorithms(
    'contentEncryptionAlgorithms',
    options.contentEncryptionAlgorithms,
    JWE_CONTENT_ENCRYPTION_ALGORITHMS
  );

  let plaintext: Uint8Array;
  let protectedHeader: Record<string, unknown>;
  try {
    const result = await compactDecrypt(jwe, recipientPrivateKey, {
      keyManagementAlgorithms: [...options.keyManagementAlgorithms],
      contentEncryptionAlgorithms: [...options.contentEncryptionAlgorithms],
    });
    plaintext = result.plaintext;
    protectedHeader = { ...result.protectedHeader };
  } catch (error) {
    throw toCryptoDecryptionError(error);
  }

  // Parsing is OUTSIDE the try above so a genuine crypto failure and a
  // structurally-wrong plaintext are never conflated in the `cause` chain — they
  // still surface as the same error to the caller.
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext));
  } catch (error) {
    throw new CryptoDecryptionError({ detail: 'payload is not valid JSON', cause: error });
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new CryptoDecryptionError({ detail: 'payload is not a JSON object' });
  }

  return { payload: parsed as Record<string, unknown>, protectedHeader };
}

/**
 * Normalize a `jose` JWE failure into a {@link CryptoDecryptionError},
 * retaining the backend message as `detail` for logs only.
 */
function toCryptoDecryptionError(error: unknown): CryptoDecryptionError {
  if (error instanceof Error) {
    return new CryptoDecryptionError({ detail: error.message, cause: error });
  }
  return new CryptoDecryptionError({ cause: error });
}
