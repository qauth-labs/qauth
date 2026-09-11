import {
  EPHEMERAL_KEY_PROTECTION_SECRET_BYTES,
  type Oid4vpEphemeralKeyProtection,
  parseEphemeralKeyProtection,
  protectEphemeralKey,
  unprotectEphemeralKey,
} from '@qauth-labs/fastify-plugin-federation';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import type { JWK } from 'jose';

import { env } from '../../config/env';

/**
 * The OPT-IN at-rest protection of the per-request ephemeral encryption key
 * (issue #377, Phase C).
 *
 * ## The default is plaintext, deliberately
 *
 * `oid4vp_request_states.response_encryption_private_jwk` holds the private half
 * of a per-request ECDH-ES pair. Nothing requires protecting it: OID4VP 1.0,
 * HAIP 1.0 and RFC 7516/7518/9101 are all silent on at-rest handling of a
 * Verifier's response-encryption key, and the column sits beside a `nonce` this
 * schema already stores in the clear for a documented reason. The key decrypts
 * exactly one presentation response, on a row that expires within minutes, and
 * the response it decrypts must still carry the matching `state` and must still
 * find the row unredeemed.
 *
 * So this is a switch a deployment turns ON, in the same idiom as
 * `WALLET_FEDERATION_ENABLED`, `HYBRID_SIGNING_ENABLED` and
 * `SIGNING_ALGORITHM_MODE` — not a default that silently hands every operator a
 * new key to manage.
 *
 * ## Why the ROW records the scheme
 *
 * Turning the secret on, off, or rotating it is a configuration change, and
 * in-flight requests outlive it. A reader that inferred the scheme from the
 * CURRENT setting would fail every row written moments before the change — which
 * is every sign-in in progress. So each row carries its own marker and is read
 * back with it. The bounded consequence is that the OLD secret must stay
 * configured until every row written under it has expired (at most
 * `MAX_OID4VP_REQUEST_TTL_MS`, 15 minutes).
 *
 * ## Scope
 *
 * This protects ONE column. It is not a column-encryption framework and must not
 * grow into one — a deployment wanting database-wide confidentiality wants disk
 * or tablespace encryption, which is an infrastructure control.
 */

/** Nothing resolved yet. Distinguished from "resolved to `undefined`". */
let resolved: { readonly secret: Uint8Array | undefined } | undefined;

/**
 * Decode the configured at-rest secret, or answer `undefined` for the default
 * posture.
 *
 * Exported separately from {@link oid4vpResponseKeySecret} so the decoding and
 * length rules are provable in a unit test with no environment — the same
 * property `resolveConfiguredVerifierSigningMaterial` and
 * `deriveCryptoCapabilities` are built around.
 *
 * @param secret - the raw `OID4VP_RESPONSE_KEY_SECRET` value.
 * @returns the 32-byte key, or `undefined` when none is configured.
 * @throws InvalidConfigurationError when a secret is configured but is not
 * exactly 32 bytes once decoded. Refused rather than stretched or truncated: a
 * silently derived key would be a key the operator cannot reproduce, and every
 * row written under it would become unreadable the moment anyone tried.
 */
export function resolveOid4vpResponseKeySecret(secret: string | undefined): Uint8Array | undefined {
  if (secret === undefined) return undefined;

  // base64url is accepted alongside base64 because that is what every other
  // random value in this workspace is printed as, and an operator who ran
  // `openssl rand -base64 32` and one who ran `head -c 32 /dev/urandom |
  // basenc --base64url` both configured the same key.
  const decoded = Buffer.from(secret, 'base64url');

  if (decoded.length !== EPHEMERAL_KEY_PROTECTION_SECRET_BYTES) {
    throw new InvalidConfigurationError(
      `OID4VP_RESPONSE_KEY_SECRET must decode to exactly ${EPHEMERAL_KEY_PROTECTION_SECRET_BYTES} bytes (AES-256) from base64 or base64url; it decoded to ${decoded.length}. Generate one with: openssl rand -base64 32`
    );
  }

  return new Uint8Array(decoded);
}

/**
 * The deployment's at-rest secret, resolved once.
 *
 * @returns the key, or `undefined` when the deployment stores the ephemeral
 * private JWK in the clear — which is the default.
 * @throws InvalidConfigurationError on a misconfigured secret, at BOOT: the
 * wallet-login gate reads it during registration so the refusal lands on the
 * operator rather than on a user's first sign-in attempt.
 */
export function oid4vpResponseKeySecret(): Uint8Array | undefined {
  resolved ??= { secret: resolveOid4vpResponseKeySecret(env.OID4VP_RESPONSE_KEY_SECRET) };
  return resolved.secret;
}

/**
 * Serialize an ephemeral private JWK for the row it belongs to.
 *
 * @param jwk - the private JWK from `exportEncryptionPrivateJwk`.
 * @param kid - the row's `kid`, bound into the envelope as AAD so a ciphertext
 * cannot be moved between rows.
 */
export function protectOid4vpResponseKey(
  jwk: JWK,
  kid: string
): { value: string; protection: Oid4vpEphemeralKeyProtection } {
  return protectEphemeralKey(jwk, { kid, secret: oid4vpResponseKeySecret() });
}

/**
 * Read a stored ephemeral private JWK back, using the marker the ROW carries.
 *
 * @param stored - `response_encryption_private_jwk`.
 * @param protection - `response_encryption_key_protection`, untrusted.
 * @param kid - `response_encryption_kid`, the envelope's AAD.
 * @throws Error when the row's marker is unrecognised or the value cannot be
 * read. The caller renders the uniform transport refusal: this is only reachable
 * after the state has been redeemed, so a distinct response would be an oracle
 * for a live request state.
 */
export function unprotectOid4vpResponseKey(
  stored: string,
  protection: string | null,
  kid: string
): JWK {
  const scheme = parseEphemeralKeyProtection(protection);

  if (scheme === undefined) {
    throw new Error(
      `Request state records an unrecognised ephemeral-key protection scheme '${String(protection)}'; refusing to guess how to read the stored key.`
    );
  }

  return unprotectEphemeralKey(stored, scheme, { kid, secret: oid4vpResponseKeySecret() });
}
