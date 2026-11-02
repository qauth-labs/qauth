import {
  EPHEMERAL_KEY_PROTECTION_SECRET_BYTES,
  parseEphemeralKeyProtection,
  unprotectEphemeralKey,
} from '@qauth-labs/fastify-plugin-federation';
import { OID4VP_RESPONSE_KEY_CONTEXT_PREFIX } from '@qauth-labs/fastify-plugin-signer';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import type { JWK } from 'jose';

import { env } from '../../config/env';

/**
 * The at-rest protection of the per-request ephemeral encryption key (issue
 * #377 Phase C, #546).
 *
 * `oid4vp_request_states.response_encryption_private_jwk` holds the private half
 * of a per-request ECDH-ES pair until the wallet answers. Since #546 the signer
 * seals it with the realm's `data_at_rest` key (ADR-019 Decision 9): the web
 * role, which mints the pair, may encrypt only under the
 * `oid4vp-response-key:` context, and the api role, which serves
 * `/oid4vp/response`, may decrypt it. The context names the row's `kid`, so a
 * ciphertext copied to another row, or another realm, does not open. The row
 * records the sealing key's `kid` (`response_encryption_sealing_kid`), and no
 * process outside the signer holds a key that opens it.
 *
 * ## Rows written before #546
 *
 * Before #546 the row carried a marker instead: `plain`, the JWK in the clear,
 * or `aes-256-gcm`, an envelope under `OID4VP_RESPONSE_KEY_SECRET`. Such a row
 * still opens, read back with its own marker, until it expires — at most
 * `MAX_OID4VP_REQUEST_TTL_MS`, 15 minutes after the last node of the previous
 * release wrote it. `OID4VP_RESPONSE_KEY_SECRET` is read for that and nothing
 * else: keep it set until then, and remove it after. Nothing writes a marker
 * row any more.
 */

/** Nothing resolved yet. Distinguished from "resolved to `undefined`". */
let resolved: { readonly secret: Uint8Array | undefined } | undefined;

/**
 * Decode the configured pre-#546 at-rest secret, or answer `undefined` when
 * none is set.
 *
 * Exported separately from {@link oid4vpResponseKeySecret} so the decoding and
 * length rules are provable in a unit test with no environment.
 *
 * @param secret - the raw `OID4VP_RESPONSE_KEY_SECRET` value.
 * @returns the 32-byte key, or `undefined` when none is configured.
 * @throws InvalidConfigurationError when a secret is configured but is not
 * exactly 32 bytes once decoded. Refused rather than stretched or truncated: a
 * silently derived key would not open the rows written under the real one.
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
      `OID4VP_RESPONSE_KEY_SECRET must decode to exactly ${EPHEMERAL_KEY_PROTECTION_SECRET_BYTES} bytes (AES-256) from base64 or base64url; it decoded to ${decoded.length}. It only opens request states written before the signer sealed them (#546): if none can still be in flight, remove it.`
    );
  }

  return new Uint8Array(decoded);
}

/**
 * The deployment's pre-#546 at-rest secret, resolved once.
 *
 * @returns the key, or `undefined` when none is set.
 * @throws InvalidConfigurationError on a misconfigured secret, at BOOT: `app.ts`
 * reads it during registration so the refusal lands on the operator rather
 * than on a user whose sign-in started before the upgrade.
 */
export function oid4vpResponseKeySecret(): Uint8Array | undefined {
  resolved ??= { secret: resolveOid4vpResponseKeySecret(env.OID4VP_RESPONSE_KEY_SECRET) };
  return resolved.secret;
}

/** The data context a response key is sealed under: its row's `kid` (#546). */
export function oid4vpResponseKeyContext(kid: string): string {
  return `${OID4VP_RESPONSE_KEY_CONTEXT_PREFIX}${kid}`;
}

/**
 * The `kid` of the `data_at_rest` key a signer ciphertext names
 * (`v1.<kid>.<nonce>.<ciphertext>`), or `undefined` for a value of another
 * form.
 */
export function dataAtRestKidOf(ciphertext: string): string | undefined {
  const parts = ciphertext.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') return undefined;
  const kid = parts[1] as string;
  return /^[A-Za-z0-9_-]{1,255}$/.test(kid) ? kid : undefined;
}

/** A sealed response key, as the request-state row stores it. */
export interface SealedOid4vpResponseKey {
  /** `response_encryption_private_jwk`: the signer's ciphertext. */
  readonly value: string;
  /** `response_encryption_sealing_kid`: the `data_at_rest` key that sealed it. */
  readonly sealingKid: string;
}

/**
 * Seal an ephemeral private JWK for the row it belongs to, with the realm's
 * `data_at_rest` key, as the `web` role (#546).
 *
 * @param signer - the signer; the only holder of the realm's keys.
 * @param realmId - the realm the request state belongs to.
 * @param jwk - the private JWK from `exportEncryptionPrivateJwk`.
 * @param kid - the row's `kid`, bound into the ciphertext through its context
 * so it cannot be moved between rows.
 * @throws the signer's errors: no `data_at_rest` key, or a signer that cannot
 * be reached. The caller renders the uniform refusal.
 */
export async function sealOid4vpResponseKey(
  signer: Pick<FastifyInstance['signer'], 'encrypt'>,
  realmId: string,
  jwk: JWK,
  kid: string
): Promise<SealedOid4vpResponseKey> {
  const plaintext = Buffer.from(JSON.stringify(jwk), 'utf8');
  let value: string;
  try {
    value = await signer.encrypt('web', {
      realmId,
      plaintext,
      context: oid4vpResponseKeyContext(kid),
    });
  } finally {
    plaintext.fill(0);
  }
  const sealingKid = dataAtRestKidOf(value);
  if (sealingKid === undefined) {
    throw new Error('The signer returned a ciphertext that names no data_at_rest key');
  }
  return { value, sealingKid };
}

/** The encrypted-response columns of a redeemed request state. */
export interface StoredOid4vpResponseKey {
  readonly realmId: string;
  /** `response_encryption_kid`. */
  readonly kid: string;
  /** `response_encryption_private_jwk`. */
  readonly value: string;
  /** `response_encryption_key_protection`: set on a row written before #546. */
  readonly protection: string | null;
  /** `response_encryption_sealing_kid`: set on a row written since #546. */
  readonly sealingKid: string | null;
}

/**
 * Read a stored ephemeral private JWK back: through the signer, as the `api`
 * role, when the row records a sealing key; with the row's own marker when it
 * was written before #546.
 *
 * @throws Error when the row records both or neither, its sealing `kid` is
 * not the one the ciphertext names, the marker is unrecognised, or the value
 * cannot be read. The caller renders the uniform transport refusal: this is
 * only reachable after the state has been redeemed, so a distinct response
 * would be an oracle for a live request state.
 */
export async function openOid4vpResponseKey(
  signer: Pick<FastifyInstance['signer'], 'decrypt'>,
  stored: StoredOid4vpResponseKey
): Promise<JWK> {
  if (stored.sealingKid !== null) {
    if (stored.protection !== null) {
      throw new Error('Request state records both a sealing key and a protection marker');
    }
    if (dataAtRestKidOf(stored.value) !== stored.sealingKid) {
      throw new Error('Request state names another sealing key than its ciphertext does');
    }
    const plaintext = await signer.decrypt('api', {
      realmId: stored.realmId,
      ciphertext: stored.value,
      context: oid4vpResponseKeyContext(stored.kid),
    });
    try {
      const jwk: unknown = JSON.parse(plaintext.toString('utf8'));
      if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) {
        throw new Error('The sealed response key is not a JWK');
      }
      return jwk as JWK;
    } finally {
      plaintext.fill(0);
    }
  }

  const scheme = parseEphemeralKeyProtection(stored.protection);
  if (scheme === undefined) {
    throw new Error(
      `Request state records an unrecognised ephemeral-key protection scheme '${String(stored.protection)}'; refusing to guess how to read the stored key.`
    );
  }
  return unprotectEphemeralKey(stored.value, scheme, {
    kid: stored.kid,
    secret: oid4vpResponseKeySecret(),
  });
}
