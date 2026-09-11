import { randomBytes } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { OID4VP_RESPONSE_KEY_SECRET: undefined } }));

import { resolveOid4vpResponseKeySecret } from './oid4vp-response-key';

/**
 * The OPT-IN at-rest secret for the per-request ephemeral encryption key
 * (#377 Phase C).
 *
 * Tested through the pure resolver rather than the memoised accessor, so the
 * decoding and length rules are provable with no environment — the same property
 * `deriveCryptoCapabilities` and `resolveConfiguredVerifierSigningMaterial` are
 * built around.
 */
describe('resolveOid4vpResponseKeySecret', () => {
  it('answers undefined for a deployment that configured nothing', () => {
    // The DEFAULT posture, and a real answer rather than a gap: the ephemeral
    // key is stored plainly beside a `nonce` that is already in the clear, and
    // no specification asks for more.
    expect(resolveOid4vpResponseKeySecret(undefined)).toBeUndefined();
  });

  it('decodes a base64 secret to 32 bytes', () => {
    const secret = randomBytes(32);

    expect(resolveOid4vpResponseKeySecret(secret.toString('base64'))).toEqual(
      new Uint8Array(secret)
    );
  });

  it('decodes the base64url spelling of the same key identically', () => {
    // An operator who ran `openssl rand -base64 32` and one who produced
    // base64url configured the same key; neither should have to know which
    // spelling this reader wanted.
    const secret = randomBytes(32);

    expect(resolveOid4vpResponseKeySecret(secret.toString('base64url'))).toEqual(
      resolveOid4vpResponseKeySecret(secret.toString('base64'))
    );
  });

  it('refuses a secret that decodes to the wrong length', () => {
    // Refused rather than stretched or truncated: a silently derived key is one
    // the operator cannot reproduce, and every row written under it becomes
    // unreadable the moment anyone tries.
    expect(() => resolveOid4vpResponseKeySecret(randomBytes(16).toString('base64'))).toThrow(
      /exactly 32 bytes/
    );
    expect(() => resolveOid4vpResponseKeySecret(randomBytes(48).toString('base64'))).toThrow(
      /exactly 32 bytes/
    );
  });

  it('refuses a value that decodes to nothing at all', () => {
    expect(() => resolveOid4vpResponseKeySecret('!!!!')).toThrow(/exactly 32 bytes/);
  });
});
