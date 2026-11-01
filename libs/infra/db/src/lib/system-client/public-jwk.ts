import { z } from 'zod';

/**
 * One public JWK an operator writes for a client that authenticates with
 * `private_key_jwt`: the system client's keys (`provision.ts`) and a seed
 * manifest entry's `jwks` (`seed-manifest.ts`). The server only ever needs a
 * client's public key, so a key carrying private material is an operator
 * mistake refused loudly rather than stored. A key of a known type must carry
 * the public members its type needs, or the token endpoint would refuse
 * every assertion it signs while the provisioner reported success. Any other
 * member, and a key type the server may not use, is left to the verifier.
 *
 * The module reaches only `zod`, so the migration runner bundles it with the
 * provisioner.
 */

/**
 * The private members of a JWK (RFC 7518 §6.2.2, §6.3.2, §6.4.1; `priv` of
 * an ML-DSA key): the private part of an EC, OKP or RSA key, the RSA primes
 * and CRT values, and a symmetric key.
 */
export const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'] as const;

/** The public members each known key type needs (RFC 7518 §6.2.1, §6.3.1; RFC 8037 §2). */
const REQUIRED_PUBLIC_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  EC: ['crv', 'x', 'y'],
  OKP: ['crv', 'x'],
  RSA: ['n', 'e'],
};

/** A public JWK, as {@link publicJwkSchema} accepts it. */
export const publicJwkSchema = z
  .object({ kty: z.string().min(1) })
  .catchall(z.unknown())
  .superRefine((jwk, ctx) => {
    const found = PRIVATE_JWK_MEMBERS.filter((member) => member in jwk);
    if (found.length > 0) {
      ctx.addIssue({
        code: 'custom',
        message: `jwks must contain PUBLIC keys only (private member ${found.map((m) => `"${m}"`).join(', ')} present)`,
      });
      return;
    }
    const missing = (REQUIRED_PUBLIC_MEMBERS[jwk.kty] ?? []).filter(
      (member) => typeof jwk[member] !== 'string' || (jwk[member] as string).length === 0
    );
    if (missing.length > 0) {
      ctx.addIssue({
        code: 'custom',
        message: `a ${jwk.kty} key needs ${missing.map((m) => `"${m}"`).join(', ')}`,
      });
    }
  });
