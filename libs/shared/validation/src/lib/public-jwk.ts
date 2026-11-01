/**
 * The rule a client's public JWK must clear (#925, #935), applied to the keys
 * an operator writes for a `private_key_jwt` client (the system client's
 * provisioner and the seed manifest, in `@qauth-labs/infra-db`) and to the key
 * sets a client publishes itself (a Client ID Metadata Document's `jwks` and a
 * `jwks_uri` document, in the auth server).
 *
 * The server only ever needs a client's public key. A key carrying private
 * material is refused, not stored with that material dropped: whoever wrote it
 * has exposed the private key, which must be rotated, not trusted. A key of a
 * known type must carry the public members its type needs, or every assertion
 * it signs is refused later for a reason nobody reads. Any other member, and a
 * key type the server may not use, is left to the caller.
 *
 * The rule lives in the shared layer because the auth server may not import
 * the database library, and the migration runner bundles the provisioner
 * without the auth server.
 */

/**
 * The private members of a JWK (RFC 7518 §6.2.2, §6.3.2, §6.4.1; `priv` of
 * an ML-DSA key): the private part of an EC, OKP or RSA key, the RSA primes
 * and CRT values, and a symmetric key.
 */
export const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'] as const;

/** The public members each known key type needs (RFC 7518 §6.2.1, §6.3.1; RFC 8037 §2). */
const REQUIRED_PUBLIC_JWK_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  EC: ['crv', 'x', 'y'],
  OKP: ['crv', 'x'],
  RSA: ['n', 'e'],
};

/** Why a JWK is not a public key the server may hold, as {@link publicJwkProblem} finds it. */
export interface PublicJwkProblem {
  /**
   * `private`: the key carries private material. `incomplete`: it lacks a
   * public member its key type needs.
   */
  readonly kind: 'private' | 'incomplete';
  /** The private members found, or the public members missing, by name. */
  readonly members: readonly string[];
  /** The refusal, naming the members, for an operator. */
  readonly message: string;
}

/**
 * Why `jwk` is not a public key the server may hold, or `undefined` when it is
 * one: the private members it carries, or else the public members its key type
 * needs and it lacks (a member that is not a non-empty string counts as
 * missing).
 *
 * It reads member names and the type of each needed member only, so no member
 * of an untrusted key is converted or walked. The key type is looked up as an
 * own name, so a `kty` such as `constructor` needs nothing rather than throwing.
 */
export function publicJwkProblem(
  jwk: Readonly<Record<string, unknown>>
): PublicJwkProblem | undefined {
  const exposed = PRIVATE_JWK_MEMBERS.filter((member) => member in jwk);
  if (exposed.length > 0) {
    return {
      kind: 'private',
      members: exposed,
      message: `jwks must contain PUBLIC keys only (private member ${quoted(exposed)} present)`,
    };
  }
  const { kty } = jwk;
  if (typeof kty !== 'string' || !Object.hasOwn(REQUIRED_PUBLIC_JWK_MEMBERS, kty)) {
    return undefined;
  }
  const missing = (REQUIRED_PUBLIC_JWK_MEMBERS[kty] ?? []).filter(
    (member) => typeof jwk[member] !== 'string' || jwk[member] === ''
  );
  if (missing.length === 0) return undefined;
  return { kind: 'incomplete', members: missing, message: `a ${kty} key needs ${quoted(missing)}` };
}

function quoted(members: readonly string[]): string {
  return members.map((member) => `"${member}"`).join(', ');
}
