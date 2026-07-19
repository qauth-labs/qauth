import type { AkpJwk, PublicJwk } from './jwks';

/** Any key entry publishable on `/.well-known/jwks.json` (OKP Ed25519 or AKP ML-DSA). */
export type PublishedJwk = PublicJwk | AkpJwk;

/**
 * How a verifier asks for a key (#248 F9).
 *
 * BOTH members participate in the match. Selecting on `kid` ALONE is the
 * rotation bug this type exists to prevent: a hybrid JWKS publishes an Ed25519
 * `OKP` entry and an ML-DSA `AKP` entry, and once retired keys are published
 * too, a bare `kid` lookup can return an entry of the wrong algorithm — which a
 * verifier would then feed to the wrong primitive.
 */
export interface JwksKeySelector {
  /** `kid` from the token's protected header (`kid` for OKP, `pqc_kid` for AKP). */
  kid?: string;
  /** Required algorithm — `'EdDSA'` or `'ML-DSA-65'`. Never inferred from `kid`. */
  alg: string;
}

/** The `kty` a given `alg` must be published under (fully-specified, RFC 9864 spirit). */
function expectedKty(alg: string): string | undefined {
  if (alg === 'EdDSA') return 'OKP';
  if (alg === 'ML-DSA-65') return 'AKP';
  return undefined;
}

/**
 * Resolve exactly one published JWK for a `(kid, alg)` pair.
 *
 * Fails CLOSED — returns `undefined` rather than guessing — when:
 * - no entry matches both `kid` and `alg`,
 * - more than one entry matches (an ambiguous JWKS must never silently pick
 *   one; the boot-time {@link assertDistinctJwksKeyIds} makes this
 *   unreachable for keys this server publishes),
 * - the matched entry's `kty` contradicts its `alg` (a malformed or tampered
 *   JWKS trying to steer an ML-DSA key into the Ed25519 path, or vice versa).
 *
 * A selector without a `kid` addresses only the entry that itself has no `kid`
 * — the legacy single-active-key shape. It is NOT a wildcard over that
 * algorithm: matching every entry would mean that publishing the first retired
 * (kid-bearing) key turns the selector ambiguous and breaks verification for
 * every still-valid token signed before a `kid` was configured. Since
 * {@link assertDistinctJwksKeyIds} permits at most one un-`kid`-ed entry per
 * algorithm, this resolves deterministically, and rotation stays backwards
 * compatible with unkeyed tokens.
 *
 * @param keys - Published JWKS entries.
 * @param selector - `(kid, alg)` to resolve; see {@link JwksKeySelector}.
 * @returns The single matching JWK, or `undefined`.
 */
export function selectJwksKey(
  keys: readonly PublishedJwk[],
  selector: JwksKeySelector
): PublishedJwk | undefined {
  const matches = keys.filter((key) => {
    if (key['alg'] !== selector.alg) return false;
    // An entry without a `kid` is only addressable by an unkeyed selector, and
    // an unkeyed selector addresses only that entry — never a kid-bearing one.
    return selector.kid === undefined ? key['kid'] === undefined : key['kid'] === selector.kid;
  });

  if (matches.length !== 1) return undefined;

  const [match] = matches;
  const kty = expectedKty(selector.alg);
  if (kty !== undefined && match['kty'] !== kty) return undefined;
  return match;
}

/**
 * Assert that a JWKS is unambiguously addressable before it is published
 * (#248 F9).
 *
 * Enforces that every `kid` is unique across the WHOLE document — including
 * across the `OKP` (Ed25519) and `AKP` (ML-DSA) halves and across active and
 * retired keys. Uniqueness per-algorithm would be enough for
 * {@link selectJwksKey}, but a `kid` shared by two algorithms is a trap for
 * every OTHER consumer (stock JOSE clients do select on `kid` alone), so the
 * stricter rule is the one worth enforcing.
 *
 * Entries without a `kid` are exempt: that is the single-active-key shape which
 * predates rotation. More than one un-`kid`-ed entry per algorithm is rejected,
 * since those are mutually unaddressable.
 *
 * @param keys - Entries about to be published.
 * @throws Error naming the duplicated `kid` (or the ambiguous algorithm).
 */
export function assertDistinctJwksKeyIds(keys: readonly PublishedJwk[]): void {
  const seenKids = new Set<string>();
  const unkeyedAlgs = new Set<string>();

  for (const key of keys) {
    const kid = key['kid'];
    const alg = String(key['alg']);
    if (typeof kid === 'string' && kid.length > 0) {
      if (seenKids.has(kid)) {
        throw new Error(
          `JWKS publishes duplicate kid '${kid}'. Every key — across OKP/AKP and across ` +
            `active and retired keys — must have its own kid so verifiers can resolve ` +
            `(kid, alg) unambiguously.`
        );
      }
      seenKids.add(kid);
      continue;
    }
    if (unkeyedAlgs.has(alg)) {
      throw new Error(
        `JWKS publishes more than one '${alg}' key without a kid. Assign a distinct kid to ` +
          `each key before publishing more than one per algorithm.`
      );
    }
    unkeyedAlgs.add(alg);
  }
}
