import { z } from 'zod';

/**
 * Issuer verification-key configuration (ADR-004, issues #234 / #236 / #238).
 *
 * `OID4VP_ISSUER_JWKS` carries the **public keys credential issuers sign with**,
 * pinned in deployment configuration. It is what turns
 * `createStaticIssuerKeyResolver` — `@qauth-labs/server-federation`'s shipped
 * `issuer-metadata` backend — from a port with no implementation into a working
 * one, and therefore what makes a Verifiable Presentation verifiable at all.
 *
 * ## Three variables, three different questions
 *
 * | variable | question |
 * | --- | --- |
 * | `OID4VP_VERIFIER_PROFILE` (#299) | who are WE, to a wallet? |
 * | `OID4VP_TRUSTED_ISSUERS` (#236) | which issuers does a realm ACCEPT? |
 * | `OID4VP_ISSUER_JWKS` (here) | which KEY does an issuer sign with? |
 *
 * The last two are easy to conflate and must not be. Configuring a key here
 * grants NO trust: a credential whose signature verifies under a key configured
 * here is still refused unless its issuer is on the presenting realm's
 * allowlist. And the converse holds too — an allowlisted issuer with no key
 * configured here can never present anything, because nothing can verify it.
 * Both directions fail closed, which is the point: neither variable is a way to
 * accidentally widen the other.
 *
 * ## Shape
 *
 * A JSON object mapping **issuer identifier** to that issuer's public JWKs:
 *
 * ```
 * OID4VP_ISSUER_JWKS={"https://issuer.example":[{"kty":"EC","crv":"P-256","x":"…","y":"…","kid":"k1"}]}
 * ```
 *
 * Keyed by the issuer identifier rather than by realm, unlike
 * `OID4VP_TRUSTED_ISSUERS`: a key is a property of the ISSUER, and two realms
 * that both trust one issuer verify against the same key. Which realms accept it
 * stays the allowlist's decision.
 *
 * More than one JWK per issuer is normal (key rotation). When an issuer has more
 * than one, its credentials MUST carry a `kid` — the resolver refuses to guess,
 * because guessing is how a rotated-out key stays live. That rule lives in
 * `createStaticIssuerKeyResolver` and is deliberately NOT duplicated here: this
 * schema validates configuration, not credentials.
 *
 * ## Fail-closed, and PUBLIC keys only
 *
 * Unset, blank and `{}` all mean "no issuer key is configured", so every
 * presentation is refused — never "accept anything". And a JWK carrying private
 * material is REJECTED at parse time rather than tolerated: an issuer's private
 * key has no business in a verifier's configuration, its presence means a secret
 * has been mis-copied into an environment variable, and the boot is where that
 * must be noticed. (`importPublicSigningJwk` refuses it again at import time;
 * neither check is load-bearing alone.)
 *
 * Kept a PLAIN `z.object` — the wrapping is per FIELD — so `apps/auth-server`'s
 * env composition can still spread `.shape` (cf. `trustRegistryEnvSchema`).
 *
 * @see docs/adr/004-wallet-agnostic-federation.md
 */

/** Longest raw `OID4VP_ISSUER_JWKS` value accepted, in characters. */
const MAX_RAW_LENGTH = 128 * 1024;

/** Most issuers one deployment may pin keys for. */
const MAX_ISSUERS = 256;

/** Most keys one issuer may publish. Generous for rotation, bounded for sanity. */
const MAX_KEYS_PER_ISSUER = 16;

/**
 * Longest issuer identifier accepted. Mirrors the cap
 * `canonicalizeIssuerIdentifier` re-applies to the VALIDATED identity, so a
 * configured entry can never be longer than an identity that could match it.
 */
const MAX_ISSUER_LENGTH = 2048;

/**
 * JWK members that carry PRIVATE key material (RFC 7517 §4, RFC 7518 §6).
 *
 * `d` covers EC, OKP and RSA private exponents; the rest are RSA CRT parameters
 * and `oth` its "other primes" array. Any one of them present means the value is
 * a private key.
 */
const PRIVATE_JWK_MEMBERS: readonly string[] = Object.freeze([
  'd',
  'p',
  'q',
  'dp',
  'dq',
  'qi',
  'oth',
  'k',
]);

/**
 * Keys that address `Object.prototype` rather than an issuer.
 *
 * Rejected for the same reason `trust-registry.ts` rejects them, and BEFORE the
 * record schema runs: `JSON.parse` produces an own `__proto__` property that
 * `z.record` silently loses while copying, so an entry the operator wrote would
 * vanish without a word. No issuer is legitimately named any of these.
 */
const PROTOTYPE_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * One public JWK.
 *
 * Deliberately loose about which members a key type needs: `kty` is open-ended
 * (RFC 7518 registers more than QAuth supports, and more may be registered), and
 * `importPublicSigningJwk` — which owns the crypto — refuses a `kty`/`crv`/`alg`
 * mismatch far more precisely than a schema can. What this layer owns is the two
 * things a schema CAN decide: it is an object with a `kty`, and it is not a
 * private key.
 */
const publicJwkSchema = z
  .looseObject({
    kty: z.string().min(1, 'Each JWK must carry a "kty"'),
    kid: z.string().max(256).optional(),
    alg: z.string().max(64).optional(),
    use: z.string().max(32).optional(),
  })
  .refine((jwk) => !PRIVATE_JWK_MEMBERS.some((member) => member in jwk), {
    error:
      'A JWK in OID4VP_ISSUER_JWKS carries private key material. Only an issuer PUBLIC key belongs in a verifier configuration',
  });

/** One issuer identifier: an absolute HTTPS URL, as SD-JWT VC requires. */
const issuerIdentifierSchema = z
  .url({
    protocol: /^https$/,
    error: 'Each OID4VP_ISSUER_JWKS key must be an absolute https:// issuer identifier',
  })
  .max(MAX_ISSUER_LENGTH);

const perIssuerKeySetSchema = z.record(
  issuerIdentifierSchema,
  z
    .array(publicJwkSchema)
    .min(1, 'An issuer with no keys can never verify a credential')
    .max(MAX_KEYS_PER_ISSUER, `An issuer may publish at most ${MAX_KEYS_PER_ISSUER} keys`)
);

/**
 * Issuer identifier → that issuer's public JWKs.
 *
 * A prototype-less, deeply frozen map, for the same reason
 * `PerRealmIssuerAllowlist` is one: a lookup by an attacker-influenced issuer
 * identifier must not walk the prototype chain and hand back
 * `Object.prototype.constructor` in place of a key set.
 */
export type PerIssuerKeySets = Readonly<
  Record<string, readonly Readonly<Record<string, unknown>>[]>
>;

/** No issuer key is configured — the value of an unset variable. */
const EMPTY_KEY_SETS: PerIssuerKeySets = Object.freeze(
  Object.create(null) as Record<string, readonly Record<string, unknown>[]>
);

function harden(parsed: Record<string, Record<string, unknown>[]>): PerIssuerKeySets {
  const result = Object.create(null) as Record<string, readonly Record<string, unknown>[]>;
  for (const [issuer, jwks] of Object.entries(parsed)) {
    result[issuer] = Object.freeze(jwks.map((jwk) => Object.freeze({ ...jwk })));
  }
  return Object.freeze(result);
}

/**
 * Parse the raw `OID4VP_ISSUER_JWKS` string into a per-issuer key map.
 *
 * Unset and blank both yield {@link EMPTY_KEY_SETS} — `${VAR:-}` is how an
 * orchestrator materialises an absent variable, and a deployment with no
 * interest in wallet federation must not have its boot taken down by one.
 * Anything PRESENT but malformed is a hard parse failure: a typo must not
 * degrade to "no keys", because "no keys" is also the legitimate default and the
 * operator would have no way to tell the two apart.
 */
function parseIssuerJwks(raw: string | undefined, ctx: z.RefinementCtx): PerIssuerKeySets {
  if (raw === undefined || raw.trim() === '') return EMPTY_KEY_SETS;

  let decoded: unknown;
  try {
    decoded = JSON.parse(raw) as unknown;
  } catch {
    ctx.addIssue({
      code: 'custom',
      message:
        'OID4VP_ISSUER_JWKS must be a JSON object mapping an https:// issuer identifier to an array of public JWKs, e.g. {"https://issuer.example":[{"kty":"EC","crv":"P-256","x":"…","y":"…"}]}',
    });
    return z.NEVER;
  }

  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
    ctx.addIssue({
      code: 'custom',
      message:
        'OID4VP_ISSUER_JWKS must be a JSON OBJECT keyed by issuer identifier — a bare array has no issuer to attach a key to',
    });
    return z.NEVER;
  }

  for (const issuer of Object.keys(decoded)) {
    if (PROTOTYPE_KEYS.has(issuer)) {
      ctx.addIssue({
        code: 'custom',
        message: `OID4VP_ISSUER_JWKS: issuer name ${JSON.stringify(issuer)} addresses Object.prototype rather than an issuer and cannot carry a key set`,
      });
      return z.NEVER;
    }
  }

  const result = perIssuerKeySetSchema.safeParse(decoded);
  if (!result.success) {
    for (const issue of result.error.issues) {
      ctx.addIssue({
        code: 'custom',
        message: `OID4VP_ISSUER_JWKS: ${issue.message}`,
        path: issue.path,
      });
    }
    return z.NEVER;
  }

  const issuerCount = Object.keys(result.data).length;
  if (issuerCount > MAX_ISSUERS) {
    ctx.addIssue({
      code: 'custom',
      message: `OID4VP_ISSUER_JWKS names ${issuerCount} issuers, more than the ${MAX_ISSUERS} supported`,
    });
    return z.NEVER;
  }

  return harden(result.data as Record<string, Record<string, unknown>[]>);
}

export const issuerKeysEnvSchema = z.object({
  /**
   * `OID4VP_ISSUER_JWKS` (#234/#236) — issuer identifier → public JWKs, as JSON.
   *
   * Typed `z.string()` because every environment variable is a string; the JSON
   * decoding happens in the field transform so a failure names the variable and
   * shows the expected shape.
   */
  OID4VP_ISSUER_JWKS: z
    .string()
    .max(
      MAX_RAW_LENGTH,
      `OID4VP_ISSUER_JWKS must be at most ${MAX_RAW_LENGTH} characters — a key map that large is a configuration mistake`
    )
    .optional()
    .transform(parseIssuerJwks),
});

/** Issuer verification-key environment configuration type. */
export type IssuerKeysEnv = z.infer<typeof issuerKeysEnvSchema>;
