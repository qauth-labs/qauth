import { z } from 'zod';

/**
 * Assurance-level environment configuration (ADR-004, ADR-010, issue #237).
 *
 * Two variables, answering two different questions:
 *
 *  - `OID4VP_ISSUER_ASSURANCE` — **which issuers a realm considers assured, and
 *    at what eIDAS Level of Assurance.** The input to the `acr` claim.
 *  - `ACR_VALUE_STYLE` — **which vocabulary the emitted `acr` value is written
 *    in.** A rendering choice, deployment-wide.
 *
 * ## Why assurance is configuration at all
 *
 * It cannot be anything else. OID4VP 1.0 §5 fixes the response type to
 * `vp_token`, so there is no wallet-signed assertion for a level to travel in,
 * and HAIP 1.0 §1 states outright that the profile does not by itself reach LoA
 * `high` — "these features must be combined with additional measures outside of
 * the scope of HAIP". A Level of Assurance is a property of the ecosystem
 * (identity proofing, wallet certification, secure cryptographic device), and
 * the only party that knows which ecosystems a deployment participates in is its
 * operator. QAuth therefore refuses to infer a level and requires one to be
 * stated.
 *
 * ## This is NOT the trust allowlist
 *
 * `OID4VP_TRUSTED_ISSUERS` (`trust-registry.ts`, #236) decides whether a realm
 * may accept an issuer's credentials AT ALL. This decides what they are worth
 * once accepted. Listing an issuer here does **not** make it trusted — the trust
 * gate runs first and independently — and the two are separate variables so that
 * neither answer can be read out of the other.
 *
 * ## Fail-closed
 *
 * Unset, blank and `{}` all mean "no realm assures any issuer", which means no
 * ID token carries an `acr` claim. There is no deployment-wide fallback and no
 * permissive default: an unconfigured deployment behaves exactly as it did
 * before wallet federation existed.
 *
 * Kept a PLAIN `z.object` — wrapping is per FIELD — so `apps/auth-server`'s env
 * composition can spread `.shape` (cf. `federationEnvSchema`,
 * `trustRegistryEnvSchema`).
 *
 * @see docs/adr/010-acr-assurance-mapping.md
 */

/** Longest raw `OID4VP_ISSUER_ASSURANCE` value accepted, in characters. */
const MAX_RAW_LENGTH = 64 * 1024;

/** Most realms one deployment may configure assurance for. */
const MAX_REALMS = 256;

/** Most issuers a single realm may assure. Mirrors the trust allowlist's cap. */
const MAX_ISSUERS_PER_REALM = 64;

/** Most credential types one issuer statement may name. */
const MAX_CREDENTIAL_TYPES = 32;

/** Longest issuer identifier accepted. Mirrors `trust-registry.ts`. */
const MAX_ISSUER_LENGTH = 2048;

/** Longest `vct` accepted. SD-JWT VC places no limit; this is a DoS bound. */
const MAX_CREDENTIAL_TYPE_LENGTH = 2048;

/** `realms.name` is `varchar(255)`; a longer key can never name a real realm. */
const MAX_REALM_NAME_LENGTH = 255;

/**
 * Keys that address `Object.prototype` rather than a realm or an issuer.
 *
 * Rejected for the same reason `trust-registry.ts` rejects them: `JSON.parse`
 * produces an own `__proto__` property, but copying it onto a plain object —
 * which `z.record` does internally — re-invokes the setter and the entry
 * vanishes. A silently dropped entry is a policy the operator wrote and the
 * server did not apply.
 */
const PROTOTYPE_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * The levels an operator may configure.
 *
 * `'low'` is deliberately NOT one of them. `'low'` is what an unlisted issuer
 * already resolves to and it emits no `acr` claim, so an entry granting it would
 * be a no-op that reads like a control — the shape that makes an operator
 * believe they disabled something they merely failed to enable.
 *
 * Duplicated from `AssuranceLevel` rather than imported: `server-config` carries
 * no dependency on `server-federation` (config is the lowest layer). The
 * duplication is pinned by `apps/auth-server`'s `src/config/env.test.ts`, the
 * lowest layer permitted to import both.
 */
const configuredAssuranceLevelSchema = z.enum(['substantial', 'high']);

/** One issuer statement: the level, and optionally the credential types it covers. */
const issuerAssuranceSchema = z
  .object({
    level: configuredAssuranceLevelSchema,
    /**
     * `vct` values this statement covers. OMITTING it covers every credential
     * type the issuer signs — a deliberate, documented widening appropriate for
     * an issuer that only ever issues one kind of credential. An issuer that
     * runs one identity-proofing process for its PID and something weaker for a
     * loyalty credential names the types.
     *
     * An explicitly EMPTY list is refused rather than treated as "all": it would
     * be an entry that covers nothing while looking like one that covers
     * something.
     */
    credentialTypes: z
      .array(z.string().min(1).max(MAX_CREDENTIAL_TYPE_LENGTH))
      .min(1, 'credentialTypes must name at least one vct, or be omitted entirely')
      .max(MAX_CREDENTIAL_TYPES)
      .optional(),
  })
  .strict();

/** One issuer identifier: an absolute HTTPS URL, exactly as the trust allowlist requires. */
const issuerIdentifierSchema = z
  .url({
    protocol: /^https$/,
    error: 'Each assured issuer must be an absolute https:// URL',
  })
  .max(MAX_ISSUER_LENGTH);

/** The `{ issuer: statement }` body for a single realm. */
const perIssuerAssuranceSchema = z.record(issuerIdentifierSchema, issuerAssuranceSchema);

/** The `{ realmName: { issuer: statement } }` body, once the raw string is JSON-parsed. */
const perRealmAssuranceSchema = z.record(
  z
    .string()
    .min(1, 'Realm name must not be empty')
    .max(MAX_REALM_NAME_LENGTH, `Realm name must be at most ${MAX_REALM_NAME_LENGTH} characters`),
  perIssuerAssuranceSchema
);

/** One operator statement about an issuer, as parsed. */
export interface ConfiguredIssuerAssuranceStatement {
  /** eIDAS LoA credentials from this issuer are worth. */
  readonly level: 'substantial' | 'high';
  /** `vct` values covered; absent covers every type the issuer signs. */
  readonly credentialTypes?: readonly string[];
}

/** Issuer identifier → what credentials from it are worth. */
export type IssuerAssuranceMap = Readonly<Record<string, ConfiguredIssuerAssuranceStatement>>;

/**
 * Realm name → the issuers that realm assures.
 *
 * A prototype-less, deeply frozen map, for the same reason
 * `PerRealmIssuerAllowlist` is: a lookup by an attacker-influenced realm name
 * must not walk `Object.prototype`.
 */
export type PerRealmIssuerAssurance = Readonly<Record<string, IssuerAssuranceMap>>;

/** No realm assures any issuer — the value of an unset variable. */
const EMPTY_ASSURANCE: PerRealmIssuerAssurance = Object.freeze(
  Object.create(null) as Record<string, IssuerAssuranceMap>
);

/** Freeze the validated map into a prototype-less, immutable structure. */
function harden(
  parsed: Record<string, Record<string, z.infer<typeof issuerAssuranceSchema>>>
): PerRealmIssuerAssurance {
  const result = Object.create(null) as Record<string, IssuerAssuranceMap>;
  for (const [realmName, issuers] of Object.entries(parsed)) {
    const perIssuer = Object.create(null) as Record<string, ConfiguredIssuerAssuranceStatement>;
    for (const [issuer, statement] of Object.entries(issuers)) {
      perIssuer[issuer] = Object.freeze({
        level: statement.level,
        ...(statement.credentialTypes !== undefined
          ? { credentialTypes: Object.freeze([...statement.credentialTypes]) }
          : {}),
      });
    }
    result[realmName] = Object.freeze(perIssuer);
  }
  return Object.freeze(result);
}

/** Reject prototype-addressing keys anywhere in the two-level map. */
function assertNoPrototypeKeys(decoded: Record<string, unknown>, ctx: z.RefinementCtx): boolean {
  for (const [realmName, issuers] of Object.entries(decoded)) {
    if (PROTOTYPE_KEYS.has(realmName)) {
      ctx.addIssue({
        code: 'custom',
        message: `OID4VP_ISSUER_ASSURANCE: realm name ${JSON.stringify(realmName)} addresses Object.prototype rather than a realm and cannot carry an assurance policy`,
      });
      return false;
    }
    if (issuers === null || typeof issuers !== 'object' || Array.isArray(issuers)) continue;
    for (const issuer of Object.keys(issuers)) {
      if (PROTOTYPE_KEYS.has(issuer)) {
        ctx.addIssue({
          code: 'custom',
          message: `OID4VP_ISSUER_ASSURANCE: issuer key ${JSON.stringify(issuer)} addresses Object.prototype rather than an issuer`,
        });
        return false;
      }
    }
  }
  return true;
}

/**
 * Parse the raw `OID4VP_ISSUER_ASSURANCE` string into a per-realm policy.
 *
 * Unset and blank both yield {@link EMPTY_ASSURANCE} — `${VAR:-}` in a compose
 * file is how an operator says "not configured", and that must not take the boot
 * down for a deployment with no interest in wallet federation. Anything PRESENT
 * but malformed is a hard parse failure: a typo must not degrade silently to
 * "assures nothing", because that is also the legitimate default and the
 * operator would have no way to tell the two apart.
 */
function parseIssuerAssurance(
  raw: string | undefined,
  ctx: z.RefinementCtx
): PerRealmIssuerAssurance {
  if (raw === undefined || raw.trim() === '') return EMPTY_ASSURANCE;

  let decoded: unknown;
  try {
    decoded = JSON.parse(raw) as unknown;
  } catch {
    ctx.addIssue({
      code: 'custom',
      message:
        'OID4VP_ISSUER_ASSURANCE must be a JSON object mapping realm name to issuer assurance, e.g. {"master":{"https://issuer.example":{"level":"high"}}}',
    });
    return z.NEVER;
  }

  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
    ctx.addIssue({
      code: 'custom',
      message:
        'OID4VP_ISSUER_ASSURANCE must be a JSON OBJECT keyed by realm name, e.g. {"master":{"https://issuer.example":{"level":"high"}}} — a bare array has no realm to attach a policy to',
    });
    return z.NEVER;
  }

  if (!assertNoPrototypeKeys(decoded as Record<string, unknown>, ctx)) return z.NEVER;

  const result = perRealmAssuranceSchema.safeParse(decoded);
  if (!result.success) {
    for (const issue of result.error.issues) {
      ctx.addIssue({
        code: 'custom',
        message: `OID4VP_ISSUER_ASSURANCE: ${issue.message}`,
        path: issue.path,
      });
    }
    return z.NEVER;
  }

  const realmCount = Object.keys(result.data).length;
  if (realmCount > MAX_REALMS) {
    ctx.addIssue({
      code: 'custom',
      message: `OID4VP_ISSUER_ASSURANCE names ${realmCount} realms, more than the ${MAX_REALMS} supported`,
    });
    return z.NEVER;
  }

  for (const [realmName, issuers] of Object.entries(result.data)) {
    const issuerCount = Object.keys(issuers).length;
    if (issuerCount > MAX_ISSUERS_PER_REALM) {
      ctx.addIssue({
        code: 'custom',
        message: `OID4VP_ISSUER_ASSURANCE: realm ${JSON.stringify(realmName)} assures ${issuerCount} issuers, more than the ${MAX_ISSUERS_PER_REALM} supported`,
      });
      return z.NEVER;
    }
  }

  return harden(result.data);
}

export const assuranceEnvSchema = z.object({
  /**
   * `OID4VP_ISSUER_ASSURANCE` (#237) — per-realm issuer assurance, as JSON.
   *
   * ```
   * OID4VP_ISSUER_ASSURANCE={"master":{"https://issuer.example":{"level":"high","credentialTypes":["https://credentials.example.com/pid"]}}}
   * ```
   *
   * Keyed by `realms.name` rather than `realms.id` for the same reason as
   * `OID4VP_TRUSTED_ISSUERS`: realm ids are database-minted `uuidv7()` values
   * unknown when an operator authors config. A renamed realm loses its policy
   * and assures nothing — fail-closed, and the direction a rename should fail
   * in.
   *
   * Typed `z.string()` because every environment variable is a string; the JSON
   * decoding happens in the field transform so failures carry a message that
   * names the variable and shows the expected shape.
   */
  OID4VP_ISSUER_ASSURANCE: z
    .string()
    .max(
      MAX_RAW_LENGTH,
      `OID4VP_ISSUER_ASSURANCE must be at most ${MAX_RAW_LENGTH} characters — a policy that large is a configuration mistake`
    )
    .optional()
    .transform(parseIssuerAssurance),

  /**
   * `ACR_VALUE_STYLE` (#237) — which vocabulary `acr` values are written in.
   *
   * - `eidas-uri` (default) — `http://eidas.europa.eu/LoA/high`. An absolute
   *   URI, which is what OIDC Core §2 asks an `acr` value to be, and the form
   *   eIDAS ecosystems already read. The `http:` scheme is part of the
   *   identifier as eIDAS defines it and is quoted verbatim.
   * - `loa-name` — bare `high` / `substantial`, for deployments whose Relying
   *   Parties already consume the short names used by national eID→OIDC bridges.
   *
   * There is no free-text option. An arbitrary operator string could collide
   * with an RFC 6711 registered `acr` name while meaning something else, which
   * OIDC Core §2 forbids.
   *
   * Same empty-is-unset handling as `OID4VP_VERIFIER_PROFILE`; unlike that
   * variable this one HAS a safe default, because rendering an `acr` value is
   * only reached once a level has already been established.
   *
   * Values are duplicated from `AcrValueStyle` in `server-federation` and pinned
   * by `apps/auth-server`'s `src/config/env.test.ts`.
   */
  ACR_VALUE_STYLE: z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z.enum(['eidas-uri', 'loa-name']).default('eidas-uri')
  ),
});

/** Assurance environment configuration type. */
export type AssuranceEnv = z.infer<typeof assuranceEnvSchema>;
