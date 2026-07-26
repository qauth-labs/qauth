import { z } from 'zod';

/**
 * Trust-registry environment configuration (ADR-004, issue #236).
 *
 * `OID4VP_TRUSTED_ISSUERS` carries the **static per-realm issuer allowlist**:
 * which credential ISSUERS a given realm is willing to accept credentials from
 * once #234's presentation validation has cryptographically established who the
 * issuer is.
 *
 * ## This is issuer trust, NOT verifier identity
 *
 * `OID4VP_VERIFIER_PROFILE` (`federation.ts`, #299) configures the OTHER trust
 * direction — how QAuth proves that IT is the Verifier to a wallet. The two
 * directions share no configuration deliberately: conflating them would let
 * "we trust this issuer" answer "who are we?". Keep the variables, the schemas
 * and the code paths separate.
 *
 * ## Shape
 *
 * A JSON object mapping **realm name** to the list of issuer identifiers that
 * realm trusts:
 *
 * ```
 * OID4VP_TRUSTED_ISSUERS={"master":["https://issuer.example"],"acme":[]}
 * ```
 *
 * Keyed by `realms.name` rather than `realms.id`: realm ids are `uuidv7()`
 * values minted by the database, so they are unknown when an operator authors
 * config, while `name` is the unique human-readable handle. A realm that is
 * renamed loses its allowlist and falls back to trusting nothing — fail-closed,
 * and the direction a rename should fail in.
 *
 * ## Per realm, never global
 *
 * There is deliberately NO deployment-wide fallback list. A single global
 * allowlist would mean an issuer added for one tenant is silently accepted by
 * every other tenant, which is the opposite of what a per-realm allowlist is
 * for (#236 AC: *"The allowlist is configurable per realm, not global"*). A
 * realm absent from this map trusts no issuer at all.
 *
 * ## Fail-closed
 *
 * Unset, blank, or `{}` all mean "no realm trusts any issuer" — the flow
 * REFUSES rather than falling back to accept-all (#296 LOCKED posture, extended
 * to trust config by #236). The parsed value is therefore an empty map, never
 * `undefined`: a caller cannot mistake "not configured" for "no opinion".
 *
 * ## Entries are validated here, canonicalized in `server-federation`
 *
 * This schema checks that each entry is a syntactically valid **HTTPS** URL and
 * caps sizes; it does NOT canonicalize. Canonicalization (case, default port,
 * trailing slash) has to be identical for allowlist entries and for the
 * validated issuer identity they are matched against, so it lives in exactly one
 * place — `@qauth-labs/server-federation`'s `canonicalizeIssuerIdentifier`,
 * which the trust registry applies to BOTH sides. `server-config` carries no
 * dependency on `server-federation` (config is the lowest layer), so duplicating
 * the canonicalizer here is how the two sides would drift apart.
 *
 * HTTP is rejected: the base OID4VP 1.0 / SD-JWT VC issuer identity is an HTTPS
 * URI, and an issuer identity that can be reached in the clear is not one worth
 * pinning trust to.
 *
 * Kept a PLAIN `z.object` — the wrapping is per FIELD — so `apps/auth-server`'s
 * env composition can still spread `.shape` (cf. `federationEnvSchema`).
 *
 * @see docs/adr/004-wallet-agnostic-federation.md
 */

/** Longest raw `OID4VP_TRUSTED_ISSUERS` value accepted, in characters. */
const MAX_RAW_LENGTH = 64 * 1024;

/** Most realms one deployment may configure an allowlist for. */
const MAX_REALMS = 256;

/** Most issuers a single realm may trust. */
const MAX_ISSUERS_PER_REALM = 64;

/**
 * Longest issuer identifier accepted, in characters. Mirrors the cap the
 * federation canonicalizer re-applies to the VALIDATED issuer identity, so an
 * allowlist entry can never be longer than an identity that could match it.
 */
const MAX_ISSUER_LENGTH = 2048;

/** `realms.name` is `varchar(255)`; a longer key can never name a real realm. */
const MAX_REALM_NAME_LENGTH = 255;

/**
 * One trusted issuer identifier: an absolute HTTPS URL.
 *
 * `z.url({ protocol })` (Zod v4 standalone format validator) rather than a
 * hand-rolled regex or the deprecated `z.string().url()` form.
 */
const trustedIssuerSchema = z
  .url({
    protocol: /^https$/,
    error: 'Each trusted issuer must be an absolute https:// URL',
  })
  .max(MAX_ISSUER_LENGTH);

/**
 * Keys that address `Object.prototype` rather than a realm.
 *
 * REJECTED rather than tolerated, and rejected BEFORE
 * {@link perRealmAllowlistSchema} runs. `JSON.parse` produces an own
 * `__proto__` property, but copying it onto a plain object — which is what
 * `z.record` does internally — re-invokes the setter and the entry vanishes. A
 * realm named `__proto__` would therefore be silently dropped: a trust policy
 * the operator wrote and the server did not apply. A loud parse failure is the
 * only honest outcome; no realm is legitimately named any of these.
 */
const PROTOTYPE_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

/** The `{ realmName: issuers[] }` body, once the raw string has been JSON-parsed. */
const perRealmAllowlistSchema = z.record(
  z
    .string()
    .min(1, 'Realm name must not be empty')
    .max(MAX_REALM_NAME_LENGTH, `Realm name must be at most ${MAX_REALM_NAME_LENGTH} characters`),
  z
    .array(trustedIssuerSchema)
    .max(MAX_ISSUERS_PER_REALM, `A realm may trust at most ${MAX_ISSUERS_PER_REALM} issuers`)
);

/**
 * Realm name → issuers that realm trusts.
 *
 * A prototype-less, deeply frozen map. Prototype-less matters: `JSON.parse`
 * happily produces an own `__proto__`/`constructor` key, and a plain-object
 * lookup by an attacker-influenced realm name would otherwise walk the
 * prototype chain and hand back `Object.prototype.constructor` in place of an
 * allowlist.
 */
export type PerRealmIssuerAllowlist = Readonly<Record<string, readonly string[]>>;

/** No realm trusts any issuer — the value of an unset variable. */
const EMPTY_ALLOWLIST: PerRealmIssuerAllowlist = Object.freeze(
  Object.create(null) as Record<string, readonly string[]>
);

/**
 * Freeze the validated map into a prototype-less, immutable structure.
 */
function harden(parsed: Record<string, string[]>): PerRealmIssuerAllowlist {
  const result = Object.create(null) as Record<string, readonly string[]>;
  for (const [realmName, issuers] of Object.entries(parsed)) {
    result[realmName] = Object.freeze([...issuers]);
  }
  return Object.freeze(result);
}

/**
 * Parse the raw `OID4VP_TRUSTED_ISSUERS` string into a per-realm allowlist.
 *
 * Unset and blank both yield {@link EMPTY_ALLOWLIST}. Blank is treated as unset
 * for the same reason `OID4VP_VERIFIER_PROFILE` does (`federation.ts`): a
 * `${VAR:-}` in `docker-compose.yml` or an orchestrator materialising an absent
 * variable is how operators say "not configured", and that must not take the
 * whole process down at import time. It does not soften anything — empty means
 * no realm trusts any issuer, which is the refusing state.
 *
 * Anything PRESENT but malformed is a hard parse failure. A typo must not
 * degrade to "trusts nothing" silently, because "trusts nothing" is also the
 * legitimate default: the operator would have no way to tell the two apart.
 */
function parseTrustedIssuers(
  raw: string | undefined,
  ctx: z.RefinementCtx
): PerRealmIssuerAllowlist {
  if (raw === undefined || raw.trim() === '') return EMPTY_ALLOWLIST;

  let decoded: unknown;
  try {
    decoded = JSON.parse(raw) as unknown;
  } catch {
    ctx.addIssue({
      code: 'custom',
      message:
        'OID4VP_TRUSTED_ISSUERS must be a JSON object mapping realm name to an array of https:// issuer URLs, e.g. {"master":["https://issuer.example"]}',
    });
    return z.NEVER;
  }

  // `z.record` rejects arrays and primitives, but not before its own message
  // ("expected record, received array") loses the shape hint operators need.
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
    ctx.addIssue({
      code: 'custom',
      message:
        'OID4VP_TRUSTED_ISSUERS must be a JSON OBJECT keyed by realm name, e.g. {"master":["https://issuer.example"]} — a bare array has no realm to attach trust to',
    });
    return z.NEVER;
  }

  // Checked here rather than inside the record's key schema: `z.record` copies
  // entries onto a plain object and loses `__proto__` before any key validator
  // sees it. See PROTOTYPE_KEYS.
  for (const realmName of Object.keys(decoded)) {
    if (PROTOTYPE_KEYS.has(realmName)) {
      ctx.addIssue({
        code: 'custom',
        message: `OID4VP_TRUSTED_ISSUERS: realm name ${JSON.stringify(realmName)} addresses Object.prototype rather than a realm and cannot carry a trust policy`,
      });
      return z.NEVER;
    }
  }

  const result = perRealmAllowlistSchema.safeParse(decoded);
  if (!result.success) {
    for (const issue of result.error.issues) {
      ctx.addIssue({
        code: 'custom',
        message: `OID4VP_TRUSTED_ISSUERS: ${issue.message}`,
        path: issue.path,
      });
    }
    return z.NEVER;
  }

  const realmCount = Object.keys(result.data).length;
  if (realmCount > MAX_REALMS) {
    ctx.addIssue({
      code: 'custom',
      message: `OID4VP_TRUSTED_ISSUERS names ${realmCount} realms, more than the ${MAX_REALMS} supported`,
    });
    return z.NEVER;
  }

  return harden(result.data);
}

export const trustRegistryEnvSchema = z.object({
  /**
   * `OID4VP_TRUSTED_ISSUERS` (#236) — per-realm issuer allowlist, as JSON.
   *
   * Typed `z.string()` because every environment variable is a string; the
   * JSON decoding happens in the field transform so failures carry a message
   * that names the variable and shows the expected shape.
   */
  OID4VP_TRUSTED_ISSUERS: z
    .string()
    .max(
      MAX_RAW_LENGTH,
      `OID4VP_TRUSTED_ISSUERS must be at most ${MAX_RAW_LENGTH} characters — an allowlist that large is a configuration mistake`
    )
    .optional()
    .transform(parseTrustedIssuers),
});

/** Trust-registry environment configuration type. */
export type TrustRegistryEnv = z.infer<typeof trustRegistryEnvSchema>;
