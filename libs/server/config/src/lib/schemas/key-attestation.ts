import { z } from 'zod';

/**
 * Key-attestation environment configuration (HAIP §4.5.1, issues #308, #379).
 *
 * One variable — `OID4VP_ATTESTING_ISSUERS` — recording which issuance chains
 * this deployment believes validate a wallet's key attestation before they will
 * issue anything, and at what OID4VCI Appendix D §D.2 grade.
 *
 * ## Why an operator has to state it
 *
 * #308's finding: HAIP places the normative key-attestation mandate at the
 * ISSUANCE endpoint (§4.5.1, *"Wallets MUST support key attestations"*), not in
 * presentation. QAuth runs no Credential Endpoint (ADR-004 puts OID4VCI out of
 * scope), so the WSCD assurance a Verifier has under HAIP is assurance it
 * INHERITED: a trusted issuer checked the wallet's attestation, and the
 * credential exists only because that check passed.
 *
 * Nothing in a presentation asserts that an issuer performs that check. Not the
 * credential, not the `x5c` chain (a certificate says who signed, not what they
 * verified), not the `vct`. It is an out-of-band fact about an issuance
 * ecosystem — exactly the kind of fact HAIP §3.4 leaves to the operator, and the
 * same posture `OID4VP_TRUSTED_ISSUERS` takes for trust anchors.
 *
 * ## This is NOT the trust allowlist, and NOT the assurance policy
 *
 * Three variables, three questions, and none of them implies another:
 *
 * | variable | question |
 * | --- | --- |
 * | `OID4VP_TRUSTED_ISSUERS` (#236) | may this realm accept the issuer at all? |
 * | `OID4VP_ISSUER_ASSURANCE` (#237) | what is a credential from it worth? |
 * | `OID4VP_ATTESTING_ISSUERS` (#308) | does its ISSUANCE process attest key storage? |
 *
 * Trusting an issuer's claims about a PERSON is a different decision from
 * trusting its claims about a DEVICE, and conflating them would hand every
 * allowlisted issuer the ability to mint high-assurance sessions by accident.
 *
 * ## Deployment-wide, unlike the two variables above
 *
 * The other two are keyed by realm; this one is a flat map, because what an
 * issuer's §4.5.1 validation establishes is a property of that ISSUANCE
 * ECOSYSTEM rather than of any realm's opinion of it — the same grade whichever
 * tenant is looking. The realm-scoped decision stays where it already is: an
 * entry here produces EVIDENCE and never a level, so a realm still grants
 * nothing unless its own `OID4VP_ISSUER_ASSURANCE` names the issuer AND its own
 * `OID4VP_TRUSTED_ISSUERS` accepts it. Listing an issuer here can therefore not
 * raise any realm's assurance on its own.
 *
 * It is also what makes the gate constructible where it is built — once per
 * deployment in `wallet-verification.ts`, before any realm is known.
 *
 * ## Fail-closed
 *
 * Unset and blank both mean "no issuer attests anything", which is what every
 * deployment predating #308 means and what keeps `haip-1.0` refusing to boot
 * until an operator has actually provisioned something. Anything PRESENT but
 * malformed is a hard parse failure, for the same reason `OID4VP_ISSUER_ASSURANCE`
 * makes one: a typo must not degrade silently into the legitimate default,
 * because the operator would have no way to tell the two apart.
 *
 * @see docs/adr/010-acr-assurance-mapping.md
 * @see https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
 */

/** Longest raw `OID4VP_ATTESTING_ISSUERS` value accepted, in characters. */
const MAX_RAW_LENGTH = 16 * 1024;

/** Most issuers one deployment may record as attesting. Mirrors the per-realm allowlist cap. */
const MAX_ATTESTING_ISSUERS = 64;

/** Longest issuer identifier accepted. Mirrors `trust-registry.ts`. */
const MAX_ISSUER_LENGTH = 2048;

/**
 * Keys that address `Object.prototype` rather than an issuer.
 *
 * Rejected for the same reason `trust-registry.ts` and `assurance.ts` reject
 * them: `JSON.parse` produces an own `__proto__` property, but copying it onto a
 * plain object — which `z.record` does internally — re-invokes the setter and the
 * entry vanishes. A silently dropped entry is a policy the operator wrote and the
 * server did not apply.
 */
const PROTOTYPE_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * The OID4VCI Appendix D §D.2 attack-potential grades.
 *
 * Duplicated from `AttackPotentialResistance` in `server-federation` rather than
 * imported: `server-config` is the lowest layer and carries no dependency on
 * `server-federation`. The duplication is pinned by `apps/auth-server`'s
 * `src/config/env.test.ts`, the lowest layer permitted to import both — the same
 * arrangement `configuredAssuranceLevelSchema` uses in `assurance.ts`.
 *
 * Spelled exactly as the specification does, hyphen included in
 * `enhanced-basic`. A near-miss would be an unrecognised grade, which fails
 * closed but would look like a wallet-compatibility bug.
 */
const attestedKeyStorageSchema = z.enum([
  'iso_18045_basic',
  'iso_18045_enhanced-basic',
  'iso_18045_moderate',
  'iso_18045_high',
]);

/** One issuer identifier: an absolute HTTPS URL, exactly as the trust allowlist requires. */
const issuerIdentifierSchema = z
  .url({
    protocol: /^https$/,
    error: 'Each attesting issuer must be an absolute https:// URL',
  })
  .max(MAX_ISSUER_LENGTH);

/** The `{ issuer: grade }` body, once the raw string is JSON-parsed. */
const attestingIssuersSchema = z.record(issuerIdentifierSchema, attestedKeyStorageSchema);

/** The §D.2 grade an issuance ecosystem's key-attestation validation establishes. */
export type AttestedKeyStorageGrade = z.infer<typeof attestedKeyStorageSchema>;

/**
 * Issuer identifier → the key-storage grade its issuance process attests.
 *
 * A prototype-less, frozen map, for the same reason `PerRealmIssuerAllowlist`
 * is: a lookup by an attacker-influenced issuer identifier must not walk
 * `Object.prototype`.
 */
export type AttestingIssuerMap = Readonly<Record<string, AttestedKeyStorageGrade>>;

/** No issuer attests anything — the value of an unset variable. */
const EMPTY_ATTESTING_ISSUERS: AttestingIssuerMap = Object.freeze(
  Object.create(null) as Record<string, AttestedKeyStorageGrade>
);

/** Freeze the validated map into a prototype-less, immutable structure. */
function harden(parsed: Record<string, AttestedKeyStorageGrade>): AttestingIssuerMap {
  const result = Object.create(null) as Record<string, AttestedKeyStorageGrade>;
  for (const [issuer, grade] of Object.entries(parsed)) result[issuer] = grade;
  return Object.freeze(result);
}

/**
 * Parse the raw `OID4VP_ATTESTING_ISSUERS` string into an issuer → grade map.
 *
 * Unset and blank both yield {@link EMPTY_ATTESTING_ISSUERS} — `${VAR:-}` in a
 * compose file is how an operator says "not configured", and that must not take
 * the boot down for a deployment with no interest in wallet federation.
 */
function parseAttestingIssuers(raw: string | undefined, ctx: z.RefinementCtx): AttestingIssuerMap {
  if (raw === undefined || raw.trim() === '') return EMPTY_ATTESTING_ISSUERS;

  let decoded: unknown;
  try {
    decoded = JSON.parse(raw) as unknown;
  } catch {
    ctx.addIssue({
      code: 'custom',
      message:
        'OID4VP_ATTESTING_ISSUERS must be a JSON object mapping issuer identifier to an OID4VCI Appendix D §D.2 key-storage grade, e.g. {"https://pid.issuer.example":"iso_18045_high"}',
    });
    return z.NEVER;
  }

  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
    ctx.addIssue({
      code: 'custom',
      message:
        'OID4VP_ATTESTING_ISSUERS must be a JSON OBJECT keyed by issuer identifier, e.g. {"https://pid.issuer.example":"iso_18045_high"} — a bare array carries no issuer to attach a grade to',
    });
    return z.NEVER;
  }

  for (const issuer of Object.keys(decoded as Record<string, unknown>)) {
    if (PROTOTYPE_KEYS.has(issuer)) {
      ctx.addIssue({
        code: 'custom',
        message: `OID4VP_ATTESTING_ISSUERS: issuer key ${JSON.stringify(issuer)} addresses Object.prototype rather than an issuer`,
      });
      return z.NEVER;
    }
  }

  const result = attestingIssuersSchema.safeParse(decoded);
  if (!result.success) {
    for (const issue of result.error.issues) {
      ctx.addIssue({
        code: 'custom',
        message: `OID4VP_ATTESTING_ISSUERS: ${issue.message}`,
        path: issue.path,
      });
    }
    return z.NEVER;
  }

  const issuerCount = Object.keys(result.data).length;
  if (issuerCount > MAX_ATTESTING_ISSUERS) {
    ctx.addIssue({
      code: 'custom',
      message: `OID4VP_ATTESTING_ISSUERS records ${issuerCount} issuers, more than the ${MAX_ATTESTING_ISSUERS} supported`,
    });
    return z.NEVER;
  }

  return harden(result.data);
}

export const keyAttestationEnvSchema = z.object({
  /**
   * `OID4VP_ATTESTING_ISSUERS` (#308/#379) — issuance chains that validate a
   * wallet's key attestation, and the grade each establishes.
   *
   * ```
   * OID4VP_ATTESTING_ISSUERS={"https://pid.member-state.example":"iso_18045_high"}
   * ```
   *
   * Recording an issuer here does NOT grant assurance by itself. It produces
   * EVIDENCE; a realm reaches a level only when its own `OID4VP_ISSUER_ASSURANCE`
   * names the issuer with `requiresKeyStorage` and its own
   * `OID4VP_TRUSTED_ISSUERS` accepts it.
   *
   * Typed `z.string()` because every environment variable is a string; the JSON
   * decoding happens in the field transform so failures carry a message that
   * names the variable and shows the expected shape.
   */
  OID4VP_ATTESTING_ISSUERS: z
    .string()
    .max(
      MAX_RAW_LENGTH,
      `OID4VP_ATTESTING_ISSUERS must be at most ${MAX_RAW_LENGTH} characters — a record that large is a configuration mistake`
    )
    .optional()
    .transform(parseAttestingIssuers),
});

/** Key-attestation environment configuration type. */
export type KeyAttestationEnv = z.infer<typeof keyAttestationEnvSchema>;
