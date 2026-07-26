/**
 * The FORMAT-ADAPTER BOUNDARY (issue #233, epic #231).
 *
 * OID4VP is credential-format agnostic: the format shows up in exactly two
 * places on the wire — the DCQL Credential Query (§6.1 `format` + format-specific
 * `meta`) and the `vp_token` entry the wallet returns (§8.1). This module is
 * that seam, and it exists so ISO mdoc (`mso_mdoc`) can be added later as a
 * second adapter WITHOUT rewriting the request builder or the response endpoint
 * — the tracked fast-follow named in epic #231.
 *
 * First target is **SD-JWT VC** (`dc+sd-jwt`), per #231's DECIDED 2026-07-20
 * note: QAuth is JOSE/JWT-native (mdoc needs a CBOR/COSE stack QAuth does not
 * have and #298 does not add), it is the EUDI PID primary encoding, and its flat
 * claim model maps directly onto `user_attributes`.
 *
 * ## What an adapter may NOT do
 *
 * An adapter is a STRUCTURAL parser, never a validator. It answers "is this
 * shaped like the format it claims to be", and nothing else — no signature
 * check, no disclosure digest check, no `vct` check, no issuer resolution, no
 * key binding. Those are #234 (presentation validation) and #236 (issuer trust),
 * and until both exist, anything this layer returns must be treated as
 * ATTACKER-SUPPLIED. See {@link PresentedCredential}.
 */

import type { CredentialFormat } from '../profiles/verifier-profile.types';
import type { DcqlClaimsQuery, DcqlCredentialQuery } from './dcql';

/** SD-JWT VC format identifier (OID4VP 1.0 Annex B / SD-JWT VC). */
export const SD_JWT_VC_FORMAT = 'dc+sd-jwt' satisfies CredentialFormat;

/**
 * What the caller wants, expressed format-independently.
 *
 * The request builder speaks only this; the adapter turns it into a
 * format-specific {@link DcqlCredentialQuery}.
 */
export interface CredentialRequestSpec {
  /** DCQL Credential Query id; the `vp_token` response is keyed by it. */
  readonly id: string;
  readonly format: CredentialFormat;
  /**
   * Accepted credential type identifiers, format-interpreted: `vct_values` for
   * `dc+sd-jwt`, and (later) `doctype_value` for `mso_mdoc`.
   *
   * REQUIRED and non-empty for every adapter shipped so far. A query with no
   * type constraint asks the wallet for "any credential you happen to hold",
   * which is both a privacy problem (OID4VP §15.6 tells Verifiers not to
   * over-ask) and an unanswerable trust question downstream.
   */
  readonly typeValues: readonly string[];
  /** Claims to request; omitted means "the whole credential" (§6.1). */
  readonly claims?: readonly DcqlClaimsQuery[];
  /** Whether more than one matching Presentation is acceptable (§6.1). */
  readonly multiple?: boolean;
}

/**
 * One entry pulled out of a `vp_token` — STRUCTURALLY parsed, NOT validated.
 *
 * There is deliberately no `subject`, no `claims` and no `issuer` field on this
 * type, and adding one is out of scope for #233. This layer proves that a party
 * round-tripped our `state` and posted something shaped like a credential. It
 * proves NOTHING about who they are: identity requires the credential to be
 * validated (#234) and its issuer to be trusted (#236), and there is no
 * protocol-guaranteed stable wallet subject identifier at all (ADR-009 / #300).
 * A field here that looked like identity would be read as identity.
 */
export interface PresentedCredential {
  /** The DCQL Credential Query id this Presentation answers. */
  readonly queryId: string;
  readonly format: CredentialFormat;
  /**
   * The raw, UNVERIFIED Presentation exactly as the wallet sent it. Opaque at
   * this layer — pass it to #234, never interpret it here.
   */
  readonly presentation: string;
}

/**
 * A credential format QAuth can express in DCQL and structurally recognise in a
 * `vp_token`.
 */
export interface CredentialFormatAdapter {
  readonly format: CredentialFormat;
  /**
   * Turn a format-independent spec into a format-specific DCQL Credential Query.
   *
   * @throws Error when the spec cannot be expressed in this format.
   */
  buildCredentialQuery(spec: CredentialRequestSpec): DcqlCredentialQuery;
  /**
   * Structurally recognise ONE `vp_token` entry. Never validates.
   *
   * @throws Error when the value is not shaped like this format.
   */
  parsePresentation(queryId: string, value: unknown): PresentedCredential;
}

/**
 * Upper bound on the byte length of a single Presentation we will even look at.
 *
 * A DoS guard, not a spec limit: the response endpoint is unauthenticated by
 * construction (a wallet has no client credentials), so an entry that is
 * obviously too large must be dropped before anything walks it.
 */
export const MAX_PRESENTATION_LENGTH = 64 * 1024;

/** Compact JWS: three non-empty base64url segments. */
const COMPACT_JWS_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * SD-JWT VC adapter (`dc+sd-jwt`).
 *
 * Query side: `meta.vct_values` (OID4VP 1.0 §6.4.1 / Annex B.3.5) constrains
 * which Verifiable Credential Types are acceptable.
 *
 * Parse side: an SD-JWT VC Presentation is the compact serialization
 * `<Issuer-signed JWT>~<Disclosure>*~<KB-JWT>?`. We check that shape and stop.
 * The Issuer-signed JWT's SIGNATURE, the Disclosure digests and the Key Binding
 * JWT's `nonce`/`aud` are all #234's job — checking any of them here would make
 * this endpoint look like it authenticates, which is precisely the confusion
 * #233 must not create.
 */
export const sdJwtVcAdapter: CredentialFormatAdapter = {
  format: SD_JWT_VC_FORMAT,

  buildCredentialQuery(spec: CredentialRequestSpec): DcqlCredentialQuery {
    if (spec.typeValues.length === 0) {
      throw new Error(
        `Credential request '${spec.id}' declares no accepted 'vct' value. An SD-JWT VC query with no 'meta.vct_values' asks the wallet for any credential it holds, which OID4VP 1.0 §15.6 warns Verifiers against and leaves #236 nothing to make a trust decision on.`
      );
    }

    return {
      id: spec.id,
      format: SD_JWT_VC_FORMAT,
      ...(spec.multiple === true ? { multiple: true } : {}),
      meta: { vct_values: [...spec.typeValues] },
      ...(spec.claims === undefined ? {} : { claims: spec.claims }),
    };
  },

  parsePresentation(queryId: string, value: unknown): PresentedCredential {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(
        `vp_token entry for '${queryId}' is not a string. An SD-JWT VC Presentation is the compact serialization, which is always a string (OID4VP 1.0 §8.1).`
      );
    }

    if (value.length > MAX_PRESENTATION_LENGTH) {
      throw new Error(
        `vp_token entry for '${queryId}' exceeds the ${MAX_PRESENTATION_LENGTH}-character bound QAuth accepts.`
      );
    }

    // `<Issuer-signed JWT>~<Disclosure>*~<KB-JWT>?` — the tilde-separated form.
    // A trailing `~` (no Key Binding JWT) is valid and yields an empty last
    // segment, so only the FIRST segment is constrained here.
    const [issuerSignedJwt] = value.split('~');

    if (!COMPACT_JWS_PATTERN.test(issuerSignedJwt)) {
      throw new Error(
        `vp_token entry for '${queryId}' does not begin with a compact-serialized Issuer-signed JWT, so it is not an SD-JWT VC Presentation. Structure only — its signature is NOT checked here (#234).`
      );
    }

    return { queryId, format: SD_JWT_VC_FORMAT, presentation: value };
  },
};

/**
 * Every format adapter QAuth ships.
 *
 * `mso_mdoc` is deliberately ABSENT — `haip-1.0` declares it as a permitted
 * format, and a deployment that selected it must be refused by
 * {@link resolveCredentialFormatAdapter} rather than silently served a
 * credential shape QAuth cannot read. ISO/IEC 18013-5 is paywalled; the mdoc
 * adapter needs the standard first (epic #231).
 */
const CREDENTIAL_FORMAT_ADAPTERS: Readonly<
  Partial<Record<CredentialFormat, CredentialFormatAdapter>>
> = Object.freeze({
  [SD_JWT_VC_FORMAT]: sdJwtVcAdapter,
});

/**
 * Resolve the adapter for a format, fail-closed (issue #233).
 *
 * Two independent gates, and both must pass:
 *   1. QAuth must SHIP an adapter for the format.
 *   2. The active {@link VerifierProfile} must PERMIT it — a profile's
 *      `credentialFormats` is a posture statement, and asking a wallet for a
 *      format the profile forbids is the leak the profile table exists to stop.
 *
 * The profile check is the caller's to pass in rather than read here, so this
 * module keeps no opinion about which profile is active.
 *
 * @param format - the requested credential format.
 * @param permitted - formats the active profile permits.
 * @throws Error when the format is unshipped or profile-forbidden.
 */
export function resolveCredentialFormatAdapter(
  format: CredentialFormat,
  permitted: readonly CredentialFormat[]
): CredentialFormatAdapter {
  if (!permitted.includes(format)) {
    throw new Error(
      `Credential format '${format}' is not permitted by the active verifier profile (permitted: ${permitted.join(', ') || 'none'}).`
    );
  }

  const adapter = CREDENTIAL_FORMAT_ADAPTERS[format];

  if (adapter === undefined) {
    throw new Error(
      `No credential format adapter is implemented for '${format}'. QAuth ships '${SD_JWT_VC_FORMAT}' only; 'mso_mdoc' is the tracked fast-follow behind this same boundary (epic #231) and needs ISO/IEC 18013-5 first.`
    );
  }

  return adapter;
}
