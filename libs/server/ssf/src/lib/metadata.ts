import { SSF_PATHS, SSF_PUSH_METHOD, SSF_SPEC_VERSION } from './constants';

/**
 * Transmitter Configuration Metadata (SSF 1.0 §7.1), served at
 * `/.well-known/ssf-configuration` (§7.2).
 *
 * Every URL is built from the realm's issuer, never from the request, as
 * QAuth's other discovery documents are (ADR-019 Decision 1). The issuer is
 * the `iss` of every SET the realm's transmitter signs, which §7.1 requires.
 */
export interface TransmitterMetadata {
  readonly spec_version: string;
  readonly issuer: string;
  readonly jwks_uri: string;
  readonly delivery_methods_supported: readonly string[];
  readonly configuration_endpoint: string;
  readonly status_endpoint: string;
  readonly add_subject_endpoint: string;
  readonly remove_subject_endpoint: string;
  readonly verification_endpoint: string;
  readonly authorization_schemes: ReadonlyArray<{ readonly spec_urn: string }>;
  readonly default_subjects: 'ALL' | 'NONE';
}

const SLASH = 0x2f;

/**
 * The issuer without trailing `/`s, the base of every URL the metadata names.
 *
 * A scan from the end, not `replace(/\/+$/, '')`: that pattern backtracks
 * quadratically on a long run of `/` that does not end the string.
 */
export function issuerBase(issuer: string): string {
  let end = issuer.length;
  while (end > 0 && issuer.charCodeAt(end - 1) === SLASH) end -= 1;
  return issuer.slice(0, end);
}

/**
 * The transmitter metadata of a realm.
 *
 * - Push delivery only (RFC 8935).
 * - Receivers authenticate with an OAuth 2.0 access token (`urn:ietf:rfc:6749`)
 *   that carries the `ssf:stream` scope.
 * - `default_subjects` is `NONE`: a stream receives events only about the
 *   subjects its receiver adds.
 *
 * @param issuer - The realm's issuer.
 */
export function buildTransmitterMetadata(issuer: string): TransmitterMetadata {
  const base = issuerBase(issuer);
  return {
    spec_version: SSF_SPEC_VERSION,
    // The realm's issuer as stored: the signer writes the same value as `iss`.
    issuer,
    jwks_uri: `${base}/.well-known/jwks.json`,
    delivery_methods_supported: [SSF_PUSH_METHOD],
    configuration_endpoint: `${base}${SSF_PATHS.stream}`,
    status_endpoint: `${base}${SSF_PATHS.status}`,
    add_subject_endpoint: `${base}${SSF_PATHS.addSubject}`,
    remove_subject_endpoint: `${base}${SSF_PATHS.removeSubject}`,
    verification_endpoint: `${base}${SSF_PATHS.verify}`,
    authorization_schemes: [{ spec_urn: 'urn:ietf:rfc:6749' }],
    default_subjects: 'NONE',
  };
}
