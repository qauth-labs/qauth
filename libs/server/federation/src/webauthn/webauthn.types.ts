/**
 * The WebAuthn vocabulary QAuth speaks (ADR-017 Decision 14, issue #467),
 * written against WebAuthn Level 3 (W3C Recommendation), not against the
 * library that verifies it. The browser side uses the JSON forms of §5.1
 * (`PublicKeyCredential.toJSON()`, `parseCreationOptionsFromJSON()`,
 * `parseRequestOptionsFromJSON()`), so options and responses cross the wire as
 * JSON with base64url byte strings.
 */
import { z } from 'zod';

/**
 * The COSE algorithm identifiers QAuth accepts for a credential key (IANA COSE
 * Algorithms registry): EdDSA (-8), ES256 (-7) and RS256 (-257). The order is
 * the preference order of `pubKeyCredParams`. Nothing else is accepted, so a
 * key type QAuth has not reviewed never becomes a credential.
 */
export const WEBAUTHN_ALGORITHMS = Object.freeze([-8, -7, -257] as const);

/** One of {@link WEBAUTHN_ALGORITHMS}. */
export type WebAuthnAlgorithm = (typeof WEBAUTHN_ALGORITHMS)[number];

/** The algorithm names, for logs and documentation. */
export const WEBAUTHN_ALGORITHM_NAMES: Readonly<Record<WebAuthnAlgorithm, string>> = Object.freeze({
  [-8]: 'EdDSA',
  [-7]: 'ES256',
  [-257]: 'RS256',
});

export function isWebAuthnAlgorithm(value: unknown): value is WebAuthnAlgorithm {
  return (WEBAUTHN_ALGORITHMS as readonly unknown[]).includes(value);
}

/**
 * The transports of WebAuthn Level 3 §5.8.4 (`AuthenticatorTransport`). A
 * client may report others; they are dropped, as §5.8.4 asks of a relying
 * party that does not know them.
 */
export const WEBAUTHN_TRANSPORTS = Object.freeze([
  'ble',
  'hybrid',
  'internal',
  'nfc',
  'smart-card',
  'usb',
] as const);

export type WebAuthnTransport = (typeof WEBAUTHN_TRANSPORTS)[number];

/** Keep the transports QAuth knows, once each, in a stable order. */
export function knownTransports(values: readonly string[] | undefined): WebAuthnTransport[] {
  if (!values) return [];
  return WEBAUTHN_TRANSPORTS.filter((transport) => values.includes(transport));
}

/**
 * What a ceremony is for, which decides its user-verification rule.
 *
 * - `sign-in` — the passkey signs the user in on its own. Registration asks for
 *   a discoverable credential, and both ceremonies REQUIRE user verification:
 *   the UV flag must be set, checked on the server (ADR-017 F2b).
 * - `second-factor` — the credential follows another factor, such as a
 *   password. User verification is preferred, not required; user presence still
 *   is.
 */
export type WebAuthnPurpose = 'sign-in' | 'second-factor';

export const WEBAUTHN_PURPOSES: readonly WebAuthnPurpose[] = Object.freeze([
  'sign-in',
  'second-factor',
]);

/** The two ceremonies (WebAuthn Level 3 §7.1 and §7.2). */
export type WebAuthnCeremony = 'registration' | 'authentication';

/**
 * Longest base64url string QAuth reads from a response. Generous: an RS256
 * attestation object with a certificate chain is a few kilobytes, and a
 * credential id is at most 1023 bytes (§5.1.3 step 16).
 */
const MAX_ENCODED_LENGTH = 16_384;

/** A base64url string, no padding, bounded. */
const base64url = z
  .string()
  .min(1)
  .max(MAX_ENCODED_LENGTH)
  .regex(/^[A-Za-z0-9_-]+$/, 'must be base64url without padding');

/** A credential id: 1–1023 bytes, so at most 1364 base64url characters. */
const credentialIdSchema = base64url.max(1364);

/**
 * `RegistrationResponseJSON` (WebAuthn Level 3 §5.1). Only the members QAuth
 * reads are checked; the rest pass through, since a newer browser may add some.
 */
export const registrationResponseSchema = z.object({
  id: credentialIdSchema,
  rawId: credentialIdSchema,
  type: z.literal('public-key'),
  response: z.object({
    clientDataJSON: base64url,
    attestationObject: base64url,
    transports: z.array(z.string().max(32)).max(16).optional(),
  }),
  authenticatorAttachment: z.string().max(32).optional(),
  clientExtensionResults: z.record(z.string(), z.unknown()).optional(),
});

export type RegistrationResponseJSON = z.infer<typeof registrationResponseSchema>;

/** `AuthenticationResponseJSON` (WebAuthn Level 3 §5.1). */
export const authenticationResponseSchema = z.object({
  id: credentialIdSchema,
  rawId: credentialIdSchema,
  type: z.literal('public-key'),
  response: z.object({
    clientDataJSON: base64url,
    authenticatorData: base64url,
    signature: base64url,
    // A user handle is at most 64 bytes (§5.4.3), 86 base64url characters.
    userHandle: base64url.max(86).optional(),
  }),
  authenticatorAttachment: z.string().max(32).optional(),
  clientExtensionResults: z.record(z.string(), z.unknown()).optional(),
});

export type AuthenticationResponseJSON = z.infer<typeof authenticationResponseSchema>;

/** `PublicKeyCredentialDescriptorJSON` (§5.1). */
export interface CredentialDescriptorJSON {
  readonly type: 'public-key';
  readonly id: string;
  readonly transports?: readonly WebAuthnTransport[];
}

/** `PublicKeyCredentialCreationOptionsJSON` (§5.1), as QAuth fills it. */
export interface CreationOptionsJSON {
  readonly rp: { readonly id: string; readonly name: string };
  readonly user: { readonly id: string; readonly name: string; readonly displayName: string };
  readonly challenge: string;
  readonly pubKeyCredParams: readonly {
    readonly type: 'public-key';
    readonly alg: WebAuthnAlgorithm;
  }[];
  readonly timeout: number;
  readonly excludeCredentials: readonly CredentialDescriptorJSON[];
  readonly authenticatorSelection: {
    readonly residentKey: 'required' | 'discouraged';
    readonly requireResidentKey: boolean;
    readonly userVerification: 'required' | 'preferred';
  };
  readonly attestation: 'none';
  readonly extensions: { readonly credProps: true };
}

/** `PublicKeyCredentialRequestOptionsJSON` (§5.1), as QAuth fills it. */
export interface RequestOptionsJSON {
  readonly challenge: string;
  readonly rpId: string;
  readonly timeout: number;
  readonly allowCredentials: readonly CredentialDescriptorJSON[];
  readonly userVerification: 'required' | 'preferred';
}
