import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  WebAuthnAlgorithm,
  WebAuthnTransport,
} from './webauthn.types';

/**
 * The seam between QAuth and the library that checks WebAuthn responses
 * (ADR-017 Decision 14, issue #467).
 *
 * Everything that decodes CBOR, COSE and attestation statements, and verifies a
 * signature, sits behind this interface; nothing else in QAuth imports the
 * library. ADR-018 §6 plans WebAuthn verification in the Rust core later, and
 * that move is then one new implementation of this interface. The ceremony
 * rules that do not need the library (which challenge, which origins, which RP
 * ID, whether user verification is required, the sign counter) belong to the
 * provider and the transaction, and reach an implementation as inputs.
 *
 * An implementation checks, in this order, and throws a `WebAuthnRejection`
 * with the matching reason at the first failure:
 *
 * 1. the response decodes (`malformed-response`);
 * 2. `clientDataJSON.type` is the ceremony's (`ceremony-mismatch`);
 * 3. `clientDataJSON.challenge` equals the expected challenge
 *    (`challenge-mismatch`);
 * 4. `clientDataJSON.origin` is one of the expected origins
 *    (`origin-mismatch`), and the ceremony was not cross-origin
 *    (`cross-origin`);
 * 5. the RP ID hash is the SHA-256 of the expected RP ID (`rp-id-mismatch`);
 * 6. UP is set (`user-not-present`), and UV when required
 *    (`user-not-verified`); BS is not set without BE (`malformed-response`);
 * 7. for registration: the key is ES256, EdDSA or RS256
 *    (`unsupported-algorithm`) and the attestation statement verifies
 *    (`attestation-invalid`); for authentication: the response names the given
 *    credential (`credential-mismatch`) and the signature verifies under its
 *    key (`signature-invalid`).
 *
 * It never trusts an attestation chain: QAuth asks for `attestation: "none"`,
 * so an attestation statement is checked for consistency and the credential
 * is treated as self-attested (WebAuthn Level 3 §7.1 step 24).
 */
export interface WebAuthnVerifier {
  verifyRegistration(check: RegistrationCheck): Promise<VerifiedRegistration>;
  verifyAssertion(check: AssertionCheck): Promise<VerifiedAssertion>;
}

/** What a registration response must match. */
export interface RegistrationCheck {
  readonly response: RegistrationResponseJSON;
  /** The transaction's challenge, base64url. */
  readonly expectedChallenge: string;
  readonly expectedOrigins: readonly string[];
  readonly expectedRpId: string;
  readonly requireUserVerification: boolean;
}

/** A registration that verified: the credential to store. */
export interface VerifiedRegistration {
  /** The credential id from the authenticator data, base64url. */
  readonly credentialId: string;
  /** The credential public key as the authenticator wrote it: a COSE_Key, base64url. */
  readonly publicKey: string;
  readonly algorithm: WebAuthnAlgorithm;
  readonly signCount: number;
  /** The authenticator's AAGUID, as a UUID string. All zeros when the client removed it. */
  readonly aaguid: string;
  /** The attestation statement format, such as `none` or `packed`. */
  readonly attestationFormat: string;
  readonly userVerified: boolean;
  /** The BE flag: the credential may be synced to other devices. */
  readonly backupEligible: boolean;
  /** The BS flag: the credential is synced now. */
  readonly backedUp: boolean;
  /** The origin the ceremony ran on. */
  readonly origin: string;
  readonly transports: readonly WebAuthnTransport[];
}

/** The stored credential an assertion is checked against. */
export interface AssertionCredential {
  /** The credential id, base64url. */
  readonly id: string;
  /** The stored COSE_Key, base64url. */
  readonly publicKey: string;
}

/** What an assertion must match. */
export interface AssertionCheck {
  readonly response: AuthenticationResponseJSON;
  readonly expectedChallenge: string;
  readonly expectedOrigins: readonly string[];
  readonly expectedRpId: string;
  readonly requireUserVerification: boolean;
  readonly credential: AssertionCredential;
}

/** An assertion that verified. The sign counter is reported, not judged here. */
export interface VerifiedAssertion {
  readonly credentialId: string;
  readonly signCount: number;
  readonly userVerified: boolean;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly origin: string;
  /** The user handle the authenticator returned, base64url, if any. */
  readonly userHandle: string | undefined;
}
