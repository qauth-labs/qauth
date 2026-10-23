import { createHash, timingSafeEqual } from 'node:crypto';

import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import {
  convertAAGUIDToString,
  cose,
  decodeAttestationObject,
  decodeCredentialPublicKey,
  isoBase64URL,
  parseAuthenticatorData,
} from '@simplewebauthn/server/helpers';
import { z } from 'zod';

import {
  isWebAuthnAlgorithm,
  knownTransports,
  WEBAUTHN_ALGORITHMS,
  type WebAuthnAlgorithm,
} from './webauthn.types';
import { WebAuthnRejection } from './webauthn-rejection';
import type {
  AssertionCheck,
  RegistrationCheck,
  VerifiedAssertion,
  VerifiedRegistration,
  WebAuthnVerifier,
} from './webauthn-verifier';

/**
 * The {@link WebAuthnVerifier} built on SimpleWebAuthn (`@simplewebauthn/server`,
 * issue #467).
 *
 * Why a library at all: a registration carries a CBOR attestation object whose
 * authenticator data holds a COSE key, and up to seven attestation statement
 * formats can arrive even when `none` is asked for (a client MAY keep the
 * authenticator's own statement). Decoding CBOR and COSE, converting COSE keys
 * to verifiable keys for three algorithm families and checking packed, TPM and
 * Android statements is a large surface to own, and a well-reviewed library is
 * the safer place for it. SimpleWebAuthn is maintained, MIT-licensed, written
 * for Node, and supports ES256, EdDSA and RS256. Its one advisory,
 * GHSA-6hxq-p678-4hr2 (attestation chains not checked against the configured
 * anchor), was fixed in 13.3.2; QAuth pins 14.0.3 and trusts no chain anyway.
 *
 * Why QAuth still checks the ceremony itself: the library's errors are plain
 * messages, and a refusal must carry a reason a test and an operator can rely
 * on. So the client data and authenticator data checks run here first, in the
 * order the interface documents, each with its reason, and the library then
 * repeats them while it does the cryptography. A library update that weakened
 * one of its checks would not weaken QAuth's.
 *
 * Two of the library's behaviours are set aside on purpose:
 *
 * - the sign counter: the library refuses a counter that does not grow. QAuth
 *   FLAGS a counter that goes backwards instead (the provider decides, from
 *   the stored record), so the library is handed a stored counter of 0, which
 *   turns its check off;
 * - cross-origin ceremonies: the library accepts `crossOrigin: true` without a
 *   `topOrigin` (Safari sends none). QAuth's pages are never framed, so any
 *   cross-origin ceremony is refused here.
 */
export function createSimpleWebAuthnVerifier(): WebAuthnVerifier {
  return {
    async verifyRegistration(check: RegistrationCheck): Promise<VerifiedRegistration> {
      const clientData = readClientData(check.response.response.clientDataJSON);
      assertClientData(clientData, 'webauthn.create', check);

      const { fmt, authData } = decodeRegistrationAuthData(
        check.response.response.attestationObject
      );
      const parsed = parseAuthData(authData);
      assertAuthenticatorData(parsed, check);

      if (!parsed.credentialID || !parsed.credentialPublicKey || !parsed.aaguid) {
        throw new WebAuthnRejection('malformed-response');
      }
      const credentialId = isoBase64URL.fromBuffer(parsed.credentialID);
      if (credentialId !== check.response.id || check.response.rawId !== check.response.id) {
        throw new WebAuthnRejection('malformed-response');
      }
      const algorithm = credentialAlgorithm(parsed.credentialPublicKey);

      let verified: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
      try {
        verified = await verifyRegistrationResponse({
          response: {
            id: check.response.id,
            rawId: check.response.rawId,
            type: 'public-key',
            response: {
              clientDataJSON: check.response.response.clientDataJSON,
              attestationObject: check.response.response.attestationObject,
            },
            clientExtensionResults: {},
          },
          expectedChallenge: check.expectedChallenge,
          expectedOrigin: [...check.expectedOrigins],
          expectedRPID: check.expectedRpId,
          expectedType: 'webauthn.create',
          requireUserPresence: true,
          requireUserVerification: check.requireUserVerification,
          supportedAlgorithmIDs: [...WEBAUTHN_ALGORITHMS],
        });
      } catch (error) {
        throw new WebAuthnRejection('attestation-invalid', { cause: error });
      }
      if (!verified.verified) throw new WebAuthnRejection('attestation-invalid');

      return {
        credentialId,
        publicKey: isoBase64URL.fromBuffer(parsed.credentialPublicKey),
        algorithm,
        signCount: parsed.counter,
        aaguid: convertAAGUIDToString(parsed.aaguid),
        attestationFormat: fmt,
        userVerified: parsed.flags.uv,
        backupEligible: parsed.flags.be,
        backedUp: parsed.flags.bs,
        origin: clientData.origin,
        transports: knownTransports(check.response.response.transports),
      };
    },

    async verifyAssertion(check: AssertionCheck): Promise<VerifiedAssertion> {
      const clientData = readClientData(check.response.response.clientDataJSON);
      assertClientData(clientData, 'webauthn.get', check);

      const parsed = parseAuthData(decodeBytes(check.response.response.authenticatorData));
      assertAuthenticatorData(parsed, check);

      if (check.response.id !== check.credential.id || check.response.rawId !== check.response.id) {
        throw new WebAuthnRejection('credential-mismatch');
      }

      let verified: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
      try {
        verified = await verifyAuthenticationResponse({
          response: {
            id: check.response.id,
            rawId: check.response.rawId,
            type: 'public-key',
            response: {
              clientDataJSON: check.response.response.clientDataJSON,
              authenticatorData: check.response.response.authenticatorData,
              signature: check.response.response.signature,
              ...(check.response.response.userHandle === undefined
                ? {}
                : { userHandle: check.response.response.userHandle }),
            },
            clientExtensionResults: {},
          },
          expectedChallenge: check.expectedChallenge,
          expectedOrigin: [...check.expectedOrigins],
          expectedRPID: check.expectedRpId,
          expectedType: 'webauthn.get',
          requireUserVerification: check.requireUserVerification,
          // A stored counter of 0 turns the library's own counter refusal off;
          // the provider flags a counter that goes backwards (see above).
          credential: {
            id: check.credential.id,
            publicKey: decodeBytes(check.credential.publicKey),
            counter: 0,
          },
        });
      } catch (error) {
        throw new WebAuthnRejection('signature-invalid', { cause: error });
      }
      if (!verified.verified) throw new WebAuthnRejection('signature-invalid');

      return {
        credentialId: check.credential.id,
        signCount: parsed.counter,
        userVerified: parsed.flags.uv,
        backupEligible: parsed.flags.be,
        backedUp: parsed.flags.bs,
        origin: clientData.origin,
        userHandle: check.response.response.userHandle,
      };
    },
  };
}

/** `CollectedClientData` (WebAuthn Level 3 §5.8.1): the members QAuth checks. */
const clientDataSchema = z.object({
  type: z.string(),
  challenge: z.string(),
  origin: z.string(),
  crossOrigin: z.boolean().optional(),
  topOrigin: z.string().optional(),
});

type ClientData = z.infer<typeof clientDataSchema>;

function decodeBytes(base64url: string): Uint8Array<ArrayBuffer> {
  try {
    return isoBase64URL.toBuffer(base64url);
  } catch (error) {
    throw new WebAuthnRejection('malformed-response', { cause: error });
  }
}

function readClientData(encoded: string): ClientData {
  let json: unknown;
  try {
    json = JSON.parse(Buffer.from(decodeBytes(encoded)).toString('utf8'));
  } catch (error) {
    throw new WebAuthnRejection('malformed-response', { cause: error });
  }
  const parsed = clientDataSchema.safeParse(json);
  if (!parsed.success) throw new WebAuthnRejection('malformed-response', { cause: parsed.error });
  return parsed.data;
}

/** Steps 2–4 of the interface: ceremony type, challenge, origin, not cross-origin. */
function assertClientData(
  clientData: ClientData,
  expectedType: 'webauthn.create' | 'webauthn.get',
  check: Pick<RegistrationCheck, 'expectedChallenge' | 'expectedOrigins'>
): void {
  if (clientData.type !== expectedType) throw new WebAuthnRejection('ceremony-mismatch');
  if (!constantTimeEqual(clientData.challenge, check.expectedChallenge)) {
    throw new WebAuthnRejection('challenge-mismatch');
  }
  if (!check.expectedOrigins.includes(clientData.origin)) {
    throw new WebAuthnRejection('origin-mismatch');
  }
  if (clientData.crossOrigin === true || clientData.topOrigin !== undefined) {
    throw new WebAuthnRejection('cross-origin');
  }
}

type ParsedAuthData = ReturnType<typeof parseAuthenticatorData>;

function decodeRegistrationAuthData(encoded: string): { fmt: string; authData: Uint8Array } {
  try {
    const attestationObject = decodeAttestationObject(decodeBytes(encoded));
    const fmt = attestationObject.get('fmt');
    const authData = attestationObject.get('authData');
    if (typeof fmt !== 'string' || !(authData instanceof Uint8Array)) {
      throw new Error('attestation object lacks fmt or authData');
    }
    return { fmt, authData };
  } catch (error) {
    if (error instanceof WebAuthnRejection) throw error;
    throw new WebAuthnRejection('malformed-response', { cause: error });
  }
}

function parseAuthData(authData: Uint8Array): ParsedAuthData {
  try {
    return parseAuthenticatorData(new Uint8Array(authData));
  } catch (error) {
    throw new WebAuthnRejection('malformed-response', { cause: error });
  }
}

/** Steps 5–6 of the interface: RP ID hash, then the UP, UV, BE and BS flags. */
function assertAuthenticatorData(
  parsed: ParsedAuthData,
  check: Pick<RegistrationCheck, 'expectedRpId' | 'requireUserVerification'>
): void {
  const expectedHash = createHash('sha256').update(check.expectedRpId, 'ascii').digest();
  if (
    parsed.rpIdHash.length !== expectedHash.length ||
    !timingSafeEqual(parsed.rpIdHash, expectedHash)
  ) {
    throw new WebAuthnRejection('rp-id-mismatch');
  }
  if (!parsed.flags.up) throw new WebAuthnRejection('user-not-present');
  if (check.requireUserVerification && !parsed.flags.uv) {
    throw new WebAuthnRejection('user-not-verified');
  }
  // WebAuthn Level 3 §6.1: a credential that is not backup eligible cannot be backed up.
  if (parsed.flags.bs && !parsed.flags.be) throw new WebAuthnRejection('malformed-response');
}

function credentialAlgorithm(publicKey: Uint8Array): WebAuthnAlgorithm {
  let alg: unknown;
  try {
    alg = decodeCredentialPublicKey(new Uint8Array(publicKey)).get(cose.COSEKEYS.alg);
  } catch (error) {
    throw new WebAuthnRejection('malformed-response', { cause: error });
  }
  if (!isWebAuthnAlgorithm(alg)) throw new WebAuthnRejection('unsupported-algorithm');
  return alg;
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}
