import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  hexToBase64Url,
  W3C_VECTOR_ORIGIN,
  W3C_VECTOR_RP_ID,
  W3C_WEBAUTHN_VECTORS,
  w3cAuthenticationResponse,
  w3cRegistrationResponse,
  type W3cWebAuthnVector,
} from '../../testing/webauthn-w3c-vectors.fixture';
import { createSimpleWebAuthnVerifier } from './simplewebauthn-verifier';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from './webauthn.types';
import { WebAuthnRejection, type WebAuthnRejectionReason } from './webauthn-rejection';
import type { AssertionCheck, RegistrationCheck } from './webauthn-verifier';

/**
 * The library seam against the WebAuthn Level 3 §16 test vectors (issue #467):
 * a registration and an assertion of each accepted algorithm verify, and each
 * refusal fires for its own reason.
 */

const verifier = createSimpleWebAuthnVerifier();

function registrationCheck(
  vector: W3cWebAuthnVector,
  overrides: Partial<RegistrationCheck> = {}
): RegistrationCheck {
  return {
    response: w3cRegistrationResponse(vector) as RegistrationResponseJSON,
    expectedChallenge: hexToBase64Url(vector.registration.challenge),
    expectedOrigins: [W3C_VECTOR_ORIGIN],
    expectedRpId: W3C_VECTOR_RP_ID,
    requireUserVerification: false,
    ...overrides,
  };
}

async function assertionCheck(
  vector: W3cWebAuthnVector,
  overrides: Partial<AssertionCheck> = {}
): Promise<AssertionCheck> {
  const registered = await verifier.verifyRegistration(registrationCheck(vector));
  return {
    response: w3cAuthenticationResponse(vector) as AuthenticationResponseJSON,
    expectedChallenge: hexToBase64Url(vector.authentication.challenge),
    expectedOrigins: [W3C_VECTOR_ORIGIN],
    expectedRpId: W3C_VECTOR_RP_ID,
    requireUserVerification: false,
    credential: { id: registered.credentialId, publicKey: registered.publicKey },
    ...overrides,
  };
}

async function rejectionOf(promise: Promise<unknown>): Promise<WebAuthnRejectionReason> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught
  );
  expect(error).toBeInstanceOf(WebAuthnRejection);
  return (error as WebAuthnRejection).reason;
}

/** A base64url clientDataJSON with one member replaced. */
function withClientData(encoded: string, patch: Record<string, unknown>): string {
  const clientData = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  return Buffer.from(JSON.stringify({ ...clientData, ...patch })).toString('base64url');
}

describe('createSimpleWebAuthnVerifier against the WebAuthn Level 3 test vectors', () => {
  describe('registration (§16)', () => {
    it.each([
      ['ES256', 'packedEs256', -7, 'packed'],
      ['ES256', 'noneEs256', -7, 'none'],
      ['ES256', 'packedSelfEs256', -7, 'packed'],
      ['RS256', 'packedRs256', -257, 'packed'],
      ['EdDSA', 'packedEd25519', -8, 'packed'],
    ] as const)('verifies an %s credential (%s)', async (_name, vectorName, alg, fmt) => {
      const vector = W3C_WEBAUTHN_VECTORS[vectorName];

      const registered = await verifier.verifyRegistration(registrationCheck(vector));

      expect(registered).toMatchObject({
        credentialId: hexToBase64Url(vector.credentialId),
        algorithm: alg,
        attestationFormat: fmt,
        signCount: 0,
        origin: W3C_VECTOR_ORIGIN,
        transports: ['internal'],
      });
      expect(registered.publicKey.length).toBeGreaterThan(0);
    });

    it('reads the backup flags and user verification from the authenticator data', async () => {
      // §16.10 sets UV, BE and BS; §16.11 sets none of them.
      await expect(
        verifier.verifyRegistration(registrationCheck(W3C_WEBAUTHN_VECTORS.packedRs256))
      ).resolves.toMatchObject({ userVerified: true, backupEligible: true, backedUp: true });
      await expect(
        verifier.verifyRegistration(registrationCheck(W3C_WEBAUTHN_VECTORS.packedEd25519))
      ).resolves.toMatchObject({ userVerified: false, backupEligible: false, backedUp: false });
    });

    it('accepts a user-verified registration when verification is required', async () => {
      await expect(
        verifier.verifyRegistration(
          registrationCheck(W3C_WEBAUTHN_VECTORS.packedEs256, { requireUserVerification: true })
        )
      ).resolves.toMatchObject({ userVerified: true });
    });

    it('refuses a registration without UV when verification is required', async () => {
      expect(
        await rejectionOf(
          verifier.verifyRegistration(
            registrationCheck(W3C_WEBAUTHN_VECTORS.packedEd25519, { requireUserVerification: true })
          )
        )
      ).toBe('user-not-verified');
    });

    it('refuses an algorithm QAuth does not accept (ES384)', async () => {
      expect(
        await rejectionOf(
          verifier.verifyRegistration(registrationCheck(W3C_WEBAUTHN_VECTORS.packedEs384))
        )
      ).toBe('unsupported-algorithm');
    });

    it('refuses an assertion answer offered as a registration', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const response = w3cRegistrationResponse(vector) as RegistrationResponseJSON;
      const swapped = {
        ...response,
        response: {
          ...response.response,
          clientDataJSON: hexToBase64Url(vector.authentication.clientDataJSON),
        },
      };
      expect(
        await rejectionOf(
          verifier.verifyRegistration(
            registrationCheck(vector, {
              response: swapped,
              expectedChallenge: hexToBase64Url(vector.authentication.challenge),
            })
          )
        )
      ).toBe('ceremony-mismatch');
    });

    it('refuses a response whose id is not the credential id in the authenticator data', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const response = w3cRegistrationResponse(vector) as RegistrationResponseJSON;
      const otherId = hexToBase64Url(W3C_WEBAUTHN_VECTORS.packedRs256.credentialId);
      expect(
        await rejectionOf(
          verifier.verifyRegistration(
            registrationCheck(vector, { response: { ...response, id: otherId, rawId: otherId } })
          )
        )
      ).toBe('malformed-response');
    });

    it('refuses an attestation statement whose signature does not verify', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedSelfEs256;
      const attestationObject = Buffer.from(vector.registration.attestationObject, 'hex');
      // The packed statement's `sig` is a DER ECDSA signature: flip a byte of it.
      const sig = attestationObject.indexOf(Buffer.from('63736967', 'hex')) + 6;
      attestationObject[sig + 10] ^= 0x01;
      const response = w3cRegistrationResponse(vector) as RegistrationResponseJSON;
      expect(
        await rejectionOf(
          verifier.verifyRegistration(
            registrationCheck(vector, {
              response: {
                ...response,
                response: {
                  ...response.response,
                  attestationObject: attestationObject.toString('base64url'),
                },
              },
            })
          )
        )
      ).toBe('attestation-invalid');
    });
  });

  describe('assertion (§16)', () => {
    it.each([
      ['ES256', 'packedEs256'],
      ['ES256', 'noneEs256'],
      ['RS256', 'packedRs256'],
      ['EdDSA', 'packedEd25519'],
    ] as const)(
      'verifies an %s assertion (%s) under its registered key',
      async (_name, vectorName) => {
        const vector = W3C_WEBAUTHN_VECTORS[vectorName];

        const asserted = await verifier.verifyAssertion(await assertionCheck(vector));

        expect(asserted).toMatchObject({
          credentialId: hexToBase64Url(vector.credentialId),
          signCount: 0,
          origin: W3C_VECTOR_ORIGIN,
          userHandle: undefined,
        });
      }
    );

    it('verifies the user-verified ES256 assertion when verification is required', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEs256, {
        requireUserVerification: true,
      });
      await expect(verifier.verifyAssertion(check)).resolves.toMatchObject({ userVerified: true });
    });

    it.each(['packedRs256', 'packedEd25519', 'noneEs256'] as const)(
      'refuses the %s assertion, which lacks UV, when verification is required',
      async (vectorName) => {
        const check = await assertionCheck(W3C_WEBAUTHN_VECTORS[vectorName], {
          requireUserVerification: true,
        });
        expect(await rejectionOf(verifier.verifyAssertion(check))).toBe('user-not-verified');
      }
    );

    it('refuses a wrong origin', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEs256, {
        expectedOrigins: ['https://auth.example.org'],
      });
      expect(await rejectionOf(verifier.verifyAssertion(check))).toBe('origin-mismatch');
    });

    it('refuses a wrong RP ID hash', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEs256, {
        expectedRpId: 'example.com',
      });
      expect(await rejectionOf(verifier.verifyAssertion(check))).toBe('rp-id-mismatch');
    });

    it('refuses a wrong challenge', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEs256, {
        expectedChallenge: hexToBase64Url(W3C_WEBAUTHN_VECTORS.packedEs256.registration.challenge),
      });
      expect(await rejectionOf(verifier.verifyAssertion(check))).toBe('challenge-mismatch');
    });

    it('refuses a registration answer offered as an assertion', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const check = await assertionCheck(vector, {
        expectedChallenge: hexToBase64Url(vector.registration.challenge),
      });
      const response = {
        ...check.response,
        response: {
          ...check.response.response,
          clientDataJSON: hexToBase64Url(vector.registration.clientDataJSON),
        },
      };
      expect(await rejectionOf(verifier.verifyAssertion({ ...check, response }))).toBe(
        'ceremony-mismatch'
      );
    });

    it('refuses a cross-origin ceremony (§16.4, "crossOrigin": true), in both ceremonies', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.noneEs256CrossOrigin;
      expect(await rejectionOf(verifier.verifyRegistration(registrationCheck(vector)))).toBe(
        'cross-origin'
      );

      // A "none" attestation signs nothing, so the same credential registered
      // from a same-origin client data gives the key the assertion is checked
      // against; the assertion's own client data stays cross-origin.
      const registration = w3cRegistrationResponse(vector) as RegistrationResponseJSON;
      const registered = await verifier.verifyRegistration(
        registrationCheck(vector, {
          response: {
            ...registration,
            response: {
              ...registration.response,
              clientDataJSON: withClientData(registration.response.clientDataJSON, {
                crossOrigin: false,
              }),
            },
          },
        })
      );
      expect(
        await rejectionOf(
          verifier.verifyAssertion({
            response: w3cAuthenticationResponse(vector) as AuthenticationResponseJSON,
            expectedChallenge: hexToBase64Url(vector.authentication.challenge),
            expectedOrigins: [W3C_VECTOR_ORIGIN],
            expectedRpId: W3C_VECTOR_RP_ID,
            requireUserVerification: false,
            credential: { id: registered.credentialId, publicKey: registered.publicKey },
          })
        )
      ).toBe('cross-origin');
    });

    it('refuses a topOrigin even without crossOrigin', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEs256);
      const response = {
        ...check.response,
        response: {
          ...check.response.response,
          clientDataJSON: withClientData(check.response.response.clientDataJSON, {
            topOrigin: 'https://example.com',
          }),
        },
      };
      expect(await rejectionOf(verifier.verifyAssertion({ ...check, response }))).toBe(
        'cross-origin'
      );
    });

    it('refuses a signature that does not verify', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEd25519);
      const signature = Buffer.from(check.response.response.signature, 'base64url');
      signature[5] ^= 0x01;
      const response = {
        ...check.response,
        response: { ...check.response.response, signature: signature.toString('base64url') },
      };
      expect(await rejectionOf(verifier.verifyAssertion({ ...check, response }))).toBe(
        'signature-invalid'
      );
    });

    it('refuses an assertion checked against another credential', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEs256);
      const other = await verifier.verifyRegistration(
        registrationCheck(W3C_WEBAUTHN_VECTORS.packedRs256)
      );
      expect(
        await rejectionOf(
          verifier.verifyAssertion({
            ...check,
            credential: { id: other.credentialId, publicKey: other.publicKey },
          })
        )
      ).toBe('credential-mismatch');
    });

    it('refuses an assertion signed for the RP ID but checked under another key', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEs256);
      const other = await verifier.verifyRegistration(
        registrationCheck(W3C_WEBAUTHN_VECTORS.packedSelfEs256)
      );
      expect(
        await rejectionOf(
          verifier.verifyAssertion({
            ...check,
            credential: { id: check.credential.id, publicKey: other.publicKey },
          })
        )
      ).toBe('signature-invalid');
    });

    it('refuses authenticator data without the UP flag', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEs256);
      const authenticatorData = Buffer.from(check.response.response.authenticatorData, 'base64url');
      authenticatorData[32] &= ~0x01;
      const response = {
        ...check.response,
        response: {
          ...check.response.response,
          authenticatorData: authenticatorData.toString('base64url'),
        },
      };
      expect(await rejectionOf(verifier.verifyAssertion({ ...check, response }))).toBe(
        'user-not-present'
      );
    });

    it('refuses BS without BE', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEd25519);
      const authenticatorData = Buffer.from(check.response.response.authenticatorData, 'base64url');
      authenticatorData[32] |= 0x10;
      const response = {
        ...check.response,
        response: {
          ...check.response.response,
          authenticatorData: authenticatorData.toString('base64url'),
        },
      };
      expect(await rejectionOf(verifier.verifyAssertion({ ...check, response }))).toBe(
        'malformed-response'
      );
    });

    it('refuses client data that is not JSON', async () => {
      const check = await assertionCheck(W3C_WEBAUTHN_VECTORS.packedEs256);
      const response = {
        ...check.response,
        response: {
          ...check.response.response,
          clientDataJSON: Buffer.from('not json').toString('base64url'),
        },
      };
      expect(await rejectionOf(verifier.verifyAssertion({ ...check, response }))).toBe(
        'malformed-response'
      );
    });
  });

  it('computes the RP ID hash the vectors carry', () => {
    // A sanity check of the fixture: the first 32 bytes of the authenticator
    // data are SHA-256("example.org").
    const rpIdHash = createHash('sha256').update(W3C_VECTOR_RP_ID).digest('hex');
    for (const vector of Object.values(W3C_WEBAUTHN_VECTORS)) {
      expect(vector.authentication.authenticatorData.slice(0, 64)).toBe(rpIdHash);
    }
  });
});
