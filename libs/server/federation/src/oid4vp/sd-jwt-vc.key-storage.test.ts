import { beforeAll, describe, expect, it } from 'vitest';

import {
  createKeyAttestationPki,
  issueKeyAttestation,
  type KeyAttestationPki,
} from '../../testing/key-attestation.fixture';
import {
  fixtureValidationContext,
  type IssuedSdJwtVc,
  issueSdJwtVc,
  presentSdJwtVc,
  TEST_CREDENTIAL_QUERY,
  TEST_ISSUER,
} from '../../testing/sd-jwt-vc.fixture';
import { createStaticAttestingIssuers } from '../attestation/attesting-issuers';
import {
  createKeyStorageAssuranceResolver,
  keyStorageAssuranceGateFor,
  keyStorageAssuranceMeets,
  type KeyStorageAssuranceResolver,
} from '../attestation/key-storage-assurance';
import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import { isPresentationValidationRejection } from './presentation-rejection';
import { validateSdJwtVcPresentation } from './sd-jwt-vc';
import type { PresentationValidationContext } from './validated-credential';

/**
 * The #308 gate AT the #234 seam, across both profiles.
 *
 * `attestation/*.test.ts` proves the gate's own logic. This file proves the
 * WIRING: that `oid4vp-1.0-base` is untouched, that `haip-1.0` refuses a
 * presentation whose assurance cannot be established, and that the refusal is
 * the same uniform rejection every other presentation failure produces.
 */

const NONCE = 'nonce-for-key-storage';

let pki: KeyAttestationPki;

beforeAll(() => {
  pki = createKeyAttestationPki();
});

/** A resolver wired the way a real HAIP deployment would be. */
function provisionedResolver(): KeyStorageAssuranceResolver {
  return createKeyStorageAssuranceResolver({
    attestingIssuers: createStaticAttestingIssuers([
      { issuer: TEST_ISSUER, keyStorage: 'iso_18045_high' },
    ]),
    keyAttestationAnchors: pki.anchors,
  });
}

/** Validate a presentation under a context, through the real entry point. */
async function validate(presentation: string, context: PresentationValidationContext) {
  return validateSdJwtVcPresentation(presentation, 'pid', TEST_CREDENTIAL_QUERY, context);
}

/** The reason a presentation was refused, narrowed properly. */
async function rejectionReasonOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (isPresentationValidationRejection(error)) return error.reason;
    throw error;
  }

  expect.fail('the presentation was expected to be refused and was not');
}

/** Present an issued credential against this request. */
async function present(issued: IssuedSdJwtVc): Promise<string> {
  return presentSdJwtVc(issued, { nonce: NONCE });
}

describe('#308 at the #234 seam — oid4vp-1.0-base is unaffected', () => {
  it('validates a clean presentation with no gate in the context at all', async () => {
    const issued = await issueSdJwtVc();
    const validated = await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE)
    );

    expect(validated.assurance.keyStorageAssurance).toEqual({ assurance: 'none' });
  });

  it('validates a clean presentation under the base profile’s own gate', async () => {
    const issued = await issueSdJwtVc();
    const context = fixtureValidationContext(issued, NONCE, {
      keyStorageAssurance: keyStorageAssuranceGateFor(VERIFIER_PROFILES['oid4vp-1.0-base']),
    });

    const validated = await validate(await present(issued), context);

    expect(validated.assurance.keyStorageAssurance).toEqual({ assurance: 'none' });
  });

  it('does not let a conveyed attestation raise assurance under the base profile', async () => {
    // The base profile forbids the capability, so the signal is unreachable. The
    // credential is still perfectly valid — refusing it because its issuer chose
    // to include extra assurance would be a regression dressed as strictness.
    const issued = await issueSdJwtVc();
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [issued.holderKeys.jwk],
      keyStorage: ['iso_18045_high'],
    });
    const withAttestation = await issueSdJwtVc({
      holderKeys: issued.holderKeys,
      cnf: { jwk: issued.holderKeys.jwk, key_attestation: attestation },
    });

    const validated = await validate(
      await present(withAttestation),
      fixtureValidationContext(withAttestation, NONCE, {
        keyStorageAssurance: keyStorageAssuranceGateFor(
          VERIFIER_PROFILES['oid4vp-1.0-base'],
          provisionedResolver()
        ),
      })
    );

    expect(validated.assurance.keyStorageAssurance).toEqual({ assurance: 'none' });
  });
});

describe('#308 at the #234 seam — haip-1.0 requires assurance', () => {
  /** The `haip-1.0` gate, with this deployment's registries wired in. */
  function haipGate(resolver: KeyStorageAssuranceResolver = provisionedResolver()) {
    return keyStorageAssuranceGateFor(VERIFIER_PROFILES['haip-1.0'], resolver);
  }

  it('accepts a presentation whose issuer attests key storage (transitive path)', async () => {
    const issued = await issueSdJwtVc();
    const validated = await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE, { keyStorageAssurance: haipGate() })
    );

    expect(validated.assurance.keyStorageAssurance).toEqual({
      assurance: 'issuer-attested',
      keyStorage: 'iso_18045_high',
    });
  });

  it('accepts a presentation carrying a valid Appendix D key attestation', async () => {
    const holderKeys = (await issueSdJwtVc()).holderKeys;
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderKeys.jwk],
      keyStorage: ['iso_18045_high'],
      userAuthentication: ['iso_18045_high'],
    });
    const issued = await issueSdJwtVc({
      holderKeys,
      cnf: { jwk: holderKeys.jwk, key_attestation: attestation },
    });

    const validated = await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE, { keyStorageAssurance: haipGate() })
    );

    expect(validated.assurance.keyStorageAssurance).toEqual({
      assurance: 'key-attested',
      keyStorage: 'iso_18045_high',
      userAuthentication: 'iso_18045_high',
    });
  });

  it('REJECTS a presentation whose assurance cannot be established', async () => {
    // An otherwise flawless credential — real issuer signature, real disclosure
    // digests, real holder binding — from an issuer nobody recorded as
    // attesting. Fail-closed: never leniently accepted because it parses.
    const issued = await issueSdJwtVc({ issuer: 'https://unknown.issuer.example' });

    expect(
      await rejectionReasonOf(
        validate(
          await present(issued),
          fixtureValidationContext(issued, NONCE, { keyStorageAssurance: haipGate() })
        )
      )
    ).toBe('key-storage-assurance-unestablished');
  });

  it('REJECTS when the deployment provisioned nothing at all', async () => {
    const issued = await issueSdJwtVc();

    expect(
      await rejectionReasonOf(
        validate(
          await present(issued),
          fixtureValidationContext(issued, NONCE, {
            keyStorageAssurance: keyStorageAssuranceGateFor(VERIFIER_PROFILES['haip-1.0']),
          })
        )
      )
    ).toBe('key-storage-assurance-unestablished');
  });

  it('REJECTS an attestation that attests a key other than the credential’s', async () => {
    // The replay this closes: a genuine attestation for a real hardware key,
    // attached to a credential bound to a software key the attacker controls.
    const strangerKeys = (await issueSdJwtVc()).holderKeys;
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [strangerKeys.jwk],
      keyStorage: ['iso_18045_high'],
    });
    const issued = await issueSdJwtVc({
      cnf: { jwk: (await issueSdJwtVc()).holderKeys.jwk, key_attestation: attestation },
    });
    const presentation = await presentSdJwtVc(issued, {
      nonce: NONCE,
      signingKeys: issued.holderKeys.keyPair,
    });

    // The credential's `cnf` names a key the holder does not hold, so holder
    // binding refuses first — which is exactly the layering #308 requires. The
    // attestation case proper is covered by `key-attestation.test.ts`; what this
    // pins is that #308 never runs INSTEAD of #234.
    expect(
      await rejectionReasonOf(
        validate(
          presentation,
          fixtureValidationContext(issued, NONCE, { keyStorageAssurance: haipGate() })
        )
      )
    ).toBe('holder-binding-invalid');
  });

  it('REJECTS an attested level below the profile floor', async () => {
    const holderKeys = (await issueSdJwtVc()).holderKeys;
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderKeys.jwk],
      keyStorage: ['iso_18045_moderate'],
    });
    const issued = await issueSdJwtVc({
      holderKeys,
      cnf: { jwk: holderKeys.jwk, key_attestation: attestation },
    });

    expect(
      await rejectionReasonOf(
        validate(
          await present(issued),
          fixtureValidationContext(issued, NONCE, { keyStorageAssurance: haipGate() })
        )
      )
    ).toBe('key-storage-assurance-unestablished');
  });

  it('renders the SAME client error as every other presentation refusal', async () => {
    // #236's non-enumeration guarantee, preserved through the seam #308 adds: an
    // expired credential and a credential with no key-storage assurance are
    // indistinguishable to a client.
    const issued = await issueSdJwtVc();
    const expired = await issueSdJwtVc({ exp: Math.floor(Date.now() / 1000) - 7200 });

    const messages = new Set<string>();

    for (const [credential, context] of [
      [
        issued,
        fixtureValidationContext(issued, NONCE, {
          keyStorageAssurance: keyStorageAssuranceGateFor(VERIFIER_PROFILES['haip-1.0']),
        }),
      ],
      [expired, fixtureValidationContext(expired, NONCE)],
    ] as const) {
      try {
        await validate(await present(credential), context);
        expect.fail('both of these must be refused');
      } catch (error) {
        if (!isPresentationValidationRejection(error)) throw error;
        messages.add(error.toClientError().message);
      }
    }

    expect(messages.size).toBe(1);
  });

  it('contains a resolver that THROWS, refusing rather than 500ing', async () => {
    // A gate that could not answer has established nothing. Letting the throw
    // escape would turn a contained 401 into a 500 an attacker can provoke
    // selectively.
    const issued = await issueSdJwtVc();
    const broken: KeyStorageAssuranceResolver = {
      resolveKeyStorageAssurance: () => {
        throw new Error('resolver is broken');
      },
      assertKeyStorageAssurance: () => {
        throw new Error('resolver is broken');
      },
    };

    expect(
      await rejectionReasonOf(
        validate(
          await present(issued),
          fixtureValidationContext(issued, NONCE, { keyStorageAssurance: haipGate(broken) })
        )
      )
    ).toBe('key-storage-assurance-unestablished');
  });
});

describe('#308 feeds #237 without deciding for it', () => {
  it('a haip-1.0 presentation lacking assurance produces NO credential to derive from', async () => {
    // The acceptance criterion, in the strongest form available: a presentation
    // that cannot establish the required key storage never becomes a
    // `ValidatedCredential` at all, so there is nothing for #237 to raise to a
    // `high` assurance level.
    const issued = await issueSdJwtVc({ issuer: 'https://unknown.issuer.example' });

    await expect(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, {
          keyStorageAssurance: keyStorageAssuranceGateFor(
            VERIFIER_PROFILES['haip-1.0'],
            provisionedResolver()
          ),
        })
      )
    ).rejects.toThrow();
  });

  it('a base-profile credential carries evidence that clears no floor', async () => {
    // The other half: a credential CAN validate with no key-storage assurance
    // (that is the base profile), and #237 must not read that as high assurance.
    // `keyStorageAssuranceMeets` is the unit it wires in to avoid re-deriving it.
    const issued = await issueSdJwtVc();
    const validated = await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE)
    );

    expect(
      keyStorageAssuranceMeets(validated.assurance.keyStorageAssurance, 'iso_18045_basic')
    ).toBe(false);
  });

  it('a haip-1.0 credential carries evidence that clears the floor it met', async () => {
    const issued = await issueSdJwtVc();
    const validated = await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE, {
        keyStorageAssurance: keyStorageAssuranceGateFor(
          VERIFIER_PROFILES['haip-1.0'],
          provisionedResolver()
        ),
      })
    );

    expect(
      keyStorageAssuranceMeets(validated.assurance.keyStorageAssurance, 'iso_18045_high')
    ).toBe(true);
  });
});
