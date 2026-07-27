import { InvalidCredentialsError } from '@qauth-labs/shared-errors';
import type { JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  createKeyAttestationPki,
  issueKeyAttestation,
  type KeyAttestationPki,
} from '../../testing/key-attestation.fixture';
import { generateFixtureKeys } from '../../testing/sd-jwt-vc.fixture';
import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import { ValidatedIssuer } from '../trust/issuer-identity';
import { createStaticAttestingIssuers } from './attesting-issuers';
import {
  assertKeyStorageAssuranceProvisioned,
  createKeyStorageAssuranceResolver,
  defaultConveyedSignalExtractor,
  DENY_ALL_KEY_STORAGE_ASSURANCE_RESOLVER,
  keyStorageAssuranceGateFor,
  keyStorageAssuranceMeets,
  type KeyStorageAssurancePolicy,
  keyStorageAssurancePolicyOf,
  NO_KEY_STORAGE_ASSURANCE,
} from './key-storage-assurance';

const ATTESTING_ISSUER = 'https://pid.issuer.example';
const SILENT_ISSUER = 'https://other.issuer.example';

/** The `haip-1.0` posture, read from the profile table rather than restated. */
const HAIP_POLICY: KeyStorageAssurancePolicy = keyStorageAssurancePolicyOf(
  VERIFIER_PROFILES['haip-1.0']
);
/** The `oid4vp-1.0-base` posture. */
const BASE_POLICY: KeyStorageAssurancePolicy = keyStorageAssurancePolicyOf(
  VERIFIER_PROFILES['oid4vp-1.0-base']
);

function validated(identifier: string): ValidatedIssuer {
  return ValidatedIssuer.fromValidatedPresentation({ identifier, keyResolution: 'x5c' });
}

let pki: KeyAttestationPki;
let holderJwk: JWK;
let otherJwk: JWK;

beforeAll(async () => {
  pki = createKeyAttestationPki();
  holderJwk = (await generateFixtureKeys('ES256')).jwk;
  otherJwk = (await generateFixtureKeys('ES256')).jwk;
});

/** A resolver wired the way a real HAIP deployment would be. */
function provisionedResolver() {
  return createKeyStorageAssuranceResolver({
    attestingIssuers: createStaticAttestingIssuers([
      { issuer: ATTESTING_ISSUER, keyStorage: 'iso_18045_high' },
    ]),
    keyAttestationAnchors: pki.anchors,
  });
}

/** The gate input for a credential from `issuer` carrying `claims`. */
function input(issuer: string, claims: Record<string, unknown> = {}) {
  return {
    issuer: validated(issuer),
    confirmationJwk: holderJwk,
    claims: { iss: issuer, cnf: { jwk: holderJwk }, ...claims },
  };
}

describe('keyStorageAssurancePolicyOf (#308)', () => {
  it('reads the haip-1.0 posture and floor as data', () => {
    expect(HAIP_POLICY).toEqual({
      posture: 'required',
      minimumAttackPotential: 'iso_18045_high',
    });
  });

  it('reads the oid4vp-1.0-base posture as "not evaluated"', () => {
    expect(BASE_POLICY).toEqual({ posture: 'forbidden' });
  });

  it('treats "no profile" as not evaluated rather than throwing', () => {
    // A caller with no profile has already been refused a wallet flow entirely
    // by `resolveVerifierProfile`; there is nothing here to evaluate.
    expect(keyStorageAssurancePolicyOf(undefined)).toEqual({ posture: 'forbidden' });
    expect(keyStorageAssurancePolicyOf(null)).toEqual({ posture: 'forbidden' });
  });
});

describe('oid4vp-1.0-base — key storage is not required and not evaluated (#308 AC)', () => {
  it('accepts and establishes nothing, even with nothing provisioned', async () => {
    const resolver = createKeyStorageAssuranceResolver();

    expect(await resolver.resolveKeyStorageAssurance(input(SILENT_ISSUER), BASE_POLICY)).toEqual({
      outcome: 'accepted',
      evidence: NO_KEY_STORAGE_ASSURANCE,
    });
  });

  it('does not even READ a conveyed signal, so one cannot raise assurance', async () => {
    // `CapabilityPosture` says `forbidden` means unreachable, not merely
    // undefaulted. What is made unreachable is the SIGNAL: an attestation
    // present under a profile that forbids the capability contributes nothing.
    let extractorCalls = 0;
    const resolver = createKeyStorageAssuranceResolver({
      keyAttestationAnchors: pki.anchors,
      extractConveyedSignal: (source) => {
        extractorCalls += 1;
        return defaultConveyedSignalExtractor(source);
      },
    });

    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
    });

    const decision = await resolver.resolveKeyStorageAssurance(
      input(ATTESTING_ISSUER, { cnf: { jwk: holderJwk, key_attestation: attestation } }),
      BASE_POLICY
    );

    expect(decision).toEqual({ outcome: 'accepted', evidence: NO_KEY_STORAGE_ASSURANCE });
    expect(extractorCalls).toBe(0);
  });

  it('accepts a credential whose issuer attests nothing at all', async () => {
    // The acceptance criterion in its plainest form: a valid base-profile
    // presentation is unaffected by this issue.
    expect(
      await provisionedResolver().resolveKeyStorageAssurance(input(SILENT_ISSUER), BASE_POLICY)
    ).toEqual({ outcome: 'accepted', evidence: NO_KEY_STORAGE_ASSURANCE });
  });
});

describe('haip-1.0 — the transitive path (#308 AC)', () => {
  it('accepts a credential from an issuer the operator recorded as attesting', async () => {
    expect(
      await provisionedResolver().resolveKeyStorageAssurance(input(ATTESTING_ISSUER), HAIP_POLICY)
    ).toEqual({
      outcome: 'accepted',
      evidence: { assurance: 'issuer-attested', keyStorage: 'iso_18045_high' },
    });
  });

  it('REJECTS a credential from an issuer nobody recorded', async () => {
    // Fail-closed with no permissive fallback: a trusted issuer is not
    // automatically an attesting one. Trusting an issuer's claims about a PERSON
    // is a different decision from trusting its claims about a DEVICE.
    expect(
      await provisionedResolver().resolveKeyStorageAssurance(input(SILENT_ISSUER), HAIP_POLICY)
    ).toEqual({ outcome: 'rejected', reason: 'assurance-required-but-absent' });
  });

  it('REJECTS everything when nothing is provisioned', async () => {
    expect(
      await DENY_ALL_KEY_STORAGE_ASSURANCE_RESOLVER.resolveKeyStorageAssurance(
        input(ATTESTING_ISSUER),
        HAIP_POLICY
      )
    ).toEqual({ outcome: 'rejected', reason: 'assurance-required-but-absent' });
  });

  it('rejects a level below the profile floor', async () => {
    const resolver = createKeyStorageAssuranceResolver({
      attestingIssuers: createStaticAttestingIssuers([
        { issuer: ATTESTING_ISSUER, keyStorage: 'iso_18045_moderate' },
      ]),
    });

    expect(await resolver.resolveKeyStorageAssurance(input(ATTESTING_ISSUER), HAIP_POLICY)).toEqual(
      { outcome: 'rejected', reason: 'attack-potential-below-minimum' }
    );
  });

  it('contains an attesting-issuer backend that throws, refusing rather than 500ing', async () => {
    const resolver = createKeyStorageAssuranceResolver({
      attestingIssuers: {
        attestedKeyStorage: () => {
          throw new Error('backend is down');
        },
      },
    });

    expect(await resolver.resolveKeyStorageAssurance(input(ATTESTING_ISSUER), HAIP_POLICY)).toEqual(
      { outcome: 'rejected', reason: 'assurance-required-but-absent' }
    );
  });
});

describe('haip-1.0 — an issuer-asserted key_storage claim', () => {
  it('is capped at what the operator recorded, never promoted by the issuer', async () => {
    // The issuer says `high`; the operator recorded `moderate`. Honouring the
    // credential would let any recorded issuer grant itself any level.
    const resolver = createKeyStorageAssuranceResolver({
      attestingIssuers: createStaticAttestingIssuers([
        { issuer: ATTESTING_ISSUER, keyStorage: 'iso_18045_moderate' },
      ]),
    });

    const decision = await resolver.resolveKeyStorageAssurance(
      input(ATTESTING_ISSUER, { key_storage: ['iso_18045_high'] }),
      { posture: 'permitted' }
    );

    expect(decision).toEqual({
      outcome: 'accepted',
      evidence: { assurance: 'issuer-attested', keyStorage: 'iso_18045_moderate' },
    });
  });

  it('is honoured when it reports WEAKER storage than the operator recorded', async () => {
    // A batch minted before a hardware rollout, say. Downgrading is the issuer's
    // to state; upgrading is not.
    const decision = await provisionedResolver().resolveKeyStorageAssurance(
      input(ATTESTING_ISSUER, { key_storage: ['iso_18045_moderate'] }),
      { posture: 'permitted' }
    );

    expect(decision).toEqual({
      outcome: 'accepted',
      evidence: { assurance: 'issuer-attested', keyStorage: 'iso_18045_moderate' },
    });
  });

  it('establishes nothing on its own when the operator recorded nothing', async () => {
    const decision = await createKeyStorageAssuranceResolver().resolveKeyStorageAssurance(
      input(SILENT_ISSUER, { key_storage: ['iso_18045_high'] }),
      HAIP_POLICY
    );

    expect(decision).toEqual({ outcome: 'rejected', reason: 'assurance-required-but-absent' });
  });

  it('falls back to the recorded level when the claim uses an unknown vocabulary', async () => {
    const decision = await provisionedResolver().resolveKeyStorageAssurance(
      input(ATTESTING_ISSUER, { key_storage: ['acme_level_9'] }),
      HAIP_POLICY
    );

    expect(decision).toEqual({
      outcome: 'accepted',
      evidence: { assurance: 'issuer-attested', keyStorage: 'iso_18045_high' },
    });
  });
});

describe('haip-1.0 — a conveyed key attestation', () => {
  it('establishes key-attested assurance and wins over the issuer record', async () => {
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      userAuthentication: ['iso_18045_moderate'],
    });

    expect(
      await provisionedResolver().resolveKeyStorageAssurance(
        input(ATTESTING_ISSUER, { cnf: { jwk: holderJwk, key_attestation: attestation } }),
        HAIP_POLICY
      )
    ).toEqual({
      outcome: 'accepted',
      evidence: {
        assurance: 'key-attested',
        keyStorage: 'iso_18045_high',
        userAuthentication: 'iso_18045_moderate',
      },
    });
  });

  it('is accepted from an issuer the operator recorded NOTHING about', async () => {
    // The direct path stands on its own: an attestation QAuth verified for
    // itself does not need the operator's word about the credential issuer.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
    });

    expect(
      await provisionedResolver().resolveKeyStorageAssurance(
        input(SILENT_ISSUER, { cnf: { jwk: holderJwk, key_attestation: attestation } }),
        HAIP_POLICY
      )
    ).toMatchObject({ outcome: 'accepted', evidence: { assurance: 'key-attested' } });
  });

  it('REJECTS when it attests a different key, even from a recorded issuer', async () => {
    // The transitive path would have accepted this credential. A conveyed
    // attestation that does not validate is a refusal, not an absence — #308:
    // only where NOTHING is conveyed does the transitive path apply.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [otherJwk],
      keyStorage: ['iso_18045_high'],
    });

    expect(
      await provisionedResolver().resolveKeyStorageAssurance(
        input(ATTESTING_ISSUER, { cnf: { jwk: holderJwk, key_attestation: attestation } }),
        HAIP_POLICY
      )
    ).toEqual({ outcome: 'rejected', reason: 'attested-key-mismatch' });
  });

  it('REJECTS a self-signed attestation certificate', async () => {
    const { leaf } = createKeyAttestationPki();
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      signer: leaf,
      x5c: [leaf.x5c],
    });

    // A leaf from another PKI presented alone chains to nothing here; the
    // self-signed case proper is asserted in `key-attestation.test.ts`.
    expect(
      await provisionedResolver().resolveKeyStorageAssurance(
        input(ATTESTING_ISSUER, { cnf: { jwk: holderJwk, key_attestation: attestation } }),
        HAIP_POLICY
      )
    ).toEqual({ outcome: 'rejected', reason: 'attestation-chain-unanchored' });
  });

  it('REJECTS an attestation whose x5c carries the trust anchor', async () => {
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      x5c: [pki.leaf.x5c, pki.intermediate.x5c, pki.root.x5c],
    });

    expect(
      await provisionedResolver().resolveKeyStorageAssurance(
        input(ATTESTING_ISSUER, { cnf: { jwk: holderJwk, key_attestation: attestation } }),
        HAIP_POLICY
      )
    ).toEqual({ outcome: 'rejected', reason: 'attestation-anchor-in-chain' });
  });

  it('REJECTS an attested level below the profile floor', async () => {
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_moderate'],
    });

    expect(
      await provisionedResolver().resolveKeyStorageAssurance(
        input(ATTESTING_ISSUER, { cnf: { jwk: holderJwk, key_attestation: attestation } }),
        HAIP_POLICY
      )
    ).toEqual({ outcome: 'rejected', reason: 'attack-potential-below-minimum' });
  });

  it('REJECTS an attestation that grades nothing under a graded floor', async () => {
    const attestation = await issueKeyAttestation(pki, { attestedKeys: [holderJwk] });

    expect(
      await provisionedResolver().resolveKeyStorageAssurance(
        input(ATTESTING_ISSUER, { cnf: { jwk: holderJwk, key_attestation: attestation } }),
        HAIP_POLICY
      )
    ).toEqual({ outcome: 'rejected', reason: 'attack-potential-below-minimum' });
  });

  it('accepts an ungraded attestation under a posture that requires no floor', async () => {
    const attestation = await issueKeyAttestation(pki, { attestedKeys: [holderJwk] });

    expect(
      await provisionedResolver().resolveKeyStorageAssurance(
        input(ATTESTING_ISSUER, { cnf: { jwk: holderJwk, key_attestation: attestation } }),
        { posture: 'required' }
      )
    ).toEqual({ outcome: 'accepted', evidence: { assurance: 'key-attested' } });
  });
});

describe("the 'permitted' posture", () => {
  it('accepts a credential that establishes nothing', async () => {
    expect(
      await provisionedResolver().resolveKeyStorageAssurance(input(SILENT_ISSUER), {
        posture: 'permitted',
      })
    ).toEqual({ outcome: 'accepted', evidence: NO_KEY_STORAGE_ASSURANCE });
  });

  it('still REJECTS a conveyed attestation that does not validate', async () => {
    // An invalid attestation is a forgery attempt, not an absence. `permitted`
    // relaxes the requirement, never the verification.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [otherJwk],
      keyStorage: ['iso_18045_high'],
    });

    expect(
      await provisionedResolver().resolveKeyStorageAssurance(
        input(SILENT_ISSUER, { cnf: { jwk: holderJwk, key_attestation: attestation } }),
        { posture: 'permitted' }
      )
    ).toEqual({ outcome: 'rejected', reason: 'attested-key-mismatch' });
  });

  it('does not enforce a floor', async () => {
    const resolver = createKeyStorageAssuranceResolver({
      attestingIssuers: createStaticAttestingIssuers([
        { issuer: ATTESTING_ISSUER, keyStorage: 'iso_18045_basic' },
      ]),
    });

    expect(
      await resolver.resolveKeyStorageAssurance(input(ATTESTING_ISSUER), {
        posture: 'permitted',
        minimumAttackPotential: 'iso_18045_high',
      })
    ).toMatchObject({ outcome: 'accepted', evidence: { keyStorage: 'iso_18045_basic' } });
  });
});

describe('defaultConveyedSignalExtractor', () => {
  it('prefers a key attestation over an issuer claim', async () => {
    // Preferring the issuer's word over an artifact carrying its own proof would
    // be strictly weaker, and would let a claim MASK an attestation that would
    // have been rejected — turning a refusal into an acceptance.
    const signal = defaultConveyedSignalExtractor({
      claims: {
        cnf: { jwk: holderJwk, key_attestation: 'the-attestation' },
        key_storage: ['iso_18045_high'],
      },
    });

    expect(signal).toEqual({ kind: 'key-attestation', attestation: 'the-attestation' });
  });

  it('reads an issuer claim when no attestation is conveyed', () => {
    expect(defaultConveyedSignalExtractor({ claims: { key_storage: ['iso_18045_high'] } })).toEqual(
      { kind: 'credential-claim', keyStorage: ['iso_18045_high'] }
    );
  });

  it('finds nothing in an ordinary credential', () => {
    expect(
      defaultConveyedSignalExtractor({ claims: { iss: ATTESTING_ISSUER, given_name: 'Alice' } })
    ).toBeUndefined();
  });

  it('is not fooled by a non-object cnf', () => {
    expect(defaultConveyedSignalExtractor({ claims: { cnf: 'not-an-object' } })).toBeUndefined();
  });
});

describe('a broken extractor is contained', () => {
  it('is treated as "nothing conveyed" rather than becoming a 500', async () => {
    const resolver = createKeyStorageAssuranceResolver({
      attestingIssuers: createStaticAttestingIssuers([
        { issuer: ATTESTING_ISSUER, keyStorage: 'iso_18045_high' },
      ]),
      extractConveyedSignal: () => {
        throw new Error('extractor is broken');
      },
    });

    expect(await resolver.resolveKeyStorageAssurance(input(ATTESTING_ISSUER), HAIP_POLICY)).toEqual(
      {
        outcome: 'accepted',
        evidence: { assurance: 'issuer-attested', keyStorage: 'iso_18045_high' },
      }
    );
  });
});

describe('assertKeyStorageAssurance — the throwing gate', () => {
  it('returns the evidence when the requirement is met', async () => {
    expect(
      await provisionedResolver().assertKeyStorageAssurance(input(ATTESTING_ISSUER), HAIP_POLICY)
    ).toEqual({ assurance: 'issuer-attested', keyStorage: 'iso_18045_high' });
  });

  it('throws the single non-enumerating refusal otherwise', async () => {
    // A caller must not be able to proceed by ignoring the result.
    await expect(
      provisionedResolver().assertKeyStorageAssurance(input(SILENT_ISSUER), HAIP_POLICY)
    ).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('throws the SAME error for every distinct internal reason', async () => {
    // The security property: a client cannot tell an unrecorded issuer from a
    // forged attestation from a level below the floor. All three are facts about
    // a stranger's device.
    const resolver = provisionedResolver();
    const wrongKey = await issueKeyAttestation(pki, {
      attestedKeys: [otherJwk],
      keyStorage: ['iso_18045_high'],
    });
    const tooWeak = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_basic'],
    });

    const messages = new Set<string>();

    for (const claims of [
      {},
      { cnf: { jwk: holderJwk, key_attestation: wrongKey } },
      { cnf: { jwk: holderJwk, key_attestation: tooWeak } },
    ]) {
      try {
        await resolver.assertKeyStorageAssurance(input(SILENT_ISSUER, claims), HAIP_POLICY);
        expect.fail('every one of these must be refused');
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidCredentialsError);
        messages.add((error as InvalidCredentialsError).message);
      }
    }

    expect(messages.size).toBe(1);
  });
});

describe('keyStorageAssuranceMeets — the unit #237 wires in', () => {
  it('is false for evidence that established nothing, whatever the floor', () => {
    expect(keyStorageAssuranceMeets(NO_KEY_STORAGE_ASSURANCE, 'iso_18045_basic')).toBe(false);
  });

  it('is false when nothing graded the storage', () => {
    expect(keyStorageAssuranceMeets({ assurance: 'key-attested' }, 'iso_18045_basic')).toBe(false);
  });

  it('is true only at or above the floor', () => {
    const evidence = { assurance: 'issuer-attested', keyStorage: 'iso_18045_moderate' } as const;

    expect(keyStorageAssuranceMeets(evidence, 'iso_18045_moderate')).toBe(true);
    expect(keyStorageAssuranceMeets(evidence, 'iso_18045_basic')).toBe(true);
    expect(keyStorageAssuranceMeets(evidence, 'iso_18045_high')).toBe(false);
  });
});

describe('keyStorageAssuranceGateFor', () => {
  it('keeps a required posture even when no resolver is provisioned', async () => {
    // The trap this helper exists to close: building a gate from the WIRING
    // would silently downgrade `haip-1.0` to "not evaluated" whenever a
    // deployment forgot its registry. Building it from the PROFILE cannot.
    const gate = keyStorageAssuranceGateFor(VERIFIER_PROFILES['haip-1.0']);

    expect(gate.policy.posture).toBe('required');
    expect(
      await gate.resolver.resolveKeyStorageAssurance(input(ATTESTING_ISSUER), gate.policy)
    ).toEqual({ outcome: 'rejected', reason: 'assurance-required-but-absent' });
  });

  it('uses the provisioned resolver when one is supplied', async () => {
    const gate = keyStorageAssuranceGateFor(VERIFIER_PROFILES['haip-1.0'], provisionedResolver());

    expect(
      await gate.resolver.resolveKeyStorageAssurance(input(ATTESTING_ISSUER), gate.policy)
    ).toMatchObject({ outcome: 'accepted' });
  });

  it('is inert for the base profile', async () => {
    const gate = keyStorageAssuranceGateFor(VERIFIER_PROFILES['oid4vp-1.0-base']);

    expect(gate.policy).toEqual({ posture: 'forbidden' });
    expect(
      await gate.resolver.resolveKeyStorageAssurance(input(SILENT_ISSUER), gate.policy)
    ).toEqual({ outcome: 'accepted', evidence: NO_KEY_STORAGE_ASSURANCE });
  });
});

describe('assertKeyStorageAssuranceProvisioned — the boot gate', () => {
  it('refuses haip-1.0 when nothing is provisioned', () => {
    expect(() => assertKeyStorageAssuranceProvisioned(VERIFIER_PROFILES['haip-1.0'])).toThrow(
      /requires key-storage assurance/
    );
  });

  it('accepts haip-1.0 once something is', () => {
    expect(() =>
      assertKeyStorageAssuranceProvisioned(VERIFIER_PROFILES['haip-1.0'], true)
    ).not.toThrow();
  });

  it('never refuses a profile that forbids the capability', () => {
    expect(() =>
      assertKeyStorageAssuranceProvisioned(VERIFIER_PROFILES['oid4vp-1.0-base'])
    ).not.toThrow();
  });

  it('names no profile in its own logic, so a future profile is gated for free', () => {
    // Profiles are DATA (#299 AC). The gate reads the declared capability.
    const hypothetical = {
      ...VERIFIER_PROFILES['oid4vp-1.0-base'],
      id: 'oid4vp-1.0-base' as const,
      keyStorageAssurance: 'required' as const,
    };

    expect(() => assertKeyStorageAssuranceProvisioned(hypothetical)).toThrow(
      /requires key-storage assurance/
    );
  });
});
