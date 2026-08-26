import { describe, expect, it } from 'vitest';

import {
  fixtureValidationContext,
  type IssuedSdJwtVc,
  issueSdJwtVc,
  presentSdJwtVc,
  TEST_CREDENTIAL_QUERY,
  TEST_ISSUER,
  TEST_VCT,
} from '../../testing/sd-jwt-vc.fixture';
import { createStaticAttestingIssuers } from '../attestation/attesting-issuers';
import {
  createKeyStorageAssuranceResolver,
  keyStorageAssuranceGateFor,
} from '../attestation/key-storage-assurance';
import type { DcqlQuery } from '../oid4vp/dcql';
import { validatePresentations } from '../oid4vp/presentation-validation';
import type { ValidatedCredential } from '../oid4vp/validated-credential';
import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import { resolveCredentialAssurance } from './credential-assurance';
import { translateKeyStorageAssurance } from './key-storage-evidence';
import { type AssurancePolicyEnvLike, resolveAssurancePolicy } from './resolve-assurance-policy';

/**
 * THE HEADLINE of issue #379, end to end over real signatures.
 *
 * #237 and #308 were built in parallel under an explicit instruction not to
 * touch each other's files, and the seam between them was documented and never
 * connected. The consequence was not a vulnerability — everything failed closed
 * — but an entry demanding hardware key storage could NEVER grant, from any
 * configuration an operator could write:
 *
 *  1. the app never built the #308 gate, so every `ValidatedCredential` carried
 *     `assurance.keyStorageAssurance === { assurance: 'none' }` unconditionally;
 *  2. the #237 call site passed a literal `undefined` for its evidence;
 *  3. `OID4VP_ISSUER_ASSURANCE`'s schema was `.strict()` over
 *     `{ level, credentialTypes }`, so `requiresKeyStorage` could not be
 *     authored at all.
 *
 * This suite walks the whole chain the way a deployment does — an SD-JWT VC
 * signed by a real key, presented with a real Key Binding JWT, validated through
 * `validatePresentations` with a gate built from the profile, translated by the
 * one D1 rule, and evaluated against a policy resolved from the JSON an operator
 * puts in `OID4VP_ISSUER_ASSURANCE`. Nothing here is stubbed except the clock.
 *
 * ## Why the gate is built from `haip-1.0`
 *
 * `oid4vp-1.0-base` declares `keyStorageAssurance: 'forbidden'`, and the
 * resolver returns `NO_KEY_STORAGE_ASSURANCE` under that posture without ever
 * consulting the attesting-issuer record. So the base profile is not merely
 * unconfigured for key storage — it cannot produce evidence by construction,
 * which is exactly why the last suite here asserts the base path is unchanged.
 * `haip-1.0` is the only shipped profile whose posture reaches the resolver.
 * Its BOOT is still refused (#298: ES256 signing + response encryption); its
 * profile object is data and drives the gate here with no server involved.
 *
 * @see docs/adr/010-acr-assurance-mapping.md §5
 */

const NONCE = 'Xb1s2v9QpM4rT7kLwZ0nCyHgEfDaUiOj3lRqSt8mVzY';
const REALM = 'master';
const QUERY: DcqlQuery = { credentials: [TEST_CREDENTIAL_QUERY] };

/** The gate a deployment builds: the profile's posture + what it provisioned. */
function gateFor(
  attesting: readonly { issuer: string; keyStorage: string }[],
  profileId: keyof typeof VERIFIER_PROFILES
) {
  return keyStorageAssuranceGateFor(
    VERIFIER_PROFILES[profileId],
    createKeyStorageAssuranceResolver({
      attestingIssuers: createStaticAttestingIssuers(
        attesting as Parameters<typeof createStaticAttestingIssuers>[0]
      ),
    })
  );
}

/** Issue and present one credential, then validate it through the real seam. */
async function validateOne(
  issued: IssuedSdJwtVc,
  gate: ReturnType<typeof keyStorageAssuranceGateFor> | undefined
): Promise<ValidatedCredential> {
  const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

  const validated = await validatePresentations(
    [{ queryId: 'pid', format: 'dc+sd-jwt', presentation }],
    QUERY,
    fixtureValidationContext(issued, NONCE, { keyStorageAssurance: gate })
  );

  const credential = validated[0];
  if (credential === undefined) throw new Error('the fixture presentation failed to validate');
  return credential;
}

/**
 * The operator's configuration, verbatim in the shape `OID4VP_ISSUER_ASSURANCE`
 * parses to — the point being that this is authorable, which is Break 3.
 */
function envAssurance(statement: Record<string, unknown>): AssurancePolicyEnvLike {
  return { OID4VP_ISSUER_ASSURANCE: { [REALM]: { [TEST_ISSUER]: statement } } };
}

/** The whole chain: evidence → the one translation → the realm's policy → a level. */
function levelFor(credential: ValidatedCredential, env: AssurancePolicyEnvLike) {
  const translated = translateKeyStorageAssurance(credential.assurance.keyStorageAssurance);

  return resolveCredentialAssurance(resolveAssurancePolicy({ name: REALM }, env), credential, {
    keyStorage: translated.keyStorage,
    keyStorageAttackPotential: translated.establishedAttackPotential,
  });
}

describe('a hardware-demanding OID4VP_ISSUER_ASSURANCE entry, end to end (#379)', () => {
  const HARDWARE_ENTRY = { level: 'high', requiresKeyStorage: 'hardware' };

  it('GRANTS when the operator recorded the issuer as attesting at the strict floor', async () => {
    const issued = await issueSdJwtVc({ issuer: TEST_ISSUER, vct: TEST_VCT });
    const credential = await validateOne(
      issued,
      gateFor([{ issuer: TEST_ISSUER, keyStorage: 'iso_18045_high' }], 'haip-1.0')
    );

    // Link 1: the gate is reachable from a real presentation at all — the
    // acceptance criterion that `keyStorageAssurance` is no longer `'none'`.
    expect(credential.assurance.keyStorageAssurance.assurance).toBe('issuer-attested');
    expect(credential.assurance.keyStorageAssurance.keyStorage).toBe('iso_18045_high');

    // Links 2 and 3: the evidence reaches a policy an operator could author.
    expect(levelFor(credential, envAssurance(HARDWARE_ENTRY))).toBe('high');
  });

  /**
   * The refusal is asserted by REASON, never merely by "it threw".
   * `rejects.toThrow()` alone would pass on a `TypeError` from a broken fixture,
   * which is how a fail-closed test quietly stops testing the thing it names.
   */
  async function expectKeyStorageRefusal(promise: Promise<unknown>): Promise<void> {
    await expect(promise).rejects.toMatchObject({
      reason: 'key-storage-assurance-unestablished',
    });
  }

  it('REFUSES the same credential when the operator recorded no attesting issuer', async () => {
    const issued = await issueSdJwtVc({ issuer: TEST_ISSUER, vct: TEST_VCT });

    // A `required` posture with nothing recorded refuses the presentation
    // outright — the credential never becomes a `ValidatedCredential` at all.
    await expectKeyStorageRefusal(validateOne(issued, gateFor([], 'haip-1.0')));
  });

  it('REFUSES a recorded grade below the floor the PROFILE mandates', async () => {
    const issued = await issueSdJwtVc({ issuer: TEST_ISSUER, vct: TEST_VCT });

    // Fail-closed in the direction that matters: an operator cannot reach a
    // `high` acr by recording a weak grade under a profile that mandates a
    // strong one. The profile's floor is checked before the policy is ever
    // consulted, so this never becomes a credential to evaluate.
    await expectKeyStorageRefusal(
      validateOne(
        issued,
        gateFor([{ issuer: TEST_ISSUER, keyStorage: 'iso_18045_basic' }], 'haip-1.0')
      )
    );
  });

  it('grants nothing when the credential is genuine but no gate was provisioned', async () => {
    // The state EVERY deployment was in before #379: a valid presentation, a
    // policy demanding hardware, and no evidence anywhere. The login succeeds
    // and carries no assurance — never an error, and never an unearned level.
    const issued = await issueSdJwtVc({ issuer: TEST_ISSUER, vct: TEST_VCT });
    const credential = await validateOne(issued, undefined);

    expect(credential.assurance.keyStorageAssurance.assurance).toBe('none');
    expect(levelFor(credential, envAssurance(HARDWARE_ENTRY))).toBe('low');
  });

  /**
   * D1's operator-stated floor, over evidence the PROFILE accepts.
   *
   * It needs a posture that reaches the resolver without imposing its own floor,
   * which no shipped profile has — `oid4vp-1.0-base` forbids and `haip-1.0`
   * mandates the strongest grade. So the profile is derived rather than
   * selected: this is the shape of a future ecosystem profile that wants
   * key-storage evidence collected and leaves what it is WORTH to the operator,
   * which is precisely the case D1 exists to serve.
   */
  describe('with a profile that permits evidence without mandating a grade', () => {
    // `haip-1.0`'s table entry with ONE member varied. Keeping the real `id`
    // rather than inventing one is deliberate: `VerifierProfileId` is a closed
    // union, and a test that widened it would be asserting about a profile shape
    // the type system says cannot exist.
    const PERMISSIVE_PROFILE = Object.freeze({
      ...VERIFIER_PROFILES['haip-1.0'],
      keyStorageAssurance: 'permitted' as const,
      minimumKeyStorageAttackPotential: undefined,
    });

    function permissiveGate(grade: string) {
      return keyStorageAssuranceGateFor(
        PERMISSIVE_PROFILE,
        createKeyStorageAssuranceResolver({
          attestingIssuers: createStaticAttestingIssuers([
            { issuer: TEST_ISSUER, keyStorage: grade } as never,
          ]),
        })
      );
    }

    it('GRANTS at a stated floor the strict default would have refused', async () => {
      const issued = await issueSdJwtVc({ issuer: TEST_ISSUER, vct: TEST_VCT });
      const credential = await validateOne(issued, permissiveGate('iso_18045_moderate'));

      expect(credential.assurance.keyStorageAssurance.assurance).toBe('issuer-attested');

      // The SAME credential and the SAME evidence, read by two entries that
      // differ only in the floor they state. This is the whole of the knob.
      expect(levelFor(credential, envAssurance(HARDWARE_ENTRY))).toBe('low');
      expect(
        levelFor(
          credential,
          envAssurance({
            ...HARDWARE_ENTRY,
            requiresKeyStorageAttackPotential: 'iso_18045_moderate',
          })
        )
      ).toBe('high');
    });

    it('REFUSES a grade below the floor the ENTRY states', async () => {
      const issued = await issueSdJwtVc({ issuer: TEST_ISSUER, vct: TEST_VCT });
      const credential = await validateOne(issued, permissiveGate('iso_18045_basic'));

      // Evidence exists and is read; it is simply not good enough for this
      // entry. A stated floor lowers the bar, it does not remove it.
      expect(credential.assurance.keyStorageAssurance.assurance).toBe('issuer-attested');
      expect(
        levelFor(
          credential,
          envAssurance({
            ...HARDWARE_ENTRY,
            requiresKeyStorageAttackPotential: 'iso_18045_moderate',
          })
        )
      ).toBe('low');
    });
  });

  it('emits no acr for a realm that configured no key-storage requirement', async () => {
    const issued = await issueSdJwtVc({ issuer: TEST_ISSUER, vct: TEST_VCT });
    const credential = await validateOne(
      issued,
      gateFor([{ issuer: TEST_ISSUER, keyStorage: 'iso_18045_high' }], 'haip-1.0')
    );

    // The acceptance criterion that `acr` behaviour is UNCHANGED for every
    // deployment that configures no key-storage requirement: the same evidence,
    // an entry that does not mention key storage, and the level the entry
    // states — not one derived from the attestation's mere presence.
    expect(levelFor(credential, envAssurance({ level: 'substantial' }))).toBe('substantial');
    expect(levelFor(credential, envAssurance({}))).toBe('low');
  });
});

describe('the oid4vp-1.0-base path is unchanged end to end (#379)', () => {
  it('establishes nothing even when the operator recorded the issuer', async () => {
    const issued = await issueSdJwtVc({ issuer: TEST_ISSUER, vct: TEST_VCT });
    const credential = await validateOne(
      issued,
      gateFor([{ issuer: TEST_ISSUER, keyStorage: 'iso_18045_high' }], 'oid4vp-1.0-base')
    );

    // The base profile's posture is `forbidden`, and the resolver returns
    // before it ever reads the attesting-issuer record. So a deployment that
    // configures `OID4VP_ATTESTING_ISSUERS` on the base profile gets exactly
    // what it got before #379 — no evidence, and no way for a hardware-demanding
    // entry to grant.
    expect(credential.assurance.keyStorageAssurance.assurance).toBe('none');
    expect(
      levelFor(credential, envAssurance({ level: 'high', requiresKeyStorage: 'hardware' }))
    ).toBe('low');

    // An entry that demands nothing still grants, exactly as it did before.
    expect(levelFor(credential, envAssurance({ level: 'high' }))).toBe('high');
  });
});
