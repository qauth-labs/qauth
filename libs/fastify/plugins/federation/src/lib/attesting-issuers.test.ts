import {
  NO_KEY_STORAGE_ASSURANCE,
  ValidatedIssuer,
  VERIFIER_PROFILES,
} from '@qauth-labs/server-federation';
import { describe, expect, it } from 'vitest';

import {
  type ConfiguredAttestingIssuers,
  createConfiguredKeyStorageAssuranceResolver,
  keyStorageAssuranceProvisioningOf,
} from './attesting-issuers';

/**
 * The configuration surface #308 shipped without (issue #379).
 *
 * `createStaticAttestingIssuers` and `createKeyStorageAssuranceResolver` existed
 * with ZERO non-test callers, and `app.ts` never passed
 * `keyStorageAssuranceProvisioned` — so `assertKeyStorageAssuranceProvisioned`
 * was permanently in its refusing state, a constant rather than a predicate.
 * What is tested here is the seam that ends both: one environment variable in,
 * a wired resolver and a truthful provisioning answer out.
 */

const ISSUER = 'https://pid.member-state.example';
const HIGH = 'iso_18045_high';

/**
 * A `ValidatedIssuer` as #234 produces one.
 *
 * Obtained through the nominal factory rather than an object literal: the
 * registry re-checks `ValidatedIssuer.isValidated`, so a literal would be
 * rejected and every assertion below would pass vacuously.
 */
function validatedIssuer(identifier: string): ValidatedIssuer {
  return ValidatedIssuer.fromValidatedPresentation({
    identifier,
    keyResolution: 'issuer-metadata',
  });
}

/** The `permitted` posture — the only one that reaches the record without a floor. */
const PERMISSIVE_POLICY = {
  posture: 'permitted' as const,
};

/** What the gate passes the resolver for one credential. */
function inputFor(identifier: string) {
  return {
    issuer: validatedIssuer(identifier),
    confirmationJwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' },
    claims: Object.freeze({}),
  };
}

describe('keyStorageAssuranceProvisioningOf (#308/#379)', () => {
  it('reports NOT provisioned for an unset, empty or unusable record', () => {
    // Fail-closed, and the honest answer: a deployment recording no attesting
    // issuer and holding no key-attestation anchors can establish key storage by
    // no path at all, so a mandating profile must not start here.
    for (const configured of [undefined, null, {}, Object.create(null), 'x', 3]) {
      expect(keyStorageAssuranceProvisioningOf(configured as ConfiguredAttestingIssuers)).toEqual(
        {}
      );
    }
  });

  it('reports the GRADE recorded, not merely that something was', () => {
    // The boot gate compares against the profile's floor, so a boolean was the
    // wrong answer shape: it said "provisioned" for a registry that could not
    // clear `haip-1.0`'s `iso_18045_high` and let the deployment boot straight
    // into refusing every presentation (#379 review).
    expect(keyStorageAssuranceProvisioningOf({ [ISSUER]: HIGH })).toEqual({
      strongestAttestedKeyStorage: HIGH,
    });
  });

  it('reports the STRONGEST grade across a mixed registry', () => {
    // The gate asks whether the deployment can clear the floor for ANY recorded
    // ecosystem, not for every one. A registry pairing a `high` issuer with a
    // `basic` one is a working deployment with one weak ecosystem, and refusing
    // to start on it would be wrong.
    expect(
      keyStorageAssuranceProvisioningOf({
        [ISSUER]: 'iso_18045_basic',
        'https://strong.example': HIGH,
        'https://middling.example': 'iso_18045_moderate',
      })
    ).toEqual({ strongestAttestedKeyStorage: HIGH });
  });

  it('reports the weak grade as-is, so the gate can refuse it against a higher floor', () => {
    expect(keyStorageAssuranceProvisioningOf({ [ISSUER]: 'iso_18045_basic' })).toEqual({
      strongestAttestedKeyStorage: 'iso_18045_basic',
    });
  });

  it('reports nothing provisioned for a registry of grades this build cannot read', () => {
    // `assertAttestingIssuersUsable` refuses those loudly at boot, naming the
    // position and the value. This must not reach a SECOND, differently-worded
    // refusal for the same typo — so it returns the same value an empty map does.
    expect(keyStorageAssuranceProvisioningOf({ [ISSUER]: 'ISO_18045_HIGH' })).toEqual({});
  });

  it('never claims the DIRECT path, which has no configuration surface yet', () => {
    // Stating `false` explicitly would read as a fact established rather than a
    // path not built, and the boot gate's `=== true` treats both alike.
    expect(
      keyStorageAssuranceProvisioningOf({ [ISSUER]: HIGH }).hasKeyAttestationAnchors
    ).toBeUndefined();
  });

  it('reads a prototype-less record, which is what server-config hardens to', () => {
    // `Object.keys` on an `Object.create(null)` map — a `hasOwnProperty` call
    // would throw on exactly the object this is always given in production.
    const configured = Object.create(null) as Record<string, string>;
    configured[ISSUER] = HIGH;

    expect(keyStorageAssuranceProvisioningOf(configured)).toEqual({
      strongestAttestedKeyStorage: HIGH,
    });
  });
});

describe('createConfiguredKeyStorageAssuranceResolver (#308/#379)', () => {
  it('builds nothing for an unconfigured deployment', () => {
    // `undefined` rather than an empty resolver, so "provisioned nothing"
    // reaches `keyStorageAssuranceGateFor` as an absent resolver and becomes the
    // deny-all — the posture is kept and the evidence refused.
    for (const configured of [undefined, null, {}]) {
      expect(
        createConfiguredKeyStorageAssuranceResolver(configured as ConfiguredAttestingIssuers)
      ).toBeUndefined();
    }
  });

  it('establishes issuer-attested evidence for an issuer the operator recorded', async () => {
    const resolver = createConfiguredKeyStorageAssuranceResolver({ [ISSUER]: HIGH });
    if (resolver === undefined) throw new Error('a configured record must build a resolver');

    const decision = await resolver.resolveKeyStorageAssurance(inputFor(ISSUER), PERMISSIVE_POLICY);

    // The acceptance criterion, at this layer: an issuer the operator recorded
    // produces evidence that is NOT `'none'`.
    expect(decision.outcome).toBe('accepted');
    expect(decision.outcome === 'accepted' && decision.evidence).toEqual({
      assurance: 'issuer-attested',
      keyStorage: HIGH,
    });
  });

  it('establishes nothing for an issuer the operator did NOT record', async () => {
    const resolver = createConfiguredKeyStorageAssuranceResolver({ [ISSUER]: HIGH });
    if (resolver === undefined) throw new Error('a configured record must build a resolver');

    const decision = await resolver.resolveKeyStorageAssurance(
      inputFor('https://someone-else.example'),
      PERMISSIVE_POLICY
    );

    // Trusting an issuer's claims about a PERSON is a different decision from
    // trusting its claims about a DEVICE. An unrecorded issuer attests nothing,
    // however trusted it is for issuing credentials.
    expect(decision.outcome === 'accepted' && decision.evidence).toEqual(NO_KEY_STORAGE_ASSURANCE);
  });

  it('establishes nothing under the base profile posture, whatever is recorded', async () => {
    const resolver = createConfiguredKeyStorageAssuranceResolver({ [ISSUER]: HIGH });
    if (resolver === undefined) throw new Error('a configured record must build a resolver');

    const decision = await resolver.resolveKeyStorageAssurance(inputFor(ISSUER), {
      posture: VERIFIER_PROFILES['oid4vp-1.0-base'].keyStorageAssurance,
    });

    // `oid4vp-1.0-base` forbids key-storage evaluation, so configuring
    // `OID4VP_ATTESTING_ISSUERS` on it changes nothing at all — the "unchanged
    // end to end" criterion, asserted where the record is actually read.
    expect(decision.outcome === 'accepted' && decision.evidence).toEqual(NO_KEY_STORAGE_ASSURANCE);
  });

  it('throws rather than dropping an entry the runtime cannot use', () => {
    // `server-config` has already validated both shapes, so reaching this throw
    // means configuration changed under a running process. Dropping the entry
    // would leave the operator believing an ecosystem is recognised when it is
    // not — every user of that wallet silently failing to reach the assurance
    // their credential should carry.
    expect(() => createConfiguredKeyStorageAssuranceResolver({ 'not-a-url': HIGH })).toThrow();
    expect(() =>
      createConfiguredKeyStorageAssuranceResolver({ [ISSUER]: 'iso_18045_supreme' })
    ).toThrow();
  });
});
