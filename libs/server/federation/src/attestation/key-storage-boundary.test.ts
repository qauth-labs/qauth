import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import {
  createKeyAttestationPki,
  issueKeyAttestation,
  type KeyAttestationPki,
} from '../../testing/key-attestation.fixture';
import {
  fixtureValidationContext,
  issueSdJwtVc,
  presentSdJwtVc,
  TEST_CREDENTIAL_QUERY,
  TEST_ISSUER,
} from '../../testing/sd-jwt-vc.fixture';
import { isPresentationValidationRejection } from '../oid4vp/presentation-rejection';
import { validateSdJwtVcPresentation } from '../oid4vp/sd-jwt-vc';
import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import { createWalletProvider } from '../providers/wallet.provider';
import { assertIssuerTrusted } from '../trust/trust-registry';
import { createStaticAttestingIssuers } from './attesting-issuers';
import {
  createKeyStorageAssuranceResolver,
  keyStorageAssuranceGateFor,
} from './key-storage-assurance';

/**
 * The safety boundary of issue #308, asserted rather than merely documented.
 *
 * #308 adds a gate that asks where the holder's private key LIVES. It is a real
 * addition — a `haip-1.0` presentation that cannot establish key storage is now
 * refused outright — and it is emphatically NOT authentication:
 *
 *  - key storage is layered ON TOP of holder binding (#234), never in place of
 *    it: a presentation whose holder binding fails is refused whether or not its
 *    key lives in certified hardware;
 *  - it is not issuer trust (#236): certified hardware holding a credential from
 *    an issuer nobody trusts is a well-protected forgery;
 *  - and it resolves no subject (ADR-009 / #300), which is why `verify()` still
 *    throws for a presentation that clears every gate this issue adds.
 *
 * If a change makes this file fail, the change is wrong. Do not soften the
 * assertions to make it pass.
 */

const NONCE = 'nonce-for-the-boundary';

let pki: KeyAttestationPki;

beforeAll(() => {
  pki = createKeyAttestationPki();
});

/** A `haip-1.0` gate with this deployment's registries wired in. */
function haipGate() {
  return keyStorageAssuranceGateFor(
    VERIFIER_PROFILES['haip-1.0'],
    createKeyStorageAssuranceResolver({
      attestingIssuers: createStaticAttestingIssuers([
        { issuer: TEST_ISSUER, keyStorage: 'iso_18045_high' },
      ]),
      keyAttestationAnchors: pki.anchors,
    })
  );
}

/** Issue, present and validate a credential that clears the #308 gate outright. */
async function validateAttestedPresentation() {
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
  const presentation = await presentSdJwtVc(issued, { nonce: NONCE });

  const validated = await validateSdJwtVcPresentation(
    presentation,
    'pid',
    TEST_CREDENTIAL_QUERY,
    fixtureValidationContext(issued, NONCE, { keyStorageAssurance: haipGate() })
  );

  return { validated, presentation, issued, attestation };
}

describe('#308 safety boundary — attested key storage authenticates nobody', () => {
  it('produces a ValidatedCredential that is still not an identity', async () => {
    const { validated } = await validateAttestedPresentation();

    expect(validated.assurance.keyStorageAssurance.assurance).toBe('key-attested');

    const surface = JSON.stringify(validated);

    expect(surface).not.toContain('externalSub');
    expect(surface).not.toContain('external_sub');
    expect(surface).not.toContain('userId');
    expect(validated).not.toHaveProperty('assuranceLevel');
    expect(validated).not.toHaveProperty('rawClaims');
  });

  it('carries away no holder key material and no copy of the attestation', async () => {
    // The attestation embeds the attested public keys and a certificate chain.
    // Both are exactly the linkability material OID4VP §15.5–§15.6 and ADR-009
    // forbid keying an account on, so the gate CONSUMES them and drops them.
    const { validated, attestation } = await validateAttestedPresentation();
    const surface = JSON.stringify(validated);

    expect(surface).not.toContain('cnf');
    expect(surface).not.toContain('"kty"');
    expect(surface).not.toContain('key_attestation');
    expect(surface).not.toContain(attestation);
  });

  it('leaves the issuer UNTRUSTED — hardware assurance is not a trust decision', async () => {
    // A credential in certified hardware from an issuer this realm never
    // allowlisted is a well-protected forgery. #236's gate must still refuse.
    const { validated } = await validateAttestedPresentation();

    expect(() => assertIssuerTrusted(undefined, validated.issuer)).toThrow(
      /Verifiable Presentation rejected/
    );
  });

  it('WalletProvider.verify() STILL throws for a fully attested presentation', async () => {
    const { presentation } = await validateAttestedPresentation();

    await expect(
      createWalletProvider().verify({ vp_token: { pid: [presentation] }, state: 'anything' })
    ).rejects.toThrow(/not implemented/);
  });
});

describe('#308 never relaxes the gates below it', () => {
  it('refuses a broken Key Binding JWT even when key storage is attested', async () => {
    // Layering, proven: a genuine attestation over the credential's own key does
    // not excuse a presentation the holder never bound to this request.
    const holderKeys = (await issueSdJwtVc()).holderKeys;
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderKeys.jwk],
      keyStorage: ['iso_18045_high'],
    });
    const issued = await issueSdJwtVc({
      holderKeys,
      cnf: { jwk: holderKeys.jwk, key_attestation: attestation },
    });
    const stale = await presentSdJwtVc(issued, { nonce: 'a-nonce-from-another-request' });

    try {
      await validateSdJwtVcPresentation(
        stale,
        'pid',
        TEST_CREDENTIAL_QUERY,
        fixtureValidationContext(issued, NONCE, { keyStorageAssurance: haipGate() })
      );
      expect.fail('a presentation bound to another request must be refused');
    } catch (error) {
      if (!isPresentationValidationRejection(error)) throw error;
      // The holder-binding refusal, NOT the key-storage one: #234 runs first and
      // its verdict is not something #308 can override.
      expect(error.reason).toBe('holder-binding-invalid');
    }
  });

  it('refuses an expired credential even when key storage is attested', async () => {
    const holderKeys = (await issueSdJwtVc()).holderKeys;
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderKeys.jwk],
      keyStorage: ['iso_18045_high'],
    });
    const issued = await issueSdJwtVc({
      holderKeys,
      cnf: { jwk: holderKeys.jwk, key_attestation: attestation },
      exp: Math.floor(Date.now() / 1000) - 7200,
    });

    try {
      await validateSdJwtVcPresentation(
        await presentSdJwtVc(issued, { nonce: NONCE }),
        'pid',
        TEST_CREDENTIAL_QUERY,
        fixtureValidationContext(issued, NONCE, { keyStorageAssurance: haipGate() })
      );
      expect.fail('an expired credential must be refused');
    } catch (error) {
      if (!isPresentationValidationRejection(error)) throw error;
      expect(error.reason).toBe('credential-expired');
    }
  });

  it('refuses an unresolvable issuer key even when key storage is attested', async () => {
    const holderKeys = (await issueSdJwtVc()).holderKeys;
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderKeys.jwk],
      keyStorage: ['iso_18045_high'],
    });
    const issued = await issueSdJwtVc({
      holderKeys,
      cnf: { jwk: holderKeys.jwk, key_attestation: attestation },
    });

    try {
      await validateSdJwtVcPresentation(
        await presentSdJwtVc(issued, { nonce: NONCE }),
        'pid',
        TEST_CREDENTIAL_QUERY,
        fixtureValidationContext(issued, NONCE, {
          resolveIssuerKey: async () => undefined,
          keyStorageAssurance: haipGate(),
        })
      );
      expect.fail('a credential whose issuer key cannot be resolved must be refused');
    } catch (error) {
      if (!isPresentationValidationRejection(error)) throw error;
      expect(error.reason).toBe('issuer-key-unresolvable');
    }
  });
});

/**
 * A grep, deliberately, for the two structural rules #308 inherits.
 *
 * Neither is expressible as a unit test of any single module: the first is about
 * where a symbol may APPEAR, and the second about what a directory may name.
 */
describe('#308 structural rules', () => {
  const attestationDir = __dirname;
  const srcRoot = path.join(attestationDir, '..');

  /** Every production `.ts` under `src/`, with block comments stripped. */
  function productionSources(directory: string): { file: string; code: string }[] {
    const found: { file: string; code: string }[] = [];

    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);

      if (entry.isDirectory()) {
        found.push(...productionSources(full));
        continue;
      }

      if (!entry.isFile() || !entry.name.endsWith('.ts')) continue;
      if (entry.name.endsWith('.test.ts')) continue;

      found.push({
        file: path.relative(srcRoot, full),
        // The boundary is DESCRIBED in the JSDoc on purpose.
        code: readFileSync(full, 'utf8').replace(/\/\*[\s\S]*?\*\//g, ''),
      });
    }

    return found;
  }

  it('finds the source tree it is asserting about', () => {
    // A walk that silently found nothing would make both rules below vacuous.
    expect(productionSources(srcRoot).length).toBeGreaterThan(20);
    expect(productionSources(attestationDir).length).toBeGreaterThan(3);
  });

  it('keeps every HAIP-specific key-attestation constant inside this adapter', () => {
    // #308 acceptance criterion: "No HAIP-specific key-attestation constant
    // appears outside the `haip-1.0` profile definition and this adapter." The
    // §D.2 level vocabulary and the Appendix D media type are those constants;
    // `verifier-profiles.ts` is the one file outside `attestation/` allowed to
    // name a level, and only inside its `haip-1.0` entry.
    const permitted = new Set(['profiles/verifier-profiles.ts']);
    const leaks: string[] = [];

    for (const { file, code } of productionSources(srcRoot)) {
      if (file.startsWith(`attestation${path.sep}`)) continue;
      if (permitted.has(file.split(path.sep).join('/'))) continue;

      if (/iso_18045_/.test(code) || /key-attestation\+jwt/.test(code)) {
        leaks.push(file);
      }
    }

    expect(leaks).toEqual([]);
  });

  it('names no HAIP-only level in the base profile entry', () => {
    // The other half of the same criterion, asserted on the profile most at risk
    // of acquiring one by copy-paste.
    expect(JSON.stringify(VERIFIER_PROFILES['oid4vp-1.0-base'])).not.toContain('iso_18045');
  });

  it('never produces an identity anywhere in attestation/', () => {
    for (const { file, code } of productionSources(attestationDir)) {
      expect(
        /VerifiedIdentity/.test(code),
        `${file} references VerifiedIdentity; key-storage assurance is evidence, and only #236 + #300 can turn a credential into an identity.`
      ).toBe(false);
      expect(
        /externalSub|external_sub/.test(code),
        `${file} appears to derive a wallet subject; ADR-009 forbids keying an account on wallet cryptography, and this gate handles exactly that material.`
      ).toBe(false);
      expect(
        /assuranceLevel/.test(code),
        `${file} emits an assuranceLevel; #308 reports key-storage EVIDENCE and #237 derives the eIDAS level.`
      ).toBe(false);
    }
  });
});
