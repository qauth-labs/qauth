import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import type { JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  createKeyAttestationPki,
  issueKeyAttestation,
  type KeyAttestationPki,
} from '../../testing/key-attestation.fixture';
import { generateFixtureKeys } from '../../testing/sd-jwt-vc.fixture';
import { createTestCertificate } from '../status/test/x509-fixtures';
import {
  createKeyAttestationTrustAnchors,
  KEY_ATTESTATION_TYP,
  NO_KEY_ATTESTATION_TRUST_ANCHORS,
  validateKeyAttestation,
} from './key-attestation';

/**
 * OID4VCI Appendix D key-attestation validation (#308).
 *
 * Every test below states ONE deviation from an attestation that validates
 * cleanly, so a failure names the check that stopped working rather than the
 * fixture that stopped building.
 */

let pki: KeyAttestationPki;
/** The credential's holder-binding key — what an attestation must attest. */
let holderJwk: JWK;
/** A different real key, for the "attests somebody else's key" cases. */
let otherJwk: JWK;

beforeAll(async () => {
  pki = createKeyAttestationPki();
  holderJwk = (await generateFixtureKeys('ES256')).jwk;
  otherJwk = (await generateFixtureKeys('ES256')).jwk;
});

/** Validate against the fixture PKI at the current time. */
async function validate(attestation: unknown, confirmationJwk: JWK = holderJwk) {
  return validateKeyAttestation({
    attestation,
    confirmationJwk,
    anchors: pki.anchors,
    now: new Date(),
  });
}

describe('createKeyAttestationTrustAnchors (#308)', () => {
  it('compiles operator PEMs into an anchor set', () => {
    expect(createKeyAttestationTrustAnchors([pki.root.pem]).size).toBe(1);
  });

  it('yields the deny-all set for an empty configuration', () => {
    expect(createKeyAttestationTrustAnchors([])).toBe(NO_KEY_ATTESTATION_TRUST_ANCHORS);
    expect(NO_KEY_ATTESTATION_TRUST_ANCHORS.size).toBe(0);
  });

  it('throws on a malformed anchor rather than silently dropping it', () => {
    // A dropped anchor leaves the operator believing a wallet provider is
    // recognised when it is not.
    expect(() => createKeyAttestationTrustAnchors(['-----BEGIN CERTIFICATE----- nope'])).toThrow(
      InvalidConfigurationError
    );
  });

  it('names the key-attestation setting, not the status-list one, in its refusal', () => {
    // The two anchor sets are different operator settings compiled by the same
    // machinery. An operator who mis-pastes one must be told which.
    try {
      createKeyAttestationTrustAnchors(['nope']);
      expect.fail('a malformed anchor must be refused');
    } catch (error) {
      expect((error as InvalidConfigurationError).message).toContain('key attestation');
      expect((error as InvalidConfigurationError).message).toContain('#308');
    }
  });
});

describe('validateKeyAttestation — the clean path', () => {
  it('validates an attestation that attests the credential holder key', async () => {
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      userAuthentication: ['iso_18045_moderate'],
    });

    expect(await validate(attestation)).toEqual({
      outcome: 'validated',
      attestation: {
        keyStorage: 'iso_18045_high',
        userAuthentication: 'iso_18045_moderate',
      },
    });
  });

  it('reports key storage and user authentication SEPARATELY', async () => {
    // A certified enclave behind no PIN and a software key behind a certified
    // biometric are different propositions; merging them would report a level
    // neither component actually resists.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      userAuthentication: ['iso_18045_basic'],
    });

    const result = await validate(attestation);

    expect(result.outcome).toBe('validated');
    if (result.outcome !== 'validated') return;
    expect(result.attestation.keyStorage).toBe('iso_18045_high');
    expect(result.attestation.userAuthentication).toBe('iso_18045_basic');
  });

  it('validates a batch attestation that includes the holder key among others', async () => {
    // Batch issuance legitimately attests many keys at once.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [otherJwk, holderJwk],
      keyStorage: ['iso_18045_high'],
    });

    expect((await validate(attestation)).outcome).toBe('validated');
  });

  it('validates when the chain is a single anchored certificate', async () => {
    // A one-tier operator PKI: the signing leaf is issued directly by the
    // anchor, so `x5c` carries only the leaf.
    const direct = createTestCertificate({
      subject: 'Direct Attestation Signer',
      issuer: pki.root,
      keyUsage: ['digitalSignature'],
    });

    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      signer: direct,
      x5c: [direct.x5c],
    });

    expect((await validate(attestation)).outcome).toBe('validated');
  });

  it('carries no attested level when the attestation states none', async () => {
    // Appendix D makes both level claims optional. An attestation without them
    // still proves the key was attested; it grades nothing, and a floor above
    // "any" therefore refuses it downstream.
    const attestation = await issueKeyAttestation(pki, { attestedKeys: [holderJwk] });

    expect(await validate(attestation)).toEqual({ outcome: 'validated', attestation: {} });
  });
});

describe('validateKeyAttestation — HAIP §4.5.1 chain prohibitions', () => {
  it('rejects a SELF-SIGNED attestation certificate', async () => {
    // "The X.509 certificate signing the key attestation MUST NOT be
    // self-signed." A self-signed signer is an unbacked assertion: anyone can
    // mint one and attest their own software key with it.
    const selfSigned = createTestCertificate({
      subject: 'Self-Signed Attestation Signer',
      keyUsage: ['digitalSignature'],
    });

    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      signer: selfSigned,
      x5c: [selfSigned.x5c],
    });

    expect(await validate(attestation)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-certificate-self-signed',
    });
  });

  it('rejects an attestation whose x5c INCLUDES the trust anchor', async () => {
    // "The X.509 certificate of the trust anchor MUST NOT be included in the
    // `x5c` JOSE header." Tolerating it would turn "chains to an anchor" into
    // "carries a copy of an anchor", which any attacker can also do.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      x5c: [pki.leaf.x5c, pki.intermediate.x5c, pki.root.x5c],
    });

    expect(await validate(attestation)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-anchor-in-chain',
    });
  });

  it('rejects a chain that reaches no configured anchor', async () => {
    // A complete, internally consistent chain under a CA this deployment never
    // anchored. Every signature verifies; none of it means anything.
    const foreignRoot = createTestCertificate({
      subject: 'Unknown Provider Root',
      ca: true,
      keyUsage: ['keyCertSign'],
    });
    const foreignLeaf = createTestCertificate({
      subject: 'Unknown Provider Signer',
      issuer: foreignRoot,
      keyUsage: ['digitalSignature'],
    });

    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      signer: foreignLeaf,
      x5c: [foreignLeaf.x5c],
    });

    expect(await validate(attestation)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-chain-unanchored',
    });
  });

  it('rejects every attestation when no anchors are configured', async () => {
    // The unconfigured deployment must refuse, not accept: an anchor set of
    // zero means "trust no wallet provider", never "trust any".
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
    });

    expect(
      await validateKeyAttestation({
        attestation,
        confirmationJwk: holderJwk,
        anchors: NO_KEY_ATTESTATION_TRUST_ANCHORS,
        now: new Date(),
      })
    ).toEqual({ outcome: 'rejected', reason: 'attestation-chain-unanchored' });
  });

  it('rejects an expired signing certificate', async () => {
    const expiredPki = createKeyAttestationPki({
      leafNotBefore: new Date(Date.now() - 7_200_000),
      leafNotAfter: new Date(Date.now() - 3_600_000),
    });

    const attestation = await issueKeyAttestation(expiredPki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
    });

    expect(
      await validateKeyAttestation({
        attestation,
        confirmationJwk: holderJwk,
        anchors: expiredPki.anchors,
        now: new Date(),
      })
    ).toEqual({ outcome: 'rejected', reason: 'attestation-chain-unanchored' });
  });
});

describe('validateKeyAttestation — the cnf binding', () => {
  it('rejects a flawless attestation of somebody ELSE’s key', async () => {
    // The attack this check exists for: an attestation is not addressed to
    // QAuth, carries no audience, and is not bound to this presentation. Without
    // the `cnf` comparison, ANY genuine attestation — captured, published, or
    // the attacker's own for a real hardware key — can be attached to a
    // credential bound to a software key they fully control, and every other
    // check here still passes.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [otherJwk],
      keyStorage: ['iso_18045_high'],
    });

    expect(await validate(attestation)).toEqual({
      outcome: 'rejected',
      reason: 'attested-key-mismatch',
    });
  });

  it('compares the KEY, not its wrapper: extra JWK members do not break the match', async () => {
    // RFC 7638 covers the canonical required members only, so a wallet that
    // publishes the same key with a `kid`, `use` or different member order still
    // matches. A structural comparison would reject a legitimate wallet here.
    const decorated: JWK = { ...holderJwk, kid: 'attested-1', use: 'sig' };

    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [decorated],
      keyStorage: ['iso_18045_high'],
    });

    expect((await validate(attestation)).outcome).toBe('validated');
  });

  it('rejects when the credential’s own confirmation key is unusable', async () => {
    // Fail-closed on the degenerate input: if no thumbprint can be computed for
    // the credential's key, nothing can be shown to attest it.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
    });

    expect(await validate(attestation, { kty: 'oops' } as unknown as JWK)).toEqual({
      outcome: 'rejected',
      reason: 'attested-key-mismatch',
    });
  });

  it.each([
    ['an empty array', []],
    ['a non-array', 'the-key'],
    ['a missing claim', undefined],
    ['entries that are not objects', ['not-a-jwk']],
  ])('rejects an attestation whose attested_keys is %s', async (_label, attestedKeys) => {
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      payloadOverrides: { attested_keys: attestedKeys },
    });

    const result = await validate(attestation);

    expect(result.outcome).toBe('rejected');
    if (result.outcome !== 'rejected') return;
    // A non-object entry is malformed but produces the mismatch outcome, since
    // it is skipped rather than parsed; both are refusals either way.
    expect(['attestation-malformed', 'attested-key-mismatch']).toContain(result.reason);
  });
});

describe('validateKeyAttestation — token shape and freshness', () => {
  it('rejects an attestation declaring an algorithm the profile does not permit', async () => {
    // HAIP §7 pins ES256. The header only ever SELECTS from what is permitted;
    // it can never widen it (RFC 9700 algorithm confusion). Rewritten AFTER
    // signing, because a P-256 key cannot produce an ES384 signature in the
    // first place — which is precisely the case: the refusal must come from the
    // declared `alg` alone, before any key is looked for.
    const signed = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
    });

    const [header, payload, signature] = signed.split('.');
    const declared = JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    const rewritten = Buffer.from(JSON.stringify({ ...declared, alg: 'ES384' }), 'utf8').toString(
      'base64url'
    );

    expect(await validate(`${rewritten}.${payload}.${signature}`)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-malformed',
    });
  });

  it('rejects an attestation declaring alg: none', async () => {
    const signed = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
    });

    const [header, payload, signature] = signed.split('.');
    const declared = JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    const rewritten = Buffer.from(JSON.stringify({ ...declared, alg: 'none' }), 'utf8').toString(
      'base64url'
    );

    expect(await validate(`${rewritten}.${payload}.${signature}`)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-malformed',
    });
  });

  it('rejects a token whose typ is not key-attestation+jwt', async () => {
    // Cross-token confusion (RFC 8725 §3.11): without this, any other JWS the
    // wallet provider's anchored key ever signed replays here as an attestation.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      typ: 'jwt',
    });

    expect(await validate(attestation)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-malformed',
    });
  });

  it('reads typ from the AUTHENTICATED header, not the one used to nominate a key', async () => {
    // The `typ` a validator acts on must come from the verified header. This
    // attestation declares the right `typ`, so a validator reading the
    // unverified copy would accept it — but the SIGNED header is what
    // `verifyWithHeader` returns, and the two agree here by construction. The
    // meaningful assertion is the negative one above; this pins that the happy
    // path reads the same member.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
    });

    expect(attestation.split('.')).toHaveLength(3);
    expect(
      JSON.parse(Buffer.from(attestation.split('.')[0], 'base64url').toString('utf8'))
    ).toMatchObject({ typ: KEY_ATTESTATION_TYP });
    expect((await validate(attestation)).outcome).toBe('validated');
  });

  it('rejects an expired attestation', async () => {
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      iat: Math.floor(Date.now() / 1000) - 7200,
      exp: Math.floor(Date.now() / 1000) - 3600,
    });

    expect(await validate(attestation)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-signature-invalid',
    });
  });

  it('rejects an attestation issued in the future', async () => {
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      iat: Math.floor(Date.now() / 1000) + 3600,
    });

    expect(await validate(attestation)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-signature-invalid',
    });
  });

  it('rejects an attestation carrying no iat', async () => {
    // An attestation with no issuance time cannot be reasoned about for
    // freshness at all, and a verifier that saw no temporal claim checked none.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_high'],
      payloadOverrides: { iat: undefined },
    });

    expect(await validate(attestation)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-malformed',
    });
  });

  it('rejects an attestation whose levels were promoted after signing', async () => {
    // The obvious forgery: take a genuine attestation for a basic-resistance key
    // and rewrite `key_storage` to the level a `haip-1.0` floor demands.
    const attestation = await issueKeyAttestation(pki, {
      attestedKeys: [holderJwk],
      keyStorage: ['iso_18045_basic'],
    });

    const [header, payload, signature] = attestation.split('.');
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    const promoted = Buffer.from(
      JSON.stringify({ ...claims, key_storage: ['iso_18045_high'] }),
      'utf8'
    ).toString('base64url');

    // The forged bytes really are different, or the test would pass vacuously.
    expect(promoted).not.toBe(payload);

    expect(await validate(`${header}.${promoted}.${signature}`)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-signature-invalid',
    });
  });

  it.each([
    ['a non-string', 42],
    ['an empty string', ''],
    ['a two-segment token', 'aGVhZGVy.cGF5bG9hZA'],
    ['a non-base64url header', '!!!.eyJhIjoxfQ.c2ln'],
    ['a header that is not JSON', 'bm90LWpzb24.eyJhIjoxfQ.c2ln'],
    ['undefined', undefined],
    ['an object', { attestation: 'x' }],
  ])('rejects %s as malformed', async (_label, value) => {
    expect(await validate(value)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-malformed',
    });
  });

  it('rejects an attestation past the length bound before parsing it', async () => {
    expect(await validate(`${'a'.repeat(40_000)}.b.c`)).toEqual({
      outcome: 'rejected',
      reason: 'attestation-malformed',
    });
  });

  it('never throws, whatever it is handed', async () => {
    // A throw would become a 500 for an attacker-supplied document, making
    // failure modes distinguishable by response code — the enumeration this
    // path exists to prevent.
    for (const value of [null, undefined, [], {}, Number.NaN, 'x'.repeat(100)]) {
      await expect(validate(value)).resolves.toMatchObject({ outcome: 'rejected' });
    }
  });
});
