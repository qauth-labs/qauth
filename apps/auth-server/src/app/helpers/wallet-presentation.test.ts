import {
  type ValidatedCredential,
  ValidatedIssuer,
  walletCredentialDataSchema,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { resolveWalletPresentation } from './wallet-presentation';

const REALM_ID = '11111111-1111-1111-1111-111111111111';
const REALM_NAME = 'master';
const ISSUER = 'https://issuer.example.com';
const VCT = 'https://credentials.example.com/pid';

/**
 * The deployment this suite runs as: base profile, one trusted issuer,
 * `asserted-lookup` bound to the PID's mandatory name attributes.
 *
 * Mutated per test so a single variable can be knocked out — that is how the
 * "one gate missing means one refusal" assertions below are written.
 */
const testEnv = vi.hoisted(() => ({
  OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' as string | undefined,
  OID4VP_TRUSTED_ISSUERS: { master: ['https://issuer.example.com'] } as
    Record<string, string[]> | undefined,
  OID4VP_SUBJECT_RESOLUTION: undefined as string | undefined,
  OID4VP_SUBJECT_BINDING_CLAIMS: ['family_name', 'given_name'] as readonly string[] | undefined,
  OID4VP_SUBJECT_CLAIM: undefined as string | undefined,
  OID4VP_SUBJECT_CLAIM_ISSUERS: undefined as readonly string[] | undefined,
}));

// Hoisted above every import by vitest, so the module under test reads
// `testEnv` rather than the process environment. Each test knocks out one
// variable to prove the gate it feeds actually refuses.
vi.mock('../../config/env', () => ({ env: testEnv }));

/**
 * The wallet-login authentication seam (#235 implementing #239's boundary).
 *
 * Every gate the module documents is exercised by REMOVING it and asserting the
 * same refusal comes back: no profile, an issuer this realm does not trust, a
 * format the profile forbids, an unconfigured strategy. That shape is
 * deliberate — the security property is not "the happy path works", it is that
 * a missing gate refuses and that all refusals look alike.
 */
function credentialFor(
  claims: Record<string, unknown>,
  overrides: Partial<ValidatedCredential> = {}
): ValidatedCredential {
  return {
    queryId: 'pid',
    format: 'dc+sd-jwt',
    credentialType: VCT,
    issuer: ValidatedIssuer.fromValidatedPresentation({
      identifier: ISSUER,
      keyResolution: 'issuer-metadata',
    }),
    claims,
    validity: {},
    assurance: {
      credentialType: VCT,
      issuerKeyResolution: 'issuer-metadata',
      issuerSignatureAlgorithm: 'ES256',
      keyBindingAlgorithm: 'ES256',
      disclosedClaimCount: Object.keys(claims).length,
      statusChecked: false,
    },
    ...overrides,
  };
}

function fakeFastify() {
  const userCredentials = {
    findByRealmAndSub: vi.fn().mockResolvedValue([]),
    findByRealmProviderSub: vi.fn().mockResolvedValue(undefined),
    create: vi
      .fn()
      .mockImplementation(async (data: unknown) => ({ id: 'cred-new', ...(data as object) })),
  };
  const userAttributes = { upsertMany: vi.fn().mockResolvedValue([]) };
  const users = { create: vi.fn().mockResolvedValue({ id: 'user-new', realmId: REALM_ID }) };
  const realms = { findById: vi.fn().mockResolvedValue({ id: REALM_ID, name: REALM_NAME }) };

  const fastify = {
    log: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
    repositories: { userCredentials, userAttributes, users, realms },
    db: {
      transaction: vi.fn().mockImplementation(async (run: (tx: unknown) => unknown) => run('tx')),
    },
  } as unknown as FastifyInstance;

  return { fastify, userCredentials, userAttributes, users, realms };
}

function inputFor(credential?: ValidatedCredential) {
  return {
    realmId: REALM_ID,
    stateHash: 'a'.repeat(64),
    assertedIdentifier: 'alice@example.com',
    ...(credential === undefined ? {} : { credential }),
  };
}

describe('resolveWalletPresentation', () => {
  let harness: ReturnType<typeof fakeFastify>;

  beforeEach(() => {
    harness = fakeFastify();
    testEnv.OID4VP_VERIFIER_PROFILE = 'oid4vp-1.0-base';
    testEnv.OID4VP_TRUSTED_ISSUERS = { [REALM_NAME]: [ISSUER] };
    testEnv.OID4VP_SUBJECT_RESOLUTION = undefined;
    testEnv.OID4VP_SUBJECT_BINDING_CLAIMS = ['family_name', 'given_name'];
  });

  describe('the gate that is still open', () => {
    it('refuses when the route supplied no validated credential', async () => {
      // `POST /oid4vp/response` cannot validate one until issuer key material is
      // configurable, so this is the production outcome today.
      expect(await resolveWalletPresentation(harness.fastify, inputFor())).toEqual({
        status: 'rejected',
      });
      expect(harness.fastify.log.warn).toHaveBeenCalledTimes(1);
    });

    it('refuses identically whatever identifier is asserted (no enumeration)', async () => {
      const known = await resolveWalletPresentation(harness.fastify, {
        ...inputFor(),
        assertedIdentifier: 'alice@example.com',
      });
      const unknown = await resolveWalletPresentation(harness.fastify, {
        ...inputFor(),
        assertedIdentifier: 'nobody-at-all@example.com',
      });

      expect(known).toEqual(unknown);
    });
  });

  describe('with a validated credential', () => {
    const credential = () => credentialFor({ given_name: 'Alice', family_name: 'Doe' });

    it('signs in a first-time user, enrolling the account and its binding together', async () => {
      const result = await resolveWalletPresentation(harness.fastify, inputFor(credential()));

      expect(result).toEqual({
        status: 'authenticated',
        userId: 'user-new',
        externalSub: 'alice@example.com',
      });

      const [written] = harness.userCredentials.create.mock.calls[0] as [Record<string, unknown>];
      expect(written['providerType']).toBe('wallet');
      expect(walletCredentialDataSchema.parse(written['credentialData']).wallet_binding).toMatch(
        /^wb1:/
      );
    });

    it('writes the claims as verified wallet attributes', async () => {
      await resolveWalletPresentation(
        harness.fastify,
        inputFor(credentialFor({ given_name: 'Alice', family_name: 'Doe', email: 'a@example.com' }))
      );

      expect(harness.userAttributes.upsertMany).toHaveBeenCalledWith(
        'user-new',
        expect.arrayContaining([
          {
            source: 'wallet',
            attrKey: 'email',
            attrValue: 'a@example.com',
            verified: true,
            expiresAt: null,
          },
        ]),
        'tx'
      );
    });

    it('refuses a credential from an issuer this realm does not trust (#236)', async () => {
      testEnv.OID4VP_TRUSTED_ISSUERS = { [REALM_NAME]: ['https://other-issuer.example'] };

      expect(await resolveWalletPresentation(harness.fastify, inputFor(credential()))).toEqual({
        status: 'rejected',
      });
      expect(harness.users.create).not.toHaveBeenCalled();
    });

    it('refuses when the realm has no allowlist at all — unconfigured trusts nobody', async () => {
      testEnv.OID4VP_TRUSTED_ISSUERS = undefined;

      expect(await resolveWalletPresentation(harness.fastify, inputFor(credential()))).toEqual({
        status: 'rejected',
      });
    });

    it('applies the allowlist of THIS realm, not of the deployment', async () => {
      harness.realms.findById.mockResolvedValue({ id: REALM_ID, name: 'acme' });

      expect(await resolveWalletPresentation(harness.fastify, inputFor(credential()))).toEqual({
        status: 'rejected',
      });
    });

    it('refuses when no VerifierProfile is selected (#296 fail-closed)', async () => {
      testEnv.OID4VP_VERIFIER_PROFILE = undefined;

      expect(await resolveWalletPresentation(harness.fastify, inputFor(credential()))).toEqual({
        status: 'rejected',
      });
    });

    it('refuses a credential in a format the active profile forbids', async () => {
      const mdoc = credentialFor(
        { given_name: 'Alice', family_name: 'Doe' },
        { format: 'mso_mdoc' }
      );

      expect(await resolveWalletPresentation(harness.fastify, inputFor(mdoc))).toEqual({
        status: 'rejected',
      });
    });

    it('refuses when the deployment configured no binding claims (ADR-009 §1 bypass)', async () => {
      // `asserted-lookup` with no entitlement check would authenticate anyone
      // holding any trusted credential. `resolveSubjectResolution` throws for it
      // and the seam turns that into the same refusal, logging the reason.
      testEnv.OID4VP_SUBJECT_BINDING_CLAIMS = undefined;

      expect(await resolveWalletPresentation(harness.fastify, inputFor(credential()))).toEqual({
        status: 'rejected',
      });
      expect(harness.users.create).not.toHaveBeenCalled();
    });

    it('does not silently enrol over a pre-existing account with no wallet binding (#238)', async () => {
      harness.userCredentials.findByRealmAndSub.mockResolvedValue([
        {
          id: 'cred-1',
          userId: 'user-1',
          realmId: REALM_ID,
          providerType: 'password',
          externalSub: 'alice@example.com',
          credentialData: { password_hash: 'x', email_verified: true },
          createdAt: 0,
          updatedAt: 0,
        },
      ]);

      expect(await resolveWalletPresentation(harness.fastify, inputFor(credential()))).toEqual({
        status: 'rejected',
      });
      expect(harness.userCredentials.create).not.toHaveBeenCalled();
    });

    it('renders every refusal identically, whatever the gate that failed', async () => {
      const untrusted = { ...testEnv };
      testEnv.OID4VP_TRUSTED_ISSUERS = { [REALM_NAME]: ['https://other-issuer.example'] };
      const byTrust = await resolveWalletPresentation(harness.fastify, inputFor(credential()));

      testEnv.OID4VP_TRUSTED_ISSUERS = untrusted.OID4VP_TRUSTED_ISSUERS;
      testEnv.OID4VP_VERIFIER_PROFILE = undefined;
      const byProfile = await resolveWalletPresentation(harness.fastify, inputFor(credential()));

      testEnv.OID4VP_VERIFIER_PROFILE = 'oid4vp-1.0-base';
      const byBinding = await resolveWalletPresentation(
        harness.fastify,
        inputFor(credentialFor({ given_name: 'Alice' }))
      );

      expect(byTrust).toEqual({ status: 'rejected' });
      expect(byProfile).toEqual(byTrust);
      expect(byBinding).toEqual(byTrust);
    });
  });
});
