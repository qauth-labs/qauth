import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import { decodeProtectedHeader, importSPKI, jwtVerify } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { createMockVerifierPki, verifierIdentityEnvironment } from '../testing/mock-verifier-pki';

/**
 * THE TWO KEY SETS MUST NOT BE INTERCHANGEABLE (#298's risk note, #377 Phase A).
 *
 * QAuth now holds two kinds of private key at once, and they answer different
 * questions to different audiences:
 *
 * | key | proves | published at |
 * | --- | --- | --- |
 * | the realm's `token_signing` keys (EdDSA, + RS256) | "QAuth issued this token" | `GET /.well-known/jwks.json` |
 * | `OID4VP_VERIFIER_SIGNING_KEY` | "QAuth is the Verifier in this request" | nowhere |
 *
 * A leak in either direction is a real vulnerability rather than an untidiness.
 * The verifier key appearing in the JWKS would invite a relying party to accept
 * an access token signed by it — a key whose only purpose is to identify QAuth
 * to a WALLET, held for the lifetime of an operator's certificate rather than
 * rotated with the token keys. A token key reaching the request-signing path
 * would put QAuth's issuance identity into an artifact every wallet in an
 * ecosystem receives.
 *
 * ## Why this suite provisions the verifier key
 *
 * The vacuity trap, stated plainly: a test that only inspects the DEFAULT JWKS
 * passes today for the wrong reason — a deployment with no P-256 key has none to
 * leak. So every deployment booted here HAS one, and the assertions are about
 * what the running server does with it.
 *
 * ## Containers
 *
 * The token keys live in the realm's encrypted key store and every token is
 * signed through the signer (#491), so the published set and the signatures
 * are the store's: each deployment here boots against a real Postgres, imports
 * its key variables into the store, and is asked what it publishes and signs.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const pki = createMockVerifierPki();

let infra: E2eInfrastructure | undefined;
let dockerUp = false;

beforeAll(async () => {
  dockerUp = await requireDockerOrSkip();
  if (!dockerUp) return;
  infra = await startE2eInfrastructure();
}, 240_000);

afterAll(async () => {
  await infra?.teardown();
});

beforeEach(async (ctx) => {
  if (!dockerUp || !infra) {
    ctx.skip();
  }
});

/** The variables of a deployment that provisions BOTH key sets. */
async function verifierDeploymentEnvironment(): Promise<Record<string, string>> {
  if (!infra) throw new Error('no infrastructure');
  return {
    ...baseEnvironment(infra, await generateJwtPem()),
    WALLET_FEDERATION_ENABLED: 'true',
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
    OID4VP_REQUESTED_VCT: 'https://credentials.example.com/pid',
    // Subject resolution, stated because #379 made it a BOOT gate: an enabled
    // deployment that names no binding claims refuses to start (ADR-010 §6).
    // Irrelevant to what this suite asserts — no request here reaches a
    // presentation — but the boot has to succeed before anything can be
    // asserted about the key sets it produced.
    OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup',
    OID4VP_SUBJECT_BINDING_CLAIMS: 'family_name,given_name,birth_date',
    ...verifierIdentityEnvironment(pki),
  };
}

/** A deployment that provisions BOTH key sets, on an empty database. */
async function bootWithVerifierIdentity(
  overrides: Record<string, string> = {}
): Promise<BootedAuthServer & { readonly realm: { readonly id: string } }> {
  // A throwaway server only to empty the database: each boot imports afresh.
  const base = await verifierDeploymentEnvironment();
  const environment = { ...base, ...overrides };
  const cleaner = await bootAuthServer(base);
  await cleaner.app.dbPool.query(truncateDomainTablesStatement());
  await cleaner.close();

  const server = await bootAuthServer(environment);
  const realm = await server.app.repositories.realms.findByName(E2E_REALM_NAME);
  if (realm === undefined) throw new Error('default realm missing');
  return { ...server, realm: { id: realm.id } };
}

/**
 * The published set is read from `jwtUtils.getJwks(realm)` rather than over
 * HTTP.
 *
 * `GET /.well-known/jwks.json` sends that value VERBATIM — the route adds two
 * headers and nothing else, and `routes/well-known.test.ts` already pins the
 * pass-through against a stubbed `jwtUtils`. What that stub cannot check is what
 * the REAL bootstrap puts in the set, which is the question here.
 */
describe('the verifier key never reaches the published JWKS (#377)', () => {
  it('publishes no EC key at all, on a deployment that HAS one', async () => {
    const server = await bootWithVerifierIdentity();

    try {
      const { keys } = await server.app.jwtUtils.getJwks(server.realm);

      expect(keys.length).toBeGreaterThan(0);

      for (const key of keys as unknown as Array<Record<string, unknown>>) {
        expect(key['kty']).not.toBe('EC');
        expect(key['crv']).not.toBe('P-256');
        expect(key['alg']).not.toBe('ES256');
      }
    } finally {
      await server.close();
    }
  });

  it("publishes nothing matching the verifier leaf's own public coordinates", async () => {
    // The strongest form of the assertion: not "no EC key" by shape, but "not
    // THIS key" by value. A future entry that carried the verifier key under a
    // mislabelled `kty` would still fail here.
    const server = await bootWithVerifierIdentity();

    try {
      const jwk = pki.leaf.publicKey.export({ format: 'jwk' }) as { x?: string; y?: string };
      const published = JSON.stringify(await server.app.jwtUtils.getJwks(server.realm));

      expect(jwk.x).toBeDefined();
      expect(published).not.toContain(jwk.x as string);
      expect(published).not.toContain(jwk.y as string);
    } finally {
      await server.close();
    }
  });

  it('publishes only the EdDSA token key it was configured with', async () => {
    // The control that makes the two assertions above non-vacuous in the other
    // direction: the set is not empty and not accidentally filtered — it holds
    // exactly the key type QAuth signs its own tokens with.
    const server = await bootWithVerifierIdentity();

    try {
      const { keys } = await server.app.jwtUtils.getJwks(server.realm);

      expect((keys as unknown as Array<Record<string, unknown>>).map((key) => key['kty'])).toEqual([
        'OKP',
      ]);
    } finally {
      await server.close();
    }
  });
});

describe('the verifier key cannot sign a QAuth access or ID token (#377)', () => {
  it('signs access and ID tokens with EdDSA, not ES256, and they do NOT verify under the verifier key', async () => {
    // What "cannot sign" means on the wire: a token the verifier key had
    // produced would verify under it. Neither of these does.
    const server = await bootWithVerifierIdentity();

    try {
      const verifierKey = await importSPKI(
        pki.leaf.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        'ES256'
      );

      const accessToken = await server.app.jwtUtils.signAccessToken(server.realm, {
        sub: 'user-1',
        clientId: 'client-1',
        scope: 'openid',
      });
      const idToken = await server.app.jwtUtils.signIdToken(server.realm, {
        sub: 'user-1',
        audience: 'client-1',
      });

      expect(decodeProtectedHeader(accessToken).alg).toBe('EdDSA');
      expect(decodeProtectedHeader(idToken).alg).toBe('EdDSA');
      await expect(jwtVerify(accessToken, verifierKey)).rejects.toThrow();
      await expect(jwtVerify(idToken, verifierKey)).rejects.toThrow();
    } finally {
      await server.close();
    }
  });
});

describe('the token keys refuse the verifier key at ADMISSION (#377, #491)', () => {
  it('will not import a P-256 PEM as the token-signing key', async () => {
    // The structural half of the guarantee, and the one that holds even if an
    // operator wired the wrong variable through: the key boot step imports a
    // token key only under its pinned algorithm, so a P-256 key cannot become
    // a token signer by configuration mistake. The JWT plugin itself takes no
    // key at all.
    await expect(
      bootWithVerifierIdentity({ JWT_PRIVATE_KEY: pki.signingKeyPem, JWT_PUBLIC_KEY: '' })
    ).rejects.toThrow(/JWT_PRIVATE_KEY/);
  });

  it('imports an Ed25519 key in the same slot — the refusal is about the key type', async () => {
    // The control. Without it the test above would pass for any boot failure
    // at all.
    const server = await bootWithVerifierIdentity();
    await server.close();
  });
});
