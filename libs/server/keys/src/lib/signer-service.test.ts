import { createHmac } from 'node:crypto';

import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  createServiceSigner,
  SERVICE_ISSUER,
  SERVICE_NOW,
  SERVICE_PROVIDER,
  SERVICE_REALM,
  SERVICE_SUBSCRIPTION,
  type ServiceSigner,
} from '../testing/service-signer';
import { KekUnavailableError } from './errors';
import type { RealmJwks, Signer } from './signer';
import { SIGNER_CALLERS, type SignerCaller } from './signer-policy';
import { createSignerService, type SignerServiceAnswer } from './signer-service';
import { decodeWireBytes, encodeWireBytes } from './signer-wire';

/** A claim value no answer may carry back: it stands for every claim a caller sends. */
const MARKER = 'claim-value-4f1c9e';

const CLAIMS = Object.freeze({
  sub: 'user-1',
  aud: 'client-1',
  iat: SERVICE_NOW / 1000,
  exp: SERVICE_NOW / 1000 + 300,
});

function result(answer: SignerServiceAnswer): unknown {
  expect(answer.status).toBe(200);
  return (answer.body as { result: unknown }).result;
}

function wireError(answer: SignerServiceAnswer): Record<string, unknown> {
  return (answer.body as unknown as { error: Record<string, unknown> }).error;
}

describe('the signer service (#497)', () => {
  let setup: ServiceSigner;

  beforeAll(async () => {
    setup = await createServiceSigner();
  });

  it('signs an access token for the api role with the realm key, setting iss and kid itself', async () => {
    const service = createSignerService(setup.signer);
    const token = result(
      await service.call('api', 'signJws', {
        realmId: SERVICE_REALM,
        purpose: 'token_signing',
        typ: 'at+jwt',
        claims: CLAIMS,
      })
    ) as string;
    const jwks = (await setup.signer.getJwks('local', SERVICE_REALM)) as RealmJwks;
    const { payload } = await jwtVerify(token, createLocalJWKSet({ keys: [...jwks.keys] }), {
      issuer: SERVICE_ISSUER,
      currentDate: new Date(SERVICE_NOW),
    });
    expect(payload.sub).toBe('user-1');
    expect(decodeProtectedHeader(token).typ).toBe('at+jwt');
  });

  it('hands the web role the cookie secrets as bytes, and refuses them to api and delivery', async () => {
    const service = createSignerService(setup.signer);
    const answer = result(
      await service.call('web', 'getCookieSecrets', { realmId: SERVICE_REALM })
    ) as { current: { kid: string; bytes: string }; previous: unknown };
    const direct = await setup.signer.getCookieSecrets('local', SERVICE_REALM);
    expect(answer.current.kid).toBe(direct.current.kid);
    expect(decodeWireBytes({ bytes: answer.current.bytes })?.equals(direct.current.secret)).toBe(
      true
    );
    expect(answer.previous).toBeNull();

    for (const role of ['api', 'delivery'] as const) {
      const refused = await service.call(role, 'getCookieSecrets', { realmId: SERVICE_REALM });
      expect(refused.status, role).toBe(403);
      expect(wireError(refused)).toEqual({
        code: 'SIGNER_ACCESS_DENIED',
        caller: role,
        operation: 'getCookieSecrets',
      });
      expect(refused.refused).toEqual({ caller: role, operation: 'getCookieSecrets' });
    }
  });

  it('signs a webhook for the delivery role, from text or bytes alike, and refuses the web role', async () => {
    const service = createSignerService(setup.signer);
    const request = {
      realmId: SERVICE_REALM,
      subscriptionId: SERVICE_SUBSCRIPTION,
      id: 'evt_1',
      timestamp: SERVICE_NOW / 1000,
    };
    const body = '{"type":"user.created"}';
    const fromText = result(await service.call('delivery', 'signWebhook', { ...request, body }));
    const fromBytes = result(
      await service.call('delivery', 'signWebhook', {
        ...request,
        body: encodeWireBytes(Buffer.from(body)),
      })
    );
    const secret = Buffer.from(setup.webhookSecret.replace(/^whsec_/, ''), 'base64');
    const expected = createHmac('sha256', secret)
      .update(`evt_1.${request.timestamp}.${body}`)
      .digest('base64');
    expect(fromText).toBe(`v1,${expected}`);
    expect(fromBytes).toBe(fromText);

    const refused = await service.call('web', 'signWebhook', { ...request, body });
    expect(refused.status).toBe(403);
    expect(refused.refused).toEqual({ caller: 'web', operation: 'signWebhook' });
  });

  it('round-trips a plaintext through encrypt and decrypt as bytes', async () => {
    const service = createSignerService(setup.signer);
    const context = 'realm_secrets:mail.smtp.password';
    const ciphertext = result(
      await service.call('api', 'encrypt', {
        realmId: SERVICE_REALM,
        plaintext: encodeWireBytes(Buffer.from('s3cret')),
        context,
      })
    ) as string;
    const opened = result(
      await service.call('api', 'decrypt', { realmId: SERVICE_REALM, ciphertext, context })
    );
    expect(decodeWireBytes(opened)?.toString()).toBe('s3cret');
  });

  it('answers each public read and signing operation the role is granted', async () => {
    const service = createSignerService(setup.signer);
    expect(
      result(
        await service.call('api', 'getVerificationKeys', {
          realmId: SERVICE_REALM,
          purpose: 'token_signing',
        })
      )
    ).toEqual(await setup.signer.getVerificationKeys('local', SERVICE_REALM, 'token_signing'));
    expect(result(await service.call('admin', 'getJwks', { realmId: SERVICE_REALM }))).toEqual(
      await setup.signer.getJwks('local', SERVICE_REALM)
    );
    expect(
      result(
        await service.call('api', 'getUpstreamJwks', {
          realmId: SERVICE_REALM,
          providerId: SERVICE_PROVIDER,
        })
      )
    ).toEqual(await setup.signer.getUpstreamJwks('local', SERVICE_REALM, SERVICE_PROVIDER));
    const assertion = result(
      await service.call('api', 'signClientAssertion', {
        realmId: SERVICE_REALM,
        providerId: SERVICE_PROVIDER,
        audience: 'https://upstream.example.test',
        claims: { exp: SERVICE_NOW / 1000 + 60, jti: 'j-1' },
      })
    );
    expect(typeof assertion).toBe('string');
    const requestObject = result(
      await service.call('web', 'signRequestObject', {
        realmId: SERVICE_REALM,
        certificateChain: setup.verifierChain,
        claims: { client_id: 'x509_hash:abc', nonce: 'n-1' },
      })
    );
    expect(typeof requestObject).toBe('string');
  });

  it('never takes local, nor a role it does not know, from a peer', async () => {
    const service = createSignerService(setup.signer);
    for (const caller of ['local', 'signer', 'metrics', undefined, 'API']) {
      const answer = await service.call(caller, 'getJwks', { realmId: SERVICE_REALM });
      expect(answer.status, String(caller)).toBe(403);
      expect(wireError(answer)).toEqual({ code: 'SIGNER_ACCESS_DENIED', operation: 'getJwks' });
      expect(answer.refused).toEqual({ caller: 'unknown', operation: 'getJwks' });
    }
  });

  it('refuses a role with no grant for the operation before it reads the body', async () => {
    const service = createSignerService(setup.signer);
    // Not even an object: a role with a grant would get 400 for it.
    const answer = await service.call('admin', 'signJws', 'not an object');
    expect(answer.status).toBe(403);
    expect(answer.refused).toEqual({ caller: 'admin', operation: 'signJws' });
    expect((await service.call('api', 'signJws', 'not an object')).status).toBe(400);
    // The same refusal with no body at all, for a route to answer before it reads one.
    expect(service.precheck('admin', 'signJws')).toEqual(answer);
    expect(service.precheck('local', 'signJws')).toMatchObject({ status: 403 });
    expect(service.precheck('api', 'signJws')).toBeUndefined();
  });

  it("holds a role to its grant's token types and contexts, and counts each refusal", async () => {
    const service = createSignerService(setup.signer);
    const logout = await service.call('api', 'signJws', {
      realmId: SERVICE_REALM,
      purpose: 'token_signing',
      typ: 'logout+jwt',
      claims: CLAIMS,
    });
    expect(logout.status).toBe(403);
    expect(wireError(logout)).toMatchObject({
      code: 'SIGNER_ACCESS_DENIED',
      purpose: 'token_signing',
    });
    expect(logout.refused).toEqual({ caller: 'api', operation: 'signJws' });

    const decrypt = await service.call('delivery', 'decrypt', {
      realmId: SERVICE_REALM,
      ciphertext: 'v1.x.y.z',
      context: 'realm_secrets:mail.smtp.password',
    });
    expect(decrypt.status).toBe(403);
    expect(decrypt.refused).toEqual({ caller: 'delivery', operation: 'decrypt' });
  });

  it('answers a refused request with its reason alone', async () => {
    const service = createSignerService(setup.signer);
    const answer = await service.call('api', 'signJws', {
      realmId: SERVICE_REALM,
      purpose: 'token_signing',
      typ: 'at+jwt',
      kid: 'chosen-by-caller',
      claims: CLAIMS,
    });
    expect(answer.status).toBe(400);
    expect(answer.body).toEqual({
      error: { code: 'SIGNER_REQUEST_REFUSED', reason: 'UNEXPECTED_FIELD' },
    });
    expect(answer.refused).toBeUndefined();
    const named = await service.call('web', 'getCookieSecrets', {
      realmId: SERVICE_REALM,
      [MARKER]: 1,
    });
    expect(named.body).toEqual({
      error: { code: 'SIGNER_REQUEST_REFUSED', reason: 'UNEXPECTED_FIELD' },
    });
  });

  it('answers the signer key-custody trouble as unavailable, and any other fault without its message', async () => {
    const throwing = (error: Error): Signer =>
      ({ ...setup.signer, signJws: async () => Promise.reject(error) }) as Signer;
    const request = {
      realmId: SERVICE_REALM,
      purpose: 'token_signing',
      typ: 'at+jwt',
      claims: { ...CLAIMS, secret: MARKER },
    };
    const custody = await createSignerService(
      throwing(new KekUnavailableError({ cause: new Error(`the KEK service is down ${MARKER}`) }))
    ).call('api', 'signJws', request);
    expect(custody.status).toBe(503);
    expect(custody.body).toEqual({ error: { code: 'SIGNER_UNAVAILABLE' } });
    expect(custody.fault).toEqual({ name: 'KekUnavailableError', code: 'KEK_UNAVAILABLE' });

    const fault = await createSignerService(
      throwing(new TypeError(`Cannot read ${MARKER} of undefined`))
    ).call('api', 'signJws', request);
    expect(fault.status).toBe(500);
    expect(fault.body).toEqual({ error: { code: 'SIGNER_FAULT' } });
    expect(JSON.stringify(fault)).not.toContain(MARKER);
    expect(JSON.stringify(custody)).not.toContain(MARKER);
  });

  describe('error bodies', () => {
    /** Requests that each fail, every one carrying the marker as a claim or a value. */
    const failing: ReadonlyArray<readonly [SignerCaller, string, Record<string, unknown>]> = [
      [
        'api',
        'signJws',
        {
          realmId: SERVICE_REALM,
          purpose: 'token_signing',
          typ: 'at+jwt',
          claims: { iss: MARKER },
        },
      ],
      [
        'api',
        'signJws',
        { realmId: SERVICE_REALM, purpose: 'token_signing', typ: MARKER, claims: CLAIMS },
      ],
      [
        'api',
        'signJws',
        { realmId: MARKER, purpose: 'token_signing', typ: 'at+jwt', claims: CLAIMS },
      ],
      [
        'api',
        'signJws',
        { realmId: SERVICE_REALM, purpose: MARKER, typ: 'at+jwt', claims: CLAIMS },
      ],
      [
        'api',
        'signJws',
        {
          realmId: SERVICE_REALM,
          purpose: 'token_signing',
          typ: 'at+jwt',
          algorithm: MARKER,
          claims: CLAIMS,
        },
      ],
      [
        'api',
        'signJws',
        {
          realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eff',
          purpose: 'token_signing',
          typ: 'at+jwt',
          claims: { secret: MARKER },
        },
      ],
      [
        'api',
        'signJws',
        {
          realmId: SERVICE_REALM,
          purpose: 'token_signing',
          typ: 'logout+jwt',
          claims: { secret: MARKER },
        },
      ],
      [
        'delivery',
        'signJws',
        {
          realmId: SERVICE_REALM,
          purpose: 'event_signing',
          typ: 'secevent+jwt',
          claims: { secret: MARKER },
        },
      ],
      ['api', 'signHybrid', { realmId: SERVICE_REALM, typ: 'at+jwt', claims: { secret: MARKER } }],
      [
        'api',
        'signClientAssertion',
        {
          realmId: SERVICE_REALM,
          providerId: SERVICE_PROVIDER,
          audience: MARKER,
          claims: { secret: MARKER },
        },
      ],
      [
        'api',
        'signClientAssertion',
        {
          realmId: SERVICE_REALM,
          providerId: MARKER,
          audience: 'https://u.example',
          claims: { exp: 1, jti: MARKER },
        },
      ],
      [
        'delivery',
        'signWebhook',
        {
          realmId: SERVICE_REALM,
          subscriptionId: SERVICE_SUBSCRIPTION,
          id: `${MARKER}.x`,
          timestamp: 1,
          body: MARKER,
        },
      ],
      [
        'delivery',
        'signWebhook',
        { realmId: SERVICE_REALM, subscriptionId: MARKER, id: 'evt', timestamp: 1, body: MARKER },
      ],
      [
        'web',
        'signRequestObject',
        { realmId: SERVICE_REALM, certificateChain: [MARKER], claims: { client_id: MARKER } },
      ],
      [
        'api',
        'encrypt',
        { realmId: SERVICE_REALM, plaintext: MARKER, context: 'realm_secrets:mail.x' },
      ],
      [
        'web',
        'encrypt',
        {
          realmId: SERVICE_REALM,
          plaintext: encodeWireBytes(Buffer.from(MARKER)),
          context: MARKER,
        },
      ],
      [
        'api',
        'decrypt',
        { realmId: SERVICE_REALM, ciphertext: MARKER, context: 'realm_secrets:mail.x' },
      ],
      [
        'api',
        'decrypt',
        {
          realmId: SERVICE_REALM,
          ciphertext: `v1.${MARKER}.AAAA.AAAA`,
          context: 'realm_secrets:mail.x',
        },
      ],
      [
        'web',
        'getCookieSecrets',
        { realmId: SERVICE_REALM, options: { kid: 7, [MARKER]: MARKER } },
      ],
      ['api', 'getUpstreamJwks', { realmId: SERVICE_REALM, providerId: `${MARKER}\u0000` }],
      ['api', 'getVerificationKeys', { realmId: SERVICE_REALM, purpose: MARKER }],
    ];

    it.each(failing)(
      '%s %s answers no claim value and no key byte',
      async (caller, operation, body) => {
        const service = createSignerService(setup.signer);
        const answer = await service.call(caller, operation as never, body);
        expect(answer.status).toBeGreaterThanOrEqual(400);
        const text = JSON.stringify(answer);
        expect(text).not.toContain(MARKER);
        expect(text).not.toContain(setup.webhookSecret);
        const cookie = await setup.signer.getCookieSecrets('local', SERVICE_REALM);
        expect(text).not.toContain(cookie.current.secret.toString('base64url'));
        expect(
          Object.keys(wireError(answer)).every((key) =>
            ['code', 'reason', 'caller', 'operation', 'purpose', 'algorithm', 'kid'].includes(key)
          )
        ).toBe(true);
      }
    );
  });

  it('serves every role of the policy table and no other', () => {
    expect([...SIGNER_CALLERS].sort()).toEqual(['admin', 'api', 'delivery', 'local', 'web']);
  });
});
