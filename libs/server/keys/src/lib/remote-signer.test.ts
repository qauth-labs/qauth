import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { beforeAll, describe, expect, it, vi } from 'vitest';

import {
  createServiceSigner,
  SERVICE_ISSUER,
  SERVICE_NOW,
  SERVICE_PROVIDER,
  SERVICE_REALM,
  SERVICE_SUBSCRIPTION,
  type ServiceSigner,
} from '../testing/service-signer';
import {
  createRemoteSigner,
  IDEMPOTENT_SIGNER_OPERATIONS,
  type RemoteSignerEvent,
  type RemoteSignerOptions,
  type SignerTransport,
  type SignerTransportRequest,
  type SignerTransportResponse,
} from './remote-signer';
import { type Signer, SIGNER_OPERATIONS, type SignerOperation } from './signer';
import { isSignerError, SignerAccessDeniedError, SignerRequestRefusedError } from './signer-errors';
import type { SignerCaller } from './signer-policy';
import { createSignerService } from './signer-service';
import { SIGNER_SERVICE_PATH, SIGNER_SERVICE_ROUTES } from './signer-wire';

const MARKER = 'claim-value-c03e55';

const CLAIMS = Object.freeze({
  sub: 'user-1',
  aud: 'client-1',
  iat: SERVICE_NOW / 1000,
  exp: SERVICE_NOW / 1000 + 300,
});

const ACCESS_TOKEN = Object.freeze({
  realmId: SERVICE_REALM,
  purpose: 'token_signing',
  typ: 'at+jwt',
  claims: CLAIMS,
} as const);

function operationOf(path: string): SignerOperation {
  const route = path.slice(SIGNER_SERVICE_PATH.length);
  const operation = SIGNER_OPERATIONS.find((name) => SIGNER_SERVICE_ROUTES[name] === route);
  if (operation === undefined || !path.startsWith(SIGNER_SERVICE_PATH)) {
    throw new Error(`no route ${path}`);
  }
  return operation;
}

function answer(status: number, body: unknown): SignerTransportResponse {
  return { status, body: Buffer.from(JSON.stringify(body)) };
}

/** A transport straight into the signer service, as a peer of `role`. */
function loopback(
  signer: Signer,
  role: string
): SignerTransport & { readonly calls: SignerTransportRequest[] } {
  const service = createSignerService(signer);
  const calls: SignerTransportRequest[] = [];
  return {
    calls,
    async send(request) {
      calls.push(request);
      const reply = await service.call(role, operationOf(request.path), JSON.parse(request.body));
      return answer(reply.status, reply.body);
    },
  };
}

/** A transport whose every call answers with `respond`. */
function scripted(
  respond: (request: SignerTransportRequest, index: number) => Promise<SignerTransportResponse>
): SignerTransport & { readonly calls: SignerTransportRequest[] } {
  const calls: SignerTransportRequest[] = [];
  return {
    calls,
    send(request) {
      calls.push(request);
      return respond(request, calls.length - 1);
    },
  };
}

const unreachable = () =>
  Promise.reject(Object.assign(new Error('connect ECONNREFUSED'), { code: 'unreachable' }));

async function caught(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected the call to fail');
}

describe('the remote signer (#497)', () => {
  let setup: ServiceSigner;

  beforeAll(async () => {
    setup = await createServiceSigner();
  });

  function remote(transport: SignerTransport, options: Partial<RemoteSignerOptions> = {}): Signer {
    return createRemoteSigner({
      transport,
      publishedKeys: setup.publishedKeys,
      retryDelayMs: 0,
      ...options,
    });
  }

  describe('over the signer service', () => {
    it('signs an access token that verifies against the realm JWKS', async () => {
      const signer = remote(loopback(setup.signer, 'api'));
      const token = await signer.signJws('local', ACCESS_TOKEN);
      const jwks = await signer.getJwks('api', SERVICE_REALM);
      const { payload } = await jwtVerify(token, createLocalJWKSet({ keys: [...jwks.keys] }), {
        issuer: SERVICE_ISSUER,
        currentDate: new Date(SERVICE_NOW),
      });
      expect(payload.sub).toBe('user-1');
    });

    it('answers every operation as the in-process signer does for the same role', async () => {
      const cases: ReadonlyArray<
        readonly [SignerCaller, (s: Signer, c: SignerCaller) => Promise<unknown>]
      > = [
        ['web', (s, c) => s.getCookieSecrets(c, SERVICE_REALM)],
        [
          'delivery',
          (s, c) =>
            s.signWebhook(c, {
              realmId: SERVICE_REALM,
              subscriptionId: SERVICE_SUBSCRIPTION,
              id: 'evt_1',
              timestamp: 1,
              body: Buffer.from('{"a":1}'),
            }),
        ],
        [
          'api',
          (s, c) =>
            s.signClientAssertion(c, {
              realmId: SERVICE_REALM,
              providerId: SERVICE_PROVIDER,
              audience: 'https://upstream.example.test',
              claims: { exp: SERVICE_NOW / 1000 + 60, jti: 'j-1' },
            }),
        ],
        ['api', (s, c) => s.getUpstreamJwks(c, SERVICE_REALM, SERVICE_PROVIDER)],
        ['api', (s, c) => s.getVerificationKeys(c, SERVICE_REALM, 'token_signing')],
        ['admin', (s, c) => s.getJwks(c, SERVICE_REALM, 'event_signing')],
      ];
      for (const [role, run] of cases) {
        expect(await run(remote(loopback(setup.signer, role)), role)).toEqual(
          await run(setup.signer, role)
        );
      }
    });

    it('round-trips a plaintext through encrypt and decrypt', async () => {
      const signer = remote(loopback(setup.signer, 'api'));
      const context = 'realm_secrets:mail.smtp.password';
      const ciphertext = await signer.encrypt('api', {
        realmId: SERVICE_REALM,
        plaintext: Buffer.from('s3cret'),
        context,
      });
      expect(
        (await signer.decrypt('api', { realmId: SERVICE_REALM, ciphertext, context })).toString()
      ).toBe('s3cret');
      // The in-process signer opens what the remote one sealed.
      expect(
        (
          await setup.signer.decrypt('api', { realmId: SERVICE_REALM, ciphertext, context })
        ).toString()
      ).toBe('s3cret');
    });

    it("holds the call to the role of the process's certificate, whatever the caller names", async () => {
      const signer = remote(loopback(setup.signer, 'api'));
      const refused = await caught(signer.getCookieSecrets('local', SERVICE_REALM));
      expect(refused).toBeInstanceOf(SignerAccessDeniedError);
      expect(refused).toMatchObject({ caller: 'api', operation: 'getCookieSecrets' });
    });

    it('refuses a call the named caller may not make before anything is sent', async () => {
      const transport = loopback(setup.signer, 'web');
      const signer = remote(transport);
      expect(await caught(signer.getCookieSecrets('api', SERVICE_REALM))).toBeInstanceOf(
        SignerAccessDeniedError
      );
      expect(
        await caught(signer.signJws('api', { ...ACCESS_TOKEN, typ: 'logout+jwt' }))
      ).toMatchObject({ code: 'SIGNER_ACCESS_DENIED', caller: 'api', purpose: 'token_signing' });
      expect(
        await caught(
          signer.decrypt('delivery', {
            realmId: SERVICE_REALM,
            ciphertext: 'x',
            context: 'realm_secrets:mail.x',
          })
        )
      ).toBeInstanceOf(SignerAccessDeniedError);
      expect(transport.calls).toEqual([]);
    });

    it("rebuilds the signer's refusals as its own errors, with no claim value in them", async () => {
      const signer = remote(loopback(setup.signer, 'api'));
      const refused = await caught(
        signer.signJws('local', { ...ACCESS_TOKEN, claims: { ...CLAIMS, iss: MARKER } })
      );
      expect(refused).toBeInstanceOf(SignerRequestRefusedError);
      expect((refused as SignerRequestRefusedError).reason).toBe('RESERVED_CLAIM');
      expect(JSON.stringify(refused)).not.toContain(MARKER);
      expect((refused as Error).message).not.toContain(MARKER);
      const missing = await caught(
        signer.signJws('local', {
          ...ACCESS_TOKEN,
          realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eff',
          claims: { secret: MARKER },
        })
      );
      expect(isSignerError(missing, 'SIGNER_ISSUER_NOT_FOUND')).toBe(true);
      expect((missing as Error).message).not.toContain(MARKER);
    });

    it('reads the JWKS and the verification keys from the published keys, never the signer', async () => {
      const transport = scripted(unreachable);
      const signer = remote(transport);
      expect(await signer.getJwks('api', SERVICE_REALM)).toEqual(
        await setup.signer.getJwks('local', SERVICE_REALM)
      );
      expect(await signer.getVerificationKeys('api', SERVICE_REALM, 'token_signing')).toEqual(
        await setup.signer.getVerificationKeys('local', SERVICE_REALM, 'token_signing')
      );
      expect(transport.calls).toEqual([]);
    });

    it('keeps an upstream JWKS for its cache interval', async () => {
      let clock = SERVICE_NOW;
      const transport = loopback(setup.signer, 'api');
      const signer = remote(transport, { now: () => clock });
      const first = await signer.getUpstreamJwks('api', SERVICE_REALM, SERVICE_PROVIDER);
      clock += 59_000;
      expect(await signer.getUpstreamJwks('api', SERVICE_REALM, SERVICE_PROVIDER)).toBe(first);
      expect(transport.calls).toHaveLength(1);
      clock += 2_000;
      await signer.getUpstreamJwks('api', SERVICE_REALM, SERVICE_PROVIDER);
      expect(transport.calls).toHaveLength(2);
    });

    it('sends no claim in the path, and the body as JSON', async () => {
      const transport = loopback(setup.signer, 'api');
      await remote(transport).signJws('local', ACCESS_TOKEN);
      expect(transport.calls[0]?.path).toBe('/internal/signer/v1-rc.0/sign-jws');
      expect(JSON.parse(transport.calls[0]?.body ?? '')).toEqual(ACCESS_TOKEN);
    });
  });

  describe('when the signer does not answer', () => {
    it('fails closed with 503, and tries an idempotent call once more', async () => {
      const events: RemoteSignerEvent[] = [];
      const transport = scripted(unreachable);
      const signer = remote(transport, { onEvent: (event) => events.push(event) });
      const signing = await caught(
        signer.signJws('local', { ...ACCESS_TOKEN, claims: { secret: MARKER } })
      );
      expect(signing).toBeInstanceOf(TemporarilyUnavailableError);
      expect(signing).toMatchObject({
        statusCode: 503,
        details: { reason: 'signer_unreachable', operation: 'signJws' },
      });
      expect(transport.calls).toHaveLength(1);
      await caught(signer.getCookieSecrets('web', SERVICE_REALM));
      expect(transport.calls).toHaveLength(3);
      expect(events).toContainEqual({
        type: 'call_failed',
        operation: 'signJws',
        reason: 'unreachable',
        code: 'unreachable',
      });
      expect(JSON.stringify(events)).not.toContain(MARKER);
      expect(JSON.stringify(signing)).not.toContain(MARKER);
    });

    it('gives up an attempt at its deadline', async () => {
      const transport = scripted(
        (request) =>
          new Promise((_resolve, reject) => {
            request.signal.addEventListener('abort', () =>
              reject(Object.assign(new Error('aborted'), { code: 'aborted' }))
            );
          })
      );
      const started = Date.now();
      const error = await caught(
        remote(transport, { attemptTimeoutMs: 30 }).signJws('local', ACCESS_TOKEN)
      );
      expect(error).toBeInstanceOf(TemporarilyUnavailableError);
      expect(Date.now() - started).toBeLessThan(2_000);
    });

    it('counts an error answer of the signer itself as an outage, and a refusal as an answer', async () => {
      const failing = scripted(async () => answer(503, { error: { code: 'SIGNER_UNAVAILABLE' } }));
      expect(await caught(remote(failing).signJws('local', ACCESS_TOKEN))).toMatchObject({
        details: { reason: 'signer_signer_failed' },
      });
      const malformed = scripted(async () =>
        answer(200, { result: { keys: [{ kty: 'OKP', d: 'x' }] } })
      );
      expect(
        await caught(remote(malformed).getUpstreamJwks('api', SERVICE_REALM, SERVICE_PROVIDER))
      ).toMatchObject({ details: { reason: 'signer_malformed_answer' } });
      const notFound = scripted(async () => answer(404, { code: 'not_found' }));
      expect(await caught(remote(notFound).signJws('local', ACCESS_TOKEN))).toBeInstanceOf(
        TemporarilyUnavailableError
      );
    });

    it("sends a call again once when the signer's listener refused it before it ran", async () => {
      const service = loopback(setup.signer, 'api');
      const transport = scripted(async (request, index) =>
        index === 0 ? answer(403, { code: 'forbidden' }) : service.send(request)
      );
      const token = await remote(transport).signJws('local', ACCESS_TOKEN);
      expect(typeof token).toBe('string');
      expect(transport.calls).toHaveLength(2);

      const refusing = scripted(async () => answer(403, { code: 'forbidden' }));
      expect(await caught(remote(refusing).signJws('local', ACCESS_TOKEN))).toMatchObject({
        details: { reason: 'signer_peer_refused' },
      });
      expect(refusing.calls).toHaveLength(2);
    });

    it('answers 503 to a rate-limited call without opening the circuit', async () => {
      const transport = scripted(async () => answer(429, { code: 'too_many_requests' }));
      const signer = remote(transport, { failureThreshold: 1 });
      for (let index = 0; index < 3; index += 1) {
        expect(await caught(signer.signJws('local', ACCESS_TOKEN))).toMatchObject({
          details: { reason: 'signer_rate_limited' },
        });
      }
      expect(transport.calls).toHaveLength(3);
    });
  });

  describe('the circuit breaker', () => {
    it('opens after repeated outages, probes once the interval ends, and closes on an answer', async () => {
      let clock = SERVICE_NOW;
      let up = false;
      const events: RemoteSignerEvent[] = [];
      const service = loopback(setup.signer, 'api');
      const transport = scripted((request) => (up ? service.send(request) : unreachable()));
      const signer = remote(transport, {
        now: () => clock,
        failureThreshold: 3,
        openMs: 5_000,
        onEvent: (event) => events.push(event),
      });

      for (let index = 0; index < 3; index += 1)
        await caught(signer.signJws('local', ACCESS_TOKEN));
      expect(events).toContainEqual({ type: 'circuit_opened', failures: 3, openMs: 5_000 });
      expect(transport.calls).toHaveLength(3);

      // Open: calls fail at once, with how long to wait.
      const fast = await caught(signer.signJws('local', ACCESS_TOKEN));
      expect(fast).toMatchObject({
        details: { reason: 'signer_circuit_open' },
        retryAfterSeconds: 5,
      });
      expect(transport.calls).toHaveLength(3);

      // The interval ends while the signer is still down: the probe fails and it opens again.
      clock += 5_000;
      await caught(signer.signJws('local', ACCESS_TOKEN));
      expect(transport.calls).toHaveLength(4);
      expect(await caught(signer.signJws('local', ACCESS_TOKEN))).toMatchObject({
        details: { reason: 'signer_circuit_open' },
      });

      // The signer is back: the next probe gets its answer, and calls flow again.
      up = true;
      clock += 5_000;
      expect(typeof (await signer.signJws('local', ACCESS_TOKEN))).toBe('string');
      expect(events.at(-1)).toEqual({ type: 'circuit_closed' });
      expect(typeof (await signer.signJws('local', ACCESS_TOKEN))).toBe('string');
    });

    it('lets one probe out at a time', async () => {
      let clock = SERVICE_NOW;
      let release: (() => void) | undefined;
      const service = loopback(setup.signer, 'api');
      let up = false;
      const transport = scripted(async (request) => {
        if (!up) return unreachable();
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        return service.send(request);
      });
      const signer = remote(transport, { now: () => clock, failureThreshold: 1, openMs: 1_000 });
      await caught(signer.signJws('local', ACCESS_TOKEN));
      up = true;
      clock += 1_000;
      const probe = signer.signJws('local', ACCESS_TOKEN);
      expect(await caught(signer.signJws('local', ACCESS_TOKEN))).toMatchObject({
        details: { reason: 'signer_circuit_open' },
      });
      await vi.waitFor(() => expect(release).toBeDefined());
      release?.();
      expect(typeof (await probe)).toBe('string');
    });

    it('counts a refusal of the request as an answer: the signer is up', async () => {
      const transport = scripted(async () =>
        answer(400, { error: { code: 'SIGNER_REQUEST_REFUSED', reason: 'UNEXPECTED_FIELD' } })
      );
      const signer = remote(transport, { failureThreshold: 1 });
      for (let index = 0; index < 3; index += 1) {
        expect(await caught(signer.signJws('local', ACCESS_TOKEN))).toBeInstanceOf(
          SignerRequestRefusedError
        );
      }
      expect(transport.calls).toHaveLength(3);
    });
  });

  it('retries only operations whose repeat changes nothing', () => {
    expect([...IDEMPOTENT_SIGNER_OPERATIONS].sort()).toEqual(
      ['decrypt', 'getCookieSecrets', 'getJwks', 'getUpstreamJwks', 'getVerificationKeys'].sort()
    );
  });
});
