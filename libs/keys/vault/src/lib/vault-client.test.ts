import { createManualClock } from '@qauth-labs/shared-testing';
import { describe, expect, it, vi } from 'vitest';

import { VaultHttpError, VaultTransportError } from './errors';
import type { VaultHttpRequest, VaultHttpResponse, VaultTransport } from './https-transport';
import { createVaultClient, VAULT_BACKOFF_MS, VAULT_MAX_ATTEMPTS } from './vault-client';

/** A transport that answers from a list, recording each request. */
function scripted(answers: Array<VaultHttpResponse | Error>) {
  const requests: VaultHttpRequest[] = [];
  const transport = vi.fn<VaultTransport>(async (request) => {
    requests.push(request);
    const answer = answers.shift() ?? { status: 200, body: {} };
    if (answer instanceof Error) throw answer;
    return answer;
  });
  return { transport, requests };
}

function nodeError(code: string): Error {
  return Object.assign(new Error(`${code} from the test`), { code });
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error('expected the call to fail');
    },
    (reason: unknown) => reason
  );
}

describe('the Vault client', () => {
  it('sends the token, the namespace and the request header, and the body as JSON', async () => {
    const { transport, requests } = scripted([{ status: 200, body: { data: {} } }]);
    const client = createVaultClient({ transport, namespace: 'org/team-a' });

    await client.send('encrypt', {
      method: 'POST',
      path: 'transit/encrypt/qauth-kek',
      token: 'hvs.token',
      body: { plaintext: 'AAAA', context: 'BBBB' },
    });

    expect(requests).toEqual([
      {
        method: 'POST',
        path: '/v1/transit/encrypt/qauth-kek',
        headers: {
          'X-Vault-Request': 'true',
          'X-Vault-Token': 'hvs.token',
          'X-Vault-Namespace': 'org/team-a',
        },
        body: '{"plaintext":"AAAA","context":"BBBB"}',
      },
    ]);
  });

  it('sends no token header for a login, and no namespace header in the root namespace', async () => {
    const { transport, requests } = scripted([]);

    await createVaultClient({ transport }).send('approle-login', {
      method: 'POST',
      path: 'auth/approle/login',
      body: { role_id: 'r', secret_id: 's' },
    });

    expect(requests[0].headers).toEqual({ 'X-Vault-Request': 'true' });
  });

  it.each([412, 429, 500, 502, 503, 504])(
    'retries %i up to the attempt limit, with exponential backoff',
    async (status) => {
      const clock = createManualClock(0);
      const { transport } = scripted(
        Array.from({ length: 5 }, () => ({ status, body: { errors: ['x'] } }))
      );
      const client = createVaultClient({ transport, clock, random: () => 1 });

      const call = failure(
        client.send('decrypt', { method: 'POST', path: 'transit/decrypt/k', token: 't' })
      );
      await clock.advanceBy(0);
      expect(transport).toHaveBeenCalledTimes(1);
      expect(clock.pending()).toEqual([VAULT_BACKOFF_MS]);
      await clock.advanceBy(VAULT_BACKOFF_MS);
      expect(transport).toHaveBeenCalledTimes(2);
      expect(clock.pending()).toEqual([3 * VAULT_BACKOFF_MS]);
      await clock.advanceBy(2 * VAULT_BACKOFF_MS);

      const error = await call;
      expect(transport).toHaveBeenCalledTimes(VAULT_MAX_ATTEMPTS);
      expect(error).toBeInstanceOf(VaultHttpError);
      expect(error).toMatchObject({ status, operation: 'decrypt', errors: ['x'] });
    }
  );

  it.each([301, 307, 400, 403, 404, 405, 501])('does not retry %i', async (status) => {
    const { transport } = scripted([{ status, body: { errors: ['refused'] } }]);

    const error = await failure(
      createVaultClient({ transport }).send('decrypt', { method: 'POST', path: 'p', token: 't' })
    );

    expect(transport).toHaveBeenCalledTimes(1);
    expect(error).toMatchObject({ name: 'VaultHttpError', status });
  });

  it('retries a refused connection, a reset and a timeout, then reports the transport failure', async () => {
    const clock = createManualClock(0);
    const { transport } = scripted([
      nodeError('ECONNREFUSED'),
      nodeError('ECONNRESET'),
      nodeError('ETIMEDOUT'),
    ]);
    const client = createVaultClient({ transport, clock });

    const call = failure(
      client.send('encrypt', { method: 'POST', path: 'p', token: 'hvs.secret' })
    );
    await clock.advanceBy(10_000);
    const error = await call;

    expect(transport).toHaveBeenCalledTimes(3);
    expect(error).toBeInstanceOf(VaultTransportError);
    expect(error).toMatchObject({ code: 'ETIMEDOUT', operation: 'encrypt' });
    expect((error as Error).message).toBe('Vault could not be reached for encrypt (ETIMEDOUT)');
  });

  it.each([
    ['a timeout', nodeError('ETIMEDOUT')],
    ['a reset connection', nodeError('ECONNRESET')],
    ['a server fault', { status: 500, body: undefined }],
    ['a precondition failure', { status: 412, body: undefined }],
  ])(
    'does not repeat an AppRole login after %s, since Vault may have served it',
    async (_what, answer) => {
      const { transport } = scripted([answer]);

      await failure(
        createVaultClient({ transport }).send('approle-login', {
          method: 'POST',
          path: 'auth/approle/login',
          body: { role_id: 'r', secret_id: 's' },
        })
      );

      expect(transport).toHaveBeenCalledTimes(1);
    }
  );

  it.each([
    ['a refused connection', nodeError('ECONNREFUSED')],
    ['a name that did not resolve', nodeError('EAI_AGAIN')],
    ['a sealed Vault', { status: 503, body: undefined }],
    ['throttling', { status: 429, body: undefined }],
  ])('repeats an AppRole login after %s, which Vault did not serve', async (_what, answer) => {
    const clock = createManualClock(0);
    const { transport } = scripted([answer]);
    const client = createVaultClient({ transport, clock });

    const call = client.send('approle-login', {
      method: 'POST',
      path: 'auth/approle/login',
      body: {},
    });
    await clock.advanceBy(10_000);

    expect(await call).toEqual({ status: 200, body: {} });
    expect(transport).toHaveBeenCalledTimes(2);
  });

  it('does not retry a TLS verification failure', async () => {
    const { transport } = scripted([nodeError('UNABLE_TO_VERIFY_LEAF_SIGNATURE')]);

    const error = await failure(
      createVaultClient({ transport }).send('encrypt', { method: 'POST', path: 'p', token: 't' })
    );

    expect(transport).toHaveBeenCalledTimes(1);
    expect(error).toMatchObject({ code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
  });

  it('succeeds when a retry is answered', async () => {
    const clock = createManualClock(0);
    const { transport } = scripted([
      { status: 503, body: undefined },
      nodeError('ECONNRESET'),
      { status: 204, body: undefined },
    ]);
    const client = createVaultClient({ transport, clock });

    const call = client.send('token-renew-self', { method: 'POST', path: 'p', token: 't' });
    await clock.advanceBy(10_000);

    expect(await call).toEqual({ status: 204, body: undefined });
  });

  it("keeps at most five of Vault's error messages, each cut short, with whitespace folded", async () => {
    const long = 'x'.repeat(500);
    const { transport } = scripted([
      {
        status: 400,
        body: {
          errors: ['1 error occurred:\n\t* permission denied\n\n', long, 1, 'c', 'd', 'e', 'f'],
        },
      },
    ]);

    const error = (await failure(
      createVaultClient({ transport }).send('decrypt', { method: 'POST', path: 'p', token: 't' })
    )) as VaultHttpError;

    expect(error.errors).toEqual([
      '1 error occurred: * permission denied',
      'x'.repeat(200),
      'c',
      'd',
      'e',
    ]);
  });
});
