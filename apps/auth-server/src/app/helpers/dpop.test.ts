import { DpopProofError } from '@qauth-labs/fastify-plugin-dpop';
import { InvalidDpopProofError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

// `user-events` reads the parsed environment at import; none of it is used here.
vi.mock('../../config/env', () => ({ env: {} }));

import {
  dpopEventReason,
  readAuthorizationDpopJkt,
  verifyResourceRequestProof,
  verifyTokenRequestProof,
} from './dpop';
import { failureData } from './user-events';

/** DPoP-bound tokens (RFC 9449, #480): the app's side of the shared verifier. */

const JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';

function fastifyWith(verifyRequest?: (...args: unknown[]) => Promise<unknown>): FastifyInstance {
  return {
    dpop: verifyRequest === undefined ? null : { algorithms: ['ES256'], verifyRequest },
  } as unknown as FastifyInstance;
}

function requestWith(headers: Record<string, string> = {}): FastifyRequest {
  return { headers, log: { warn: vi.fn() } } as unknown as FastifyRequest;
}

describe('dpopEventReason', () => {
  it('prefixes the verifier reason and turns it into snake_case', () => {
    expect(dpopEventReason('missing-proof')).toBe('dpop_missing_proof');
    expect(dpopEventReason('replay-store-unavailable')).toBe('dpop_replay_store_unavailable');
    expect(dpopEventReason('htu')).toBe('dpop_htu');
  });
});

describe('verifyTokenRequestProof (RFC 9449 §5)', () => {
  it('reads no header while DPoP is off, even for a DPoP-bound client', async () => {
    await expect(
      verifyTokenRequestProof(fastifyWith(), requestWith({ dpop: 'x' }), {
        dpopBoundAccessTokens: true,
      })
    ).resolves.toBeUndefined();
  });

  it('checks nothing when the request has no proof and the client is not DPoP-bound', async () => {
    const verifyRequest = vi.fn();
    await expect(
      verifyTokenRequestProof(fastifyWith(verifyRequest), requestWith(), {})
    ).resolves.toBeUndefined();
    expect(verifyRequest).not.toHaveBeenCalled();
  });

  it('checks a proof the request carries and returns its key thumbprint', async () => {
    const verifyRequest = vi.fn(async () => ({ thumbprint: JKT }));
    const request = requestWith({ dpop: 'proof' });
    await expect(verifyTokenRequestProof(fastifyWith(verifyRequest), request, {})).resolves.toBe(
      JKT
    );
    // No access token and no expected key at the token endpoint.
    expect(verifyRequest).toHaveBeenCalledWith(request);
  });

  it('requires a proof from a DPoP-bound client: the verifier refuses the missing one', async () => {
    const verifyRequest = vi.fn(async () => {
      throw new DpopProofError('missing-proof');
    });
    await expect(
      verifyTokenRequestProof(fastifyWith(verifyRequest), requestWith(), {
        dpopBoundAccessTokens: true,
      })
    ).rejects.toMatchObject({ reason: 'missing-proof' });
    expect(verifyRequest).toHaveBeenCalledTimes(1);
  });
});

describe('verifyResourceRequestProof (RFC 9449 §7.1)', () => {
  const claims = { sub: 'user-1', clientId: 'client-1', cnf: { jkt: JKT } };

  it('checks the proof against the token hash and the bound key', async () => {
    const verifyRequest = vi.fn(async () => ({ thumbprint: JKT }));
    const request = requestWith();
    await verifyResourceRequestProof(fastifyWith(verifyRequest), request, 'the.token', claims);
    expect(verifyRequest).toHaveBeenCalledWith(request, {
      accessToken: 'the.token',
      expectedThumbprint: JKT,
    });
  });

  it('answers a refused proof with a 401 invalid_dpop_proof, its reason kept for the event', async () => {
    const fastify = fastifyWith(async () => {
      throw new DpopProofError('ath');
    });
    const error = await verifyResourceRequestProof(fastify, requestWith(), 't', claims).catch(
      (caught: unknown) => caught
    );
    expect(error).toBeInstanceOf(InvalidDpopProofError);
    expect((error as InvalidDpopProofError).statusCode).toBe(401);
    expect(failureData(error)).toEqual({ error: 'invalid_dpop_proof', reason: 'dpop_ath' });
  });

  it('answers a proof under another key with invalid_token (RFC 9449 Figure 16)', async () => {
    const fastify = fastifyWith(async () => {
      throw new DpopProofError('key-mismatch');
    });
    const error = await verifyResourceRequestProof(fastify, requestWith(), 't', claims).catch(
      (caught: unknown) => caught
    );
    expect(error).toBeInstanceOf(JWTInvalidError);
    expect(failureData(error)).toEqual({ error: 'invalid_token', reason: 'dpop_key_mismatch' });
  });

  it('lets an unexpected failure through untouched', async () => {
    const boom = new Error('boom');
    const fastify = fastifyWith(async () => {
      throw boom;
    });
    await expect(verifyResourceRequestProof(fastify, requestWith(), 't', claims)).rejects.toBe(
      boom
    );
  });

  it('refuses a token bound to no key, or a server with DPoP off', async () => {
    const verifyRequest = vi.fn();
    await expect(
      verifyResourceRequestProof(fastifyWith(verifyRequest), requestWith(), 't', {
        sub: 'u',
        clientId: 'c',
      })
    ).rejects.toBeInstanceOf(JWTInvalidError);
    await expect(
      verifyResourceRequestProof(fastifyWith(), requestWith(), 't', claims)
    ).rejects.toBeInstanceOf(JWTInvalidError);
    expect(verifyRequest).not.toHaveBeenCalled();
  });
});

describe('readAuthorizationDpopJkt (RFC 9449 §10)', () => {
  const on = fastifyWith(async () => ({ thumbprint: JKT }));

  it('binds a SHA-256 thumbprint while DPoP is on', () => {
    expect(readAuthorizationDpopJkt(on, JKT)).toEqual({ kind: 'bound', jkt: JKT });
  });

  it('is unbound without the parameter, or with DPoP off whatever its value', () => {
    expect(readAuthorizationDpopJkt(on, undefined)).toEqual({ kind: 'unbound' });
    for (const value of [JKT, 'not a thumbprint', [JKT, JKT], 'x'.repeat(5000), 42]) {
      expect(readAuthorizationDpopJkt(fastifyWith(), value)).toEqual({ kind: 'unbound' });
    }
  });

  it('refuses a repeated or non-string value while DPoP is on', () => {
    expect(readAuthorizationDpopJkt(on, [JKT, JKT])).toEqual({ kind: 'malformed' });
    expect(readAuthorizationDpopJkt(on, [JKT])).toEqual({ kind: 'malformed' });
    expect(readAuthorizationDpopJkt(on, 42)).toEqual({ kind: 'malformed' });
  });

  it.each([
    ['empty', ''],
    ['padded', `${JKT.slice(0, 42)}=`],
    ['standard base64', `${JKT.slice(0, 42)}+`],
    ['too short', JKT.slice(0, 42)],
    ['too long', `${JKT}A`],
  ])('refuses a %s value while DPoP is on', (_name, value) => {
    expect(readAuthorizationDpopJkt(on, value)).toEqual({ kind: 'malformed' });
  });
});
