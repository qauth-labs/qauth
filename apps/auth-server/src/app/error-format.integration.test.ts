import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type E2eInfrastructure,
  generateJwtPem,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE OAUTH PROTOCOL ENDPOINTS KEEP THE ERROR SHAPE THEIR RFC DEFINES
 * (ADR-019 Decision 7, #506).
 *
 * The admin, account and developer APIs answer an error with an RFC 9457
 * problem document. An OAuth protocol endpoint does not: the clients and
 * libraries written to its specification parse the shape that specification
 * defines. `error-handler-wiring.test.ts` asserts the problem half on API family
 * routes in the assembled app; this suite asserts the protocol half on the
 * token and revocation endpoints, which resolve the realm from the database
 * before they refuse a client, so they need a real one.
 *
 * Assertions read the machine-readable member (`error`) and the status, never
 * the wording.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

/** Problem-document members that must never appear in an RFC 6749 §5.2 body. */
const PROBLEM_MEMBERS = ['type', 'title', 'status', 'trace_id'];

describe('OAuth protocol endpoints keep their RFC error shape (real containers, #506)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer(baseEnvironment(infra, await generateJwtPem()));
    await resetE2eState(booted.app);
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  function app(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /** RFC 6749 §5.2: a JSON object whose `error` is the registered token. */
  function expectOAuthError(
    response: Awaited<ReturnType<FastifyInstance['inject']>>,
    status: number,
    error: string
  ): void {
    expect(response.statusCode).toBe(status);
    expect(response.headers['content-type']).toMatch(/^application\/json(?:;|$)/);
    const body = response.json() as Record<string, unknown>;
    expect(body['error']).toBe(error);
    for (const member of PROBLEM_MEMBERS) expect(body).not.toHaveProperty(member);
  }

  it('POST /oauth/token answers invalid_client for an unknown client (RFC 6749 §5.2)', async () => {
    const response = await app().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload:
        'grant_type=client_credentials&client_id=no-such-client&client_secret=wrong&scope=read',
    });

    expectOAuthError(response, 401, 'invalid_client');
  });

  it('POST /oauth/token answers invalid_client with a Basic challenge for two authentication methods (RFC 6749 §2.3, §5.2)', async () => {
    const response = await app().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: {
        ...FORM,
        authorization: `Basic ${Buffer.from('a-client:a-secret').toString('base64')}`,
      },
      payload: 'grant_type=client_credentials&client_secret=another-secret',
    });

    expectOAuthError(response, 401, 'invalid_client');
    expect(response.headers['www-authenticate']).toBe('Basic realm="OAuth"');
  });

  it('POST /oauth/revoke answers invalid_client for an unknown client (RFC 7009 §2.2.1)', async () => {
    const response = await app().inject({
      method: 'POST',
      url: '/oauth/revoke',
      headers: FORM,
      payload: 'token=anything&client_id=no-such-client&client_secret=wrong',
    });

    expectOAuthError(response, 401, 'invalid_client');
  });
});
