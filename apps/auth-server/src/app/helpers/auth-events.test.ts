import { createHash } from 'node:crypto';

import type { FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { hashEmail, logAuthEvent } from './auth-events';

function createRequestStub() {
  const info = vi.fn();
  const warn = vi.fn();
  const request = {
    ip: '203.0.113.7',
    log: { info, warn },
  } as unknown as FastifyRequest;
  return { request, info, warn };
}

describe('auth-events helper', () => {
  it('hashEmail produces a stable SHA-256 hex digest', () => {
    const email = 'user@example.com';
    const expected = createHash('sha256').update(email).digest('hex');
    expect(hashEmail(email)).toBe(expected);
    expect(hashEmail(email)).toBe(hashEmail(email));
  });

  it('logs success events at info with identifiers and IP', () => {
    const { request, info, warn } = createRequestStub();
    logAuthEvent(request, 'user.login.success', true, {
      userId: 'u1',
      clientId: 'system',
      email: 'user@example.com',
    });

    expect(warn).not.toHaveBeenCalled();
    expect(info).toHaveBeenCalledTimes(1);
    const [payload, msg] = info.mock.calls[0];
    expect(msg).toContain('user.login.success');
    expect(payload).toMatchObject({
      authEvent: 'user.login.success',
      success: true,
      userId: 'u1',
      clientId: 'system',
      ip: '203.0.113.7',
    });
    expect(typeof payload.timestamp).toBe('string');
  });

  it('logs failures at warn with an email hash and reason', () => {
    const { request, info, warn } = createRequestStub();
    logAuthEvent(request, 'user.login.failure', false, {
      emailHash: hashEmail('user@example.com'),
      reason: 'invalid_credentials',
    });

    expect(info).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
    const [payload] = warn.mock.calls[0];
    expect(payload).toMatchObject({
      authEvent: 'user.login.failure',
      success: false,
      reason: 'invalid_credentials',
    });
    // No raw email on the failure path.
    expect(payload.email).toBeUndefined();
    expect(payload.emailHash).toBe(hashEmail('user@example.com'));
  });
});
