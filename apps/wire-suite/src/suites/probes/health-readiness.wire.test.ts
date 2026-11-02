import { describe, expect, it } from 'vitest';

import { call } from '../../helpers/operations';

/**
 * The probes every process answers (ADR-019 Decisions 1 and 8, #500): `/health`
 * is liveness and checks no dependency, `/ready` runs the readiness checks of
 * the process's service roles. A target the suite can run against is ready,
 * so `/ready` answers 200 here; the 503 answer is the auth server's
 * integration suite's, which can take a dependency away.
 */

/** The service roles a process may run. */
const SERVICE_ROLES = ['web', 'api', 'admin', 'signer', 'delivery'];

/** `application/json`, with or without parameters. */
const JSON_CONTENT_TYPE = /^application\/json\s*(?:;|$)/i;

/** The roles a probe names: a non-empty list of known roles. */
function expectRoles(roles: unknown): void {
  expect(Array.isArray(roles), 'roles is a list').toBe(true);
  expect((roles as unknown[]).length).toBeGreaterThan(0);
  for (const role of roles as unknown[]) expect(SERVICE_ROLES).toContain(role);
}

describe('[GET /health] liveness: the process answers, with its service roles', () => {
  it('answers 200 with status ok, the time and the roles, never stored', async () => {
    const response = await call('GET /health');

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type') ?? '').toMatch(JSON_CONTENT_TYPE);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(['roles', 'status', 'timestamp']);
    expect(body['status']).toBe('ok');
    expect(Number.isNaN(Date.parse(String(body['timestamp'])))).toBe(false);
    expectRoles(body['roles']);
  });
});

describe('[GET /ready] readiness: every check of the process roles passes', () => {
  it('answers 200 with status ok and each check passed, never stored', async () => {
    const response = await call('GET /ready');

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type') ?? '').toMatch(JSON_CONTENT_TYPE);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(['checks', 'roles', 'status']);
    expect(body['status']).toBe('ok');
    expectRoles(body['roles']);
    const checks = body['checks'] as Record<string, unknown>;
    // Every process checks its database.
    expect(Object.keys(checks)).toContain('database');
    for (const [name, result] of Object.entries(checks)) {
      expect(result, name).toEqual({ status: 'ok' });
    }
  });
});
