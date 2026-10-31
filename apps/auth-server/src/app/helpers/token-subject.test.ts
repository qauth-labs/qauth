import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { InvalidRequestError, JWTInvalidError } from '@qauth-labs/shared-errors';
import Fastify, { type FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// management-token → client-auth → client-resolution → cimd pulls in the env
// module; stub it so the real env-schema parse does not run in tests.
vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

vi.mock('./oauth-client', () => ({
  getOrCreateSystemClient: vi.fn(async () => ({
    id: '00000000-0000-4000-8000-00000000000a',
    clientId: 'system',
    audience: null,
  })),
}));

// The helpers, spied on, so a test can see that a refusal went through them.
vi.mock('./token-subject', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./token-subject')>();
  return {
    ...actual,
    inactiveSubjectError: vi.fn(actual.inactiveSubjectError),
    inactiveSubjectTokenError: vi.fn(actual.inactiveSubjectTokenError),
  };
});

import errorHandler from '../plugins/error-handler';
import { assertManagementToken } from './management-token';
import {
  INACTIVE_SUBJECT_DESCRIPTION,
  inactiveSubjectError,
  inactiveSubjectTokenError,
} from './token-subject';

/**
 * ONE REFUSAL FOR A TOKEN WHOSE SUBJECT IS NOT AN ACTIVE USER (#513).
 *
 * Before #513 the same condition read three ways — `Access token subject is
 * not a user` (userinfo, logout), `Access token subject is not an active user`
 * (management token) and `Token subject is not an active user` (the
 * authorization endpoint's bearer path) — and the token exchange said three
 * more things about its `subject_token`. Every route now raises it through
 * `helpers/token-subject.ts`, and so answers one code: `invalid_access_token` on a
 * problem route, `invalid_token` on an OAuth endpoint, and `invalid_request`
 * for a `subject_token` (RFC 8693 §2.2.2).
 */

const APP_DIR = join(__dirname, '..');

/** Every source module of the app, tests left out. */
function appSources(dir = APP_DIR): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return appSources(path);
    return name.endsWith('.ts') && !name.endsWith('.test.ts') ? [path] : [];
  });
}

/** The modules that refuse a token for its subject, and the helper each raises it with. */
const REFUSING_MODULES: Readonly<
  Record<string, 'inactiveSubjectError' | 'inactiveSubjectTokenError'>
> = {
  'routes/oauth/userinfo.ts': 'inactiveSubjectError',
  'routes/auth/logout.ts': 'inactiveSubjectError',
  'helpers/management-token.ts': 'inactiveSubjectError',
  'helpers/family-token.ts': 'inactiveSubjectError',
  'routes/oauth/token.ts': 'inactiveSubjectTokenError',
};

const USER_ID = '11111111-1111-4111-8111-111111111111';
const REALM = { id: '0190e3c4-0000-7000-8000-00000000000a' };
const users = { findById: vi.fn() };
const fastify = { repositories: { users } } as unknown as FastifyInstance;

/** The claims `/auth/login` puts on the developer-portal token. */
function portalClaims(overrides: Record<string, unknown> = {}) {
  return {
    sub: USER_ID,
    clientId: 'system',
    aud: 'urn:qauth:aud:developer:v1-rc.0',
    ...overrides,
  };
}

beforeEach(() => {
  vi.mocked(inactiveSubjectError).mockClear();
  vi.mocked(inactiveSubjectTokenError).mockClear();
  users.findById.mockReset();
});

describe('the inactive-subject refusal (#513)', () => {
  it('is one class and one wording for an access token, another for a subject_token', () => {
    const access = inactiveSubjectError();
    const subjectToken = inactiveSubjectTokenError();

    expect(access).toBeInstanceOf(JWTInvalidError);
    expect(access.message).toBe(INACTIVE_SUBJECT_DESCRIPTION);
    expect(subjectToken).toBeInstanceOf(InvalidRequestError);
    expect(subjectToken.message).toBe('invalid_request');
  });

  it('answers invalid_access_token on a problem route and invalid_token on an OAuth endpoint', async () => {
    const app = Fastify({ logger: false });
    await app.register(errorHandler);
    app.get('/api/clients', async () => {
      throw inactiveSubjectError();
    });
    app.get('/oauth/userinfo', { config: { errorFormat: 'oauth' } }, async () => {
      throw inactiveSubjectError();
    });
    app.post('/oauth/token', { config: { errorFormat: 'oauth' } }, async () => {
      throw inactiveSubjectTokenError();
    });

    // The refusal is of a token that was presented: its challenge names
    // `invalid_token` (RFC 6750 §3.1).
    const presented = { authorization: 'Bearer a.b.c' };
    const problem = await app.inject({ method: 'GET', url: '/api/clients', headers: presented });
    const oauth = await app.inject({ method: 'GET', url: '/oauth/userinfo', headers: presented });
    const exchange = await app.inject({ method: 'POST', url: '/oauth/token' });
    await app.close();

    expect(problem.statusCode).toBe(401);
    expect(problem.json()).toMatchObject({ status: 401, code: 'invalid_access_token' });
    expect(oauth.statusCode).toBe(401);
    expect(oauth.json()).toMatchObject({ error: 'invalid_token' });
    expect(oauth.headers['www-authenticate']).toContain('error="invalid_token"');
    expect(exchange.statusCode).toBe(400);
    expect(exchange.json()).toMatchObject({ error: 'invalid_request' });
  });

  it.each([
    ['a subject that is not a UUID', 'reporting-service', undefined],
    ['a subject that names no user', USER_ID, null],
    ['a disabled user', USER_ID, { id: USER_ID, enabled: false, realmId: REALM.id }],
  ])('is what the management token check raises for %s', async (_label, sub, user) => {
    users.findById.mockResolvedValue(user);

    const refused = await assertManagementToken(fastify, REALM, portalClaims({ sub })).catch(
      (error: unknown) => error
    );

    expect(inactiveSubjectError).toHaveBeenCalledTimes(1);
    expect(refused).toBe(vi.mocked(inactiveSubjectError).mock.results[0]?.value);
  });

  it.each(Object.entries(REFUSING_MODULES))('%s raises the refusal through %s', (path, helper) => {
    const source = readFileSync(join(APP_DIR, path), 'utf8');

    expect(source).toMatch(
      new RegExp(`import \\{[^}]*\\b${helper}\\b[^}]*\\} from '[./]+(?:helpers/)?token-subject'`)
    );
    expect(source).toMatch(new RegExp(`\\b${helper}\\(\\)`));
  });

  it('is worded nowhere else: no module builds its own refusal of a token subject', () => {
    // A JWTInvalidError, InvalidRequestError or BadRequestError whose message
    // or description names the subject, written outside the helper.
    const ownWording =
      /new (?:JWTInvalidError|InvalidRequestError|BadRequestError)\(\s*['`"][^'`"]*\bsubject\b[^'`"]*['`"]/i;
    const offenders = appSources()
      .filter((path) => !path.endsWith(join('helpers', 'token-subject.ts')))
      .filter((path) => ownWording.test(readFileSync(path, 'utf8')))
      .map((path) => relative(APP_DIR, path));

    expect(offenders).toEqual([]);
  });
});
