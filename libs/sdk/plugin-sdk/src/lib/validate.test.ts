import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { createSampleAuthMethod } from '../../testing/sample-auth-method.fixture';
import {
  AUTH_METHOD_CONTRACT,
  AUTH_METHOD_ROUTE_ROOT,
  authMethodRoutePrefix,
  MAX_AUTH_METHOD_ICON_BYTES,
  UPSTREAM_STEP_URN,
} from './contract';
import { AuthMethodContractError } from './errors';
import { assertAuthMethod, authMethodProblems, isAuthMethod } from './validate';

const PNG = Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d);
const handle = async () => ({ kind: 'failed' as const, reason: 'transaction_mismatch' as const });

/** The sample method with some members replaced. */
function sample(overrides: Record<string, unknown>): unknown {
  return { ...createSampleAuthMethod(), ...overrides };
}

function callbackAt(path: unknown, method: unknown = 'GET') {
  return { kind: 'callback', method, path, handle };
}

describe('the static checks of the AuthMethod contract', () => {
  it('accepts the sample method', () => {
    const method = createSampleAuthMethod();
    expect(authMethodProblems(method)).toEqual([]);
    expect(isAuthMethod(method)).toBe(true);
    expect(() => assertAuthMethod(method)).not.toThrow();
  });

  it('names the contract and the step with versioned identifiers', () => {
    expect(AUTH_METHOD_CONTRACT).toBe('qauth-auth-method/1-rc.0');
    expect(UPSTREAM_STEP_URN).toBe('urn:qauth:ia:upstream:v1-rc.0');
  });

  it('refuses a method written against another contract version, naming both', () => {
    expect(authMethodProblems(sample({ contract: 'qauth-auth-method/1-rc.1' }))).toEqual([
      'it is written against the contract qauth-auth-method/1-rc.1, and this server implements qauth-auth-method/1-rc.0',
    ]);
    expect(authMethodProblems(sample({ contract: 'something-else' }))).toEqual([
      'contract must be qauth-auth-method/1-rc.0',
    ]);
  });

  it.each([
    ['', 'empty'],
    ['Oidc_corp', 'upper case'],
    ['oidc:corp', 'a colon'],
    ['oidc_https://idp.example', 'an ID-JAG issuer type'],
    ['oidc/corp', 'a slash'],
    ['9oidc', 'a leading digit'],
    ['o'.repeat(64), 'too long'],
  ])('refuses the type %j (%s)', (type) => {
    expect(authMethodProblems(sample({ type }))).toEqual([
      'type must match ^[a-z][a-z0-9_]{0,62}$',
    ]);
  });

  it.each([
    'password',
    'wallet',
    'webauthn',
    'self_reported',
    'totp',
    'recovery_code',
    'email_code',
  ])('refuses the reserved type %s', (type) => {
    expect(authMethodProblems(sample({ type }))).toEqual([
      `type ${type} is reserved for QAuth's own credentials`,
    ]);
  });

  it('refuses an id outside its pattern', () => {
    expect(authMethodProblems(sample({ id: 'Sample' }))).toEqual([
      'id must match ^[a-z][a-z0-9_-]{0,62}$',
    ]);
  });

  it.each([
    ['<b>Bold</b>', 'markup'],
    [' Leading', 'a space at the start'],
    ['Trailing ', 'a space at the end'],
    ['Line\nbreak', 'a control character'],
    [`Zero${String.fromCharCode(0x200b)}width`, 'a format character'],
    ['x'.repeat(65), 'over 64 characters'],
    ['', 'empty'],
  ])('refuses the display name %j (%s)', (name) => {
    expect(authMethodProblems(sample({ display: { name } }))).toHaveLength(1);
  });

  it('accepts a PNG icon within its cap and refuses anything else', () => {
    expect(
      authMethodProblems(
        sample({ display: { name: 'Corp', icon: { mediaType: 'image/png', bytes: PNG } } })
      )
    ).toEqual([]);
    expect(
      authMethodProblems(
        sample({ display: { name: 'Corp', icon: { mediaType: 'image/svg+xml', bytes: PNG } } })
      )
    ).toEqual(['display.icon.mediaType must be image/png']);
    expect(
      authMethodProblems(
        sample({
          display: {
            name: 'Corp',
            icon: {
              mediaType: 'image/png',
              bytes: new TextEncoder().encode('<svg onload="x()"/>'),
            },
          },
        })
      )
    ).toEqual(['display.icon.bytes must be a PNG file']);
    const large = new Uint8Array(MAX_AUTH_METHOD_ICON_BYTES + 1);
    large.set(PNG);
    expect(
      authMethodProblems(
        sample({ display: { name: 'Corp', icon: { mediaType: 'image/png', bytes: large } } })
      )
    ).toEqual([`display.icon.bytes must be at most ${MAX_AUTH_METHOD_ICON_BYTES} bytes`]);
  });

  it('refuses a method with no config schema, or no function where one belongs', () => {
    expect(authMethodProblems(sample({ configSchema: { type: 'object' } }))).toEqual([
      'configSchema must be a Zod schema',
    ]);
    expect(authMethodProblems(sample({ start: undefined, verify: 'yes' }))).toEqual([
      'verify must be a function',
      'start must be a function',
    ]);
    expect(authMethodProblems(sample({ configSchema: z.object({}) }))).toEqual([]);
  });

  it('refuses steps that are missing, unknown, of another version or repeated', () => {
    expect(authMethodProblems(sample({ steps: [] }))).toEqual([
      'steps must list at least one step',
    ]);
    expect(authMethodProblems(sample({ steps: ['urn:qauth:ia:upstream:v1'] }))).toEqual([
      'steps holds urn:qauth:ia:upstream:v1, which is not a step a method may contribute here (urn:qauth:ia:upstream:v1-rc.0)',
    ]);
    expect(authMethodProblems(sample({ steps: ['urn:qauth:ia:password:v1-rc.0'] }))).toHaveLength(
      1
    );
    expect(authMethodProblems(sample({ steps: [UPSTREAM_STEP_URN, UPSTREAM_STEP_URN] }))).toEqual([
      'steps repeats urn:qauth:ia:upstream:v1-rc.0',
    ]);
  });

  describe('a method cannot mount a route outside its prefix', () => {
    const outside =
      "routes[0].path must be one to four lower-case segments, such as /callback: a route cannot leave the method's prefix";

    it.each([
      '/../oauth/token',
      '/..',
      '/./callback',
      'callback',
      '//evil.example/callback',
      '/%2e%2e/oauth/token',
      '/callback/',
      '/Callback',
      '/:provider/callback',
      '/*',
      '/callback?x=1',
      '/a/b/c/d/e',
      '',
      '/',
    ])('refuses the path %j', (path) => {
      expect(authMethodProblems(sample({ routes: [callbackAt(path)] }))).toEqual([outside]);
    });

    it('builds every prefix under the fixed root, from the type alone', () => {
      expect(AUTH_METHOD_ROUTE_ROOT).toBe('/upstream');
      expect(authMethodRoutePrefix('oidc_corp')).toBe('/upstream/oidc_corp');
      expect(() => authMethodRoutePrefix('../admin')).toThrow(TypeError);
    });
  });

  it('refuses repeated routes, unknown kinds and methods, and a method with no callback', () => {
    expect(authMethodProblems(sample({ routes: [callbackAt('/cb'), callbackAt('/cb')] }))).toEqual([
      'routes[1] repeats GET /cb',
    ]);
    expect(authMethodProblems(sample({ routes: [callbackAt('/cb', 'PUT')] }))).toEqual([
      'routes[0].method must be GET or POST',
    ]);
    expect(
      authMethodProblems(
        sample({ routes: [{ kind: 'bounce', method: 'POST', path: '/cb', handle }] })
      )
    ).toEqual(['routes must hold at least one callback route: the upstream step returns there']);
    expect(
      authMethodProblems(sample({ routes: [{ kind: 'page', method: 'GET', path: '/cb', handle }] }))
    ).toEqual([
      'routes[0].kind must be callback or bounce',
      'routes must hold at least one callback route: the upstream step returns there',
    ]);
  });

  it('accepts a callback that names its binding parameter, and refuses a bad name or a bounce that names one', () => {
    expect(
      authMethodProblems(sample({ routes: [{ ...callbackAt('/cb'), bindingParameter: 'rs' }] }))
    ).toEqual([]);
    const problem =
      'routes[0].bindingParameter must be the name of a parameter (^[A-Za-z0-9_.-]{1,64}$), on a callback route only';
    for (const bindingParameter of ['', 'a b', 'x'.repeat(65), 7]) {
      expect(
        authMethodProblems(sample({ routes: [{ ...callbackAt('/cb'), bindingParameter }] }))
      ).toEqual([problem]);
    }
    expect(
      authMethodProblems(
        sample({
          routes: [
            { kind: 'bounce', method: 'POST', path: '/cb', handle, bindingParameter: 'state' },
            callbackAt('/cb'),
          ],
        })
      )
    ).toEqual([problem]);
  });

  it('throws one error that lists every problem', () => {
    try {
      assertAuthMethod(sample({ type: 'wallet', id: 'X', steps: [] }));
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AuthMethodContractError);
      expect((error as AuthMethodContractError).problems).toHaveLength(3);
      expect((error as Error).message).toMatch(
        /^The AuthMethod wallet does not meet the AuthMethod contract:/
      );
    }
    expect(authMethodProblems(null)).toEqual(['it is not an object']);
  });
});
