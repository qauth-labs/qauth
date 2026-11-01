import { describe, expect, it } from 'vitest';

import {
  INTERNAL_ROUTE_MODULES,
  type InternalRouteModule,
  internalRouteModulesFor,
  internalRouteProblem,
  publicInternalRouteProblem,
} from './route-manifest';

/** Where an internal route may be served (#496). */

describe('internalRouteProblem', () => {
  it('admits a route under /internal/', () => {
    for (const url of ['/internal/signer/v1-rc.0/sign', '/internal/x']) {
      expect(internalRouteProblem({ method: 'POST', url })).toBeUndefined();
    }
  });

  it('refuses any other path', () => {
    for (const url of [
      '/internal',
      '/internal/',
      '/internals/x',
      '/oauth/token',
      '/admin/v1-rc.0',
      '/',
    ]) {
      expect(internalRouteProblem({ method: ['GET', 'POST'], url })).toContain(
        `GET,POST ${url}: every route of the internal listener sits under /internal/`
      );
    }
  });
});

describe('publicInternalRouteProblem', () => {
  it('refuses a path under /internal on the public listener', () => {
    for (const url of ['/internal', '/internal/', '/internal/signer/v1-rc.0/sign', '/internal/*']) {
      expect(publicInternalRouteProblem({ method: 'GET', url })).toContain(
        'is an internal route: it registers only on the internal listener'
      );
    }
  });

  it('admits every other path', () => {
    for (const url of ['/internals', '/interaction/v1-rc.0/x', '/oauth/token', '*', '/']) {
      expect(publicInternalRouteProblem({ method: 'GET', url })).toBeUndefined();
    }
  });
});

describe('the internal route manifest', () => {
  it('holds no module until the signer service lands (#497)', () => {
    expect(INTERNAL_ROUTE_MODULES).toEqual([]);
    expect(Object.isFrozen(INTERNAL_ROUTE_MODULES)).toBe(true);
  });

  it('gives a process the modules of the roles it holds', () => {
    const load = async () => ({ default: async () => undefined });
    const modules: InternalRouteModule[] = [
      { module: 'signer', prefix: '/internal/signer/v1-rc.0', roles: ['signer'], load },
      { module: 'web', prefix: '/internal/web/v1-rc.0', roles: ['web', 'api'], load },
    ];
    expect(internalRouteModulesFor(['signer'], modules).map((entry) => entry.module)).toEqual([
      'signer',
    ]);
    expect(
      internalRouteModulesFor(['api', 'signer'], modules).map((entry) => entry.module)
    ).toEqual(['signer', 'web']);
    expect(internalRouteModulesFor(['delivery'], modules)).toEqual([]);
  });
});
