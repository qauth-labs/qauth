import { SIGNER_SERVICE_PATH } from '@qauth-labs/fastify-plugin-signer';
import { SERVICE_ROLE_NAMES } from '@qauth-labs/server-config';
import { describe, expect, it } from 'vitest';

import {
  enabledInternalRouteModules,
  INTERNAL_ROUTE_MODULES,
  internalModuleProblem,
  type InternalRouteModule,
  internalRouteModulesFor,
  internalRouteProblem,
  publicInternalRouteProblem,
  SIGNER_SERVICE_PREFIX,
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
  it('holds the metrics module and the signer service (#497)', () => {
    expect(INTERNAL_ROUTE_MODULES.map((entry) => entry.module)).toEqual(['metrics', 'signer']);
    expect(Object.isFrozen(INTERNAL_ROUTE_MODULES)).toBe(true);
  });

  it('serves the signer service on a split process that holds the signer, to the roles the signer has grants for', () => {
    const signer = INTERNAL_ROUTE_MODULES.find((entry) => entry.module === 'signer');
    expect(signer).toMatchObject({
      prefix: SIGNER_SERVICE_PATH,
      roles: ['signer'],
      peerRoles: ['web', 'api', 'delivery', 'admin'],
    });
    expect(SIGNER_SERVICE_PREFIX).toBe(SIGNER_SERVICE_PATH);
    expect(signer?.inSingleProcess).toBeUndefined();
    expect(signer?.peerRoles).not.toContain('metrics');
    for (const roles of [['signer'], ['api', 'signer'], ['signer', 'delivery']] as const) {
      expect(
        internalRouteModulesFor(roles).map((entry) => entry.module),
        roles.join()
      ).toEqual(['metrics', 'signer']);
    }
    expect(internalRouteModulesFor(SERVICE_ROLE_NAMES).map((entry) => entry.module)).toEqual([
      'metrics',
    ]);
  });

  it('serves the metrics on every process, to the metrics peer only, while METRICS_ENABLED is on (#500)', () => {
    const [metrics, signer] = INTERNAL_ROUTE_MODULES;
    expect(metrics).toMatchObject({
      prefix: '/internal',
      roles: SERVICE_ROLE_NAMES,
      peerRoles: ['metrics'],
      inSingleProcess: true,
    });
    for (const roles of [SERVICE_ROLE_NAMES, ['web'], ['delivery']] as const) {
      expect(internalRouteModulesFor(roles), roles.join()).toEqual([metrics]);
    }
    expect(enabledInternalRouteModules({})).toEqual([metrics, signer]);
    expect(enabledInternalRouteModules({ METRICS_ENABLED: true })).toEqual([metrics, signer]);
    expect(enabledInternalRouteModules({ METRICS_ENABLED: false })).toEqual([signer]);
  });

  it('names the peer roles of every module', () => {
    for (const entry of INTERNAL_ROUTE_MODULES) {
      expect(internalModuleProblem(entry), entry.module).toBeUndefined();
    }
  });

  it('refuses a module that names no peer role', () => {
    const load = async () => ({ default: async () => undefined });
    const open: InternalRouteModule = {
      module: 'open',
      prefix: '/internal/open/v1-rc.0',
      roles: ['signer'],
      peerRoles: [],
      load,
    };
    expect(internalModuleProblem(open)).toContain(
      'The internal route module open names no peer role'
    );
    expect(internalModuleProblem({ ...open, peerRoles: ['admin'] })).toBeUndefined();
  });

  it('gives a process the modules of the roles it holds', () => {
    const load = async () => ({ default: async () => undefined });
    const modules: InternalRouteModule[] = [
      {
        module: 'signer',
        prefix: '/internal/signer/v1-rc.0',
        roles: ['signer'],
        peerRoles: ['web', 'api'],
        load,
      },
      {
        module: 'web',
        prefix: '/internal/web/v1-rc.0',
        roles: ['web', 'api'],
        peerRoles: ['delivery'],
        load,
      },
    ];
    expect(internalRouteModulesFor(['signer'], modules).map((entry) => entry.module)).toEqual([
      'signer',
    ]);
    expect(
      internalRouteModulesFor(['api', 'signer'], modules).map((entry) => entry.module)
    ).toEqual(['signer', 'web']);
    expect(internalRouteModulesFor(['delivery'], modules)).toEqual([]);
    // A single process calls its own roles in-process: only a module marked
    // for it registers there.
    expect(internalRouteModulesFor(SERVICE_ROLE_NAMES, modules)).toEqual([]);
    const shared = { ...modules[1], inSingleProcess: true };
    expect(internalRouteModulesFor(SERVICE_ROLE_NAMES, [modules[0], shared])).toEqual([shared]);
  });
});
