import { describe, expect, it } from 'vitest';

import {
  ADMIN_REALM_ROUTE_PREFIX,
  adminRealmRouteProblem,
  publicRouteProblem,
} from './route-placement';

/** Where an admin route may be served (#511). */

describe('adminRealmRouteProblem', () => {
  it('admits a route on the realm its path names, and every path below it', () => {
    expect(ADMIN_REALM_ROUTE_PREFIX).toBe('/admin/v1-rc.0/realms/:realmId');
    for (const url of [
      '/admin/v1-rc.0/realms/:realmId',
      '/admin/v1-rc.0/realms/:realmId/policies',
      '/admin/v1-rc.0/realms/:realmId/approvals/:approvalId',
    ]) {
      expect(adminRealmRouteProblem({ method: 'GET', url })).toBeUndefined();
    }
  });

  it('refuses a route that names no realm in its path, or names it another way', () => {
    for (const url of [
      '/admin/v1-rc.0/realms',
      '/admin/v1-rc.0/realms/:id',
      '/admin/v1-rc.0/realms/:realmIdentifier',
      '/admin/v1-rc.0/operators/:realmId',
      '/admin/v1-rc.1/realms/:realmId',
      '/realms/:realmId',
    ]) {
      expect(adminRealmRouteProblem({ method: ['GET', 'POST'], url })).toContain(
        `GET,POST ${url}: every admin route acts on the realm its path names`
      );
    }
  });
});

describe('publicRouteProblem', () => {
  it('refuses a path under /admin on the public listener, whatever its version or none', () => {
    for (const url of [
      '/admin/v1-rc.0/realms/:realmId',
      '/admin/v1-rc.0',
      '/admin/v1/realms',
      '/admin/v2-rc.3/anything',
      '/admin',
      '/admin/*',
      '/admin/realms/:realmId',
    ]) {
      expect(publicRouteProblem({ method: 'GET', url })).toContain(
        'registers only on the admin listener'
      );
    }
  });

  it('admits every other path, the other families and the unversioned ones included', () => {
    for (const url of [
      '/oauth/token',
      '/account/v1-rc.0/consents',
      '/developer/v1-rc.0/clients',
      '/administration',
      '/api/clients',
    ]) {
      expect(publicRouteProblem({ method: 'GET', url })).toBeUndefined();
    }
  });
});
