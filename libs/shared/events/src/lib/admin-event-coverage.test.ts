import { describe, expect, it } from 'vitest';

import { adminEventCoverage } from './admin-event-coverage';

const ADMIN = { type: 'urn:qauth:event:admin.change_applied:v1-rc.0' };
const USER = { type: 'urn:qauth:event:user.signed_in:v1-rc.0' };

const ROUTES = [
  { method: 'GET', url: '/admin/v1-rc.0/realms/:realmId/clients' },
  { method: ['POST', 'HEAD'], url: '/admin/v1-rc.0/realms/:realmId/clients' },
  { method: 'PATCH', url: '/admin/v1-rc.0/realms/:realmId/clients/:clientId' },
  { method: 'DELETE', url: '/admin/v1-rc.0/realms/:realmId/clients/:clientId' },
  { method: 'OPTIONS', url: '/admin/v1-rc.0/realms/:realmId/clients/:clientId' },
];

describe('adminEventCoverage', () => {
  it('reports every route that changes something and whose test saw no admin event', () => {
    const coverage = adminEventCoverage();
    coverage.record({ method: 'post', url: '/admin/v1-rc.0/realms/:realmId/clients' }, [ADMIN]);
    expect(coverage.missing(ROUTES)).toEqual([
      'DELETE /admin/v1-rc.0/realms/:realmId/clients/:clientId',
      'PATCH /admin/v1-rc.0/realms/:realmId/clients/:clientId',
    ]);
  });

  it('counts only an admin event', () => {
    const coverage = adminEventCoverage();
    coverage.record({ method: 'PATCH', url: '/admin/v1-rc.0/realms/:realmId/clients/:clientId' }, [
      USER,
    ]);
    coverage.record({ method: 'DELETE', url: '/admin/v1-rc.0/realms/:realmId/clients/:clientId' }, [
      { type: 'urn:qauth:event:admin.unknown:v1-rc.0' },
    ]);
    expect(coverage.missing(ROUTES)).toHaveLength(3);
  });

  it('passes a table whose changing routes are all covered, and never asks it of a read', () => {
    const coverage = adminEventCoverage();
    for (const route of ROUTES) {
      for (const method of typeof route.method === 'string' ? [route.method] : route.method) {
        if (method !== 'GET') coverage.record({ method, url: route.url }, [USER, ADMIN]);
      }
    }
    expect(coverage.missing(ROUTES)).toEqual([]);
    expect(adminEventCoverage().missing(ROUTES.filter((r) => r.method === 'GET'))).toEqual([]);
  });
});
