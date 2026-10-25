import type { FastifyInstance } from 'fastify';

import type { RealmRow } from '../app/helpers/request-realm';

/**
 * A realm row for a unit test's request, as the realm resolver
 * (`plugins/realm-resolver.ts`, #486) decorates it on `request.realm`. Every
 * handler takes its realm from there (#487), so a unit test that calls a
 * handler or injects into a bare Fastify instance supplies one.
 *
 * Only the columns handlers read are filled, with the defaults a new realm
 * gets; `overrides` sets any other, such as a `maxEnvironmentLaxity` ceiling
 * or an `ssoMaxLifespan`.
 */
export function testRealm(overrides: Partial<RealmRow> & { id: string }): RealmRow {
  return {
    name: 'master',
    enabled: true,
    issuer: 'https://auth.example.com',
    maxEnvironmentLaxity: 'production',
    dynamicRegistrationAllowedScopes: [],
    ssoMaxLifespan: null,
    ...overrides,
  } as RealmRow;
}

/**
 * Give every request of `app` the realm `realm`, as the realm resolver would
 * for a request to the realm's host. For a unit test that registers routes on
 * a bare Fastify instance without the resolver.
 */
export function supplyRequestRealm(app: FastifyInstance, realm: RealmRow): void {
  app.decorateRequest('realm', null);
  app.decorateRequest('realmHost', null);
  app.addHook('onRequest', async (request) => {
    request.realm = realm;
    request.realmHost = { host: 'auth.example.com', kind: 'primary' };
  });
}
