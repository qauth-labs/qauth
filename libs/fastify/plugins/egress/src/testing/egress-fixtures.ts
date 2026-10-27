/**
 * TEST SUPPORT — the egress library's fixtures, for an auth-server suite
 * (issue #481), which may not import the library itself:
 *
 * - `startLocalHttpsFixture`: an HTTPS server on localhost that only
 *   `createTestEgressClient` reaches;
 * - `createFixtureNetwork`: a DNS table and a dialler to local servers, for a
 *   suite that mocks the egress transport module to give the production
 *   client public and private addresses of its own (as the SSF suite does).
 */
export type { EgressTransport } from '@qauth-labs/server-egress/src/lib/transport';
export {
  createFixtureNetwork,
  type FixtureHandler,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/server-egress/src/testing/fixture-network';
export {
  type LocalFixtureHandler,
  type LocalHttpsFixture,
  startLocalHttpsFixture,
} from '@qauth-labs/server-egress/src/testing/loopback-fixture';
