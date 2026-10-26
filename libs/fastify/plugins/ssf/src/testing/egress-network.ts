/**
 * TEST SUPPORT — the egress client's fixture network, for a suite that pushes
 * SETs to local HTTPS receivers (issue #410).
 *
 * The egress client refuses loopback, so a suite replaces its two network
 * edges with `createFixtureNetwork` (a DNS table and a dialler to local
 * servers) by mocking the egress transport module, as the egress library's
 * own tests do. Everything between, the address checks included, is the
 * production code.
 */
export type { EgressTransport } from '@qauth-labs/server-egress/src/lib/transport';
export {
  createFixtureNetwork,
  type FixtureHandler,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/server-egress/src/testing/fixture-network';
