/**
 * `@qauth-labs/plugin-sdk/host` — the host's half of the AuthMethod contract
 * (#599): what QAuth's server runs around a method, and what the contract
 * test kit runs the same way, so a method meets in its tests exactly what the
 * server does.
 *
 * - the engine's checks around the two calls it makes into a method
 *   (`startUpstreamStep`, `completeUpstreamStep`) and the host's binding check
 *   before it hands a callback its transaction (`presentedUpstreamBinding`,
 *   `upstreamBindingMatches`);
 * - the context a method is handed for one realm (`createAuthMethodContext`),
 *   over the host's egress client, signer and logger;
 * - the parameters a route handler sees (`authMethodParameters`);
 * - the registry's snapshot and route checks.
 *
 * EXPERIMENTAL, like the contract. A plugin does not import this entry point:
 * it needs only the main one and `@qauth-labs/plugin-sdk/testing`.
 *
 * @packageDocumentation
 */

export * from './lib/context.js';
export * from './lib/engine.js';
export { authMethodParameters } from './lib/parameters.js';
export {
  authMethodSnapshot,
  authMethodTypeProblems,
  declaresAuthMethodContract,
  routeProblems,
} from './lib/validate.js';
