/**
 * `@qauth-labs/plugin-sdk/testing` — test support for authors of AuthMethods
 * (#599, EXPERIMENTAL): the contract test kit, `checkAuthMethod`, which checks
 * a method against the contract in any test runner, and the preset kit,
 * `checkUpstreamOidcPreset`, which checks an upstream OpenID Connect preset
 * (#671) without the server.
 *
 * Never imported by the main entry point: while the kit runs, it replaces the
 * global `fetch`, and it refuses to run with `NODE_ENV=production`.
 *
 * @packageDocumentation
 */
export type {
  AuthMethodKitReport,
  AuthMethodKitRequest,
  AuthMethodKitScenario,
} from './contract-kit.js';
export { checkAuthMethod } from './contract-kit.js';
export type { UpstreamOidcPresetKitReport, UpstreamOidcPresetKitScenario } from './preset-kit.js';
export { checkUpstreamOidcPreset } from './preset-kit.js';
