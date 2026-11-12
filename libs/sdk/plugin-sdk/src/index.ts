/**
 * `@qauth-labs/plugin-sdk` — what a QAuth sign-in method plugin is written
 * against: the AuthMethod contract (`qauth-auth-method/1-rc.0`).
 *
 * EXPERIMENTAL. The contract is QAuth's plugin API, the experimental item
 * `plugin-api` (ADR-018 §4): public and documented, but outside the 1.0
 * stability promise, so it may change in a minor release. A breaking change to
 * anything this package exports raises {@link AUTH_METHOD_CONTRACT_VERSION}, and
 * the server refuses a plugin written against another version.
 *
 * Three entry points:
 *
 * - this one: the `AuthMethod` interface and the types it uses, the contract's
 *   constants, its errors and the static checks the server's registry runs;
 *   and the shape of an upstream OpenID Connect preset, a plugin the server
 *   builds on its own OpenID Connect client (`defineUpstreamOidcPreset`);
 * - `@qauth-labs/plugin-sdk/testing`: the contract test kit,
 *   `checkAuthMethod`, and the preset kit, `checkUpstreamOidcPreset`, for a
 *   plugin's own tests;
 * - `@qauth-labs/plugin-sdk/host`: the host's half, which QAuth's server
 *   imports and the test kit runs (the engine's checks around a method's
 *   answers, the context a method is handed). A plugin does not need it.
 *
 * See the package README and `examples/minimal-plugin`.
 *
 * @packageDocumentation
 */

// The AuthMethod interface, the context and egress client as a method sees
// them, and the CredentialProvider half it extends (ADR-003).
export type * from './lib/auth-method.js';
export type * from './lib/credential-provider.js';

// The contract's fixed values: its version, the plugin export, the step, the
// route prefix, the patterns and the caps.
export * from './lib/contract.js';

// The errors of the contract.
export {
  AuthMethodConfigError,
  AuthMethodContractError,
  AuthMethodFaultError,
} from './lib/errors.js';

// The static checks the server's registry and loader run on a method.
export { assertAuthMethod, authMethodProblems, isAuthMethod } from './lib/validate.js';

// An upstream OpenID Connect preset (#671): a provider's facts and claim
// rules, which the server's own client runs. Its types, its constants, the
// helper that defines one and the loader's static checks of it.
export * from './lib/upstream-oidc-preset.js';
