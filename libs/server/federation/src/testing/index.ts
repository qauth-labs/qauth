// The `testing` entry point of @qauth-labs/server-federation: test support for
// authors of AuthMethods (#599, EXPERIMENTAL). Never imported by the main
// entry point; the contract test kit replaces the global `fetch` while it runs.
export type {
  AuthMethodKitReport,
  AuthMethodKitRequest,
  AuthMethodKitScenario,
} from './contract-kit';
export { checkAuthMethod } from './contract-kit';
