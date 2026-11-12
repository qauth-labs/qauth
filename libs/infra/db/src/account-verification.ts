/**
 * `@qauth-labs/infra-db/account-verification`: an operator's verification of
 * an account from the server host (issue #1052), for the migration runner's
 * `verify-account` command, and nothing else.
 *
 * A separate entry point for the reason `./migrations` is one: the migration
 * runner is bundled into one file with no `node_modules`, and this module
 * reaches only `pg`, `drizzle-orm`, the event contract and the shared
 * validation rules, while the package root also loads the native password
 * hashing.
 */
export * from './lib/account-verification/verify-account';
