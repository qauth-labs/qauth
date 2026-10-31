/**
 * `@qauth-labs/infra-db/system-client`: the system client's provisioner
 * (issue #631), for the migration runner and the seed manifest, and nothing
 * else.
 *
 * A separate entry point for the reason `./migrations` is one: the migration
 * runner is bundled into one file with no `node_modules`, and this module
 * reaches only `pg`, `drizzle-orm`, the event contract and the shared
 * validation rules, while the package root also loads the native password
 * hashing.
 */
export * from './lib/system-client/provision';
