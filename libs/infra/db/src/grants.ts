/**
 * `@qauth-labs/infra-db/grants`: the service roles' database users and their
 * grants (issue #498), for the migration runner, and nothing else.
 *
 * A separate entry point for the reason `./migrations` is one: the migration
 * runner is bundled into one file with no `node_modules`, and this module
 * reaches only `pg` and Node itself, while the package root also loads the
 * repositories and their native password hashing.
 */
export * from './lib/database-users';
