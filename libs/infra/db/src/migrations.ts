/**
 * `@qauth-labs/infra-db/migrations`: the migration runner's work and the
 * pending-migration check (issue #474), and nothing else.
 *
 * A separate entry point because the migration runner is bundled into one
 * file with no `node_modules`: this module reaches only `pg`, `drizzle-orm`
 * and Node itself, while the package root also loads the repositories and
 * their native password hashing.
 */
export * from './lib/migrations';
