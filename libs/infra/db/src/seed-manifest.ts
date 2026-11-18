/**
 * `@qauth-labs/infra-db/seed-manifest`: the schema of the
 * `db:seed-oauth-clients` manifest and of each of its sections, for the
 * declarative realm file (`@qauth-labs/realm-file`, issue #515), whose
 * `clients`, `cimd_clients`, `resources` and `system_client` sections are the
 * manifest's own, so that a manifest stays a valid realm file (ADR-018 §5).
 *
 * A separate entry point, like `./system-client`: it loads what the system
 * client's provisioner loads (`pg`, `drizzle-orm`, the event contract and the
 * shared validation rules), never the native password hashing that the package
 * root loads. Loading it opens no connection.
 */
export * from './scripts/seed-manifest';

// What the realm file needs beside the sections: the values of a client's
// `environment` (ADR-008), which the realm file adds to a `clients` entry, and
// the public-key rule of a `jwks` entry, which its JSON Schema states as well.
export { environmentEnum } from './lib/schema/enums';
export { publicJwkSchema } from './lib/system-client/public-jwk';
