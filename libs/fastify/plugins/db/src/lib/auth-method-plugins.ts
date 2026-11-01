/**
 * The types of a realm's state of an AuthMethod plugin (#600), for the
 * plugin runtime and the admin API in the auth server, which may not import
 * the database library itself.
 */
export type {
  RealmAuthMethodPlugin,
  RealmAuthMethodPluginExpectedVersion,
  RealmAuthMethodPluginState,
} from '@qauth-labs/infra-db';
