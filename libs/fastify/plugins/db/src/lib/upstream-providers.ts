/**
 * The types of a realm's generic upstream OpenID Connect provider (#639), for
 * the sign-in flow and the admin API in the auth server, which may not import
 * the database library itself.
 */
export type {
  NewRealmUpstreamProvider,
  RealmUpstreamProvider,
  RealmUpstreamProviderChanges,
} from '@qauth-labs/infra-db';
