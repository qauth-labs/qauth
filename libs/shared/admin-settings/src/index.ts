import realmPolicySettings from './lib/realm-policy-settings.json';
import type { RealmPolicySettingsFile } from './lib/settings';

export type * from './lib/settings';

/**
 * The realm policy settings, as generated from the realm policy schema
 * (`@qauth-labs/server-realm-policy`, `pnpm nx test server-realm-policy -- -u`).
 */
export const REALM_POLICY_SETTINGS = realmPolicySettings as RealmPolicySettingsFile;
