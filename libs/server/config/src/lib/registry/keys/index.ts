import type { ConfigKey } from '../types';
import { ACCOUNT_KEYS } from './accounts';
import { AUTH_SERVER_KEYS } from './auth-server';
import { DEVELOPER_PORTAL_KEYS } from './developer-portal';
import { FEDERATION_KEYS } from './federation';
import { RATE_LIMIT_KEYS } from './rate-limits';
import { REGISTRATION_KEYS } from './registration';
import { SERVER_KEYS } from './server';
import { STORAGE_KEYS } from './storage';
import { TOKEN_KEYS } from './tokens';

export { AUTH_SERVER_KEYS, DEVELOPER_PORTAL_KEYS };

/**
 * The keys this library's env schemas define (`src/lib/schemas/*.ts`). The
 * registry test checks both directions against those schemas.
 */
export const SERVER_CONFIG_KEYS: readonly ConfigKey[] = [
  ...SERVER_KEYS,
  ...STORAGE_KEYS,
  ...TOKEN_KEYS,
  ...ACCOUNT_KEYS,
  ...REGISTRATION_KEYS,
  ...RATE_LIMIT_KEYS,
  ...FEDERATION_KEYS,
];

/**
 * Every configuration key QAuth reads, with its tier, role, default and
 * meaning (ADR-018 §5).
 *
 * A pull request that adds, renames or removes a key changes this registry in
 * the same pull request: the key goes into the file for its area, and
 * `pnpm nx test server-config -- -u` regenerates the configuration page.
 */
export const CONFIG_KEY_REGISTRY: readonly ConfigKey[] = [
  ...SERVER_CONFIG_KEYS,
  ...AUTH_SERVER_KEYS,
  ...DEVELOPER_PORTAL_KEYS,
];
