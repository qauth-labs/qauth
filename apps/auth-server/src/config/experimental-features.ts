import {
  enabledExperimentalItems,
  experimentalBootWarning,
  type ExperimentalItem,
  type ExperimentalSwitches,
} from '@qauth-labs/shared-stability';

import { env } from './env';

/**
 * The experimental items of ADR-018 §4 that this deployment turns on, read
 * from its parsed configuration. The registry (`@qauth-labs/shared-stability`)
 * lists the items; this file says how the auth server reads each built one's
 * switch.
 */

/** The settings the switches below read. A new item adds the keys it reads. */
export type ExperimentalSwitchConfig = Pick<
  typeof env,
  'WALLET_FEDERATION_ENABLED' | 'OID4VP_VERIFIER_PROFILE'
>;

/**
 * One reader per built server item. The type names every built server item
 * of the registry, so building one without a reader here fails to compile.
 */
export const EXPERIMENTAL_SWITCHES: ExperimentalSwitches<ExperimentalSwitchConfig> = {
  // The base profile runs only when wallet sign-in is on; with it off, no
  // verifier runs, whatever the profile says.
  'oid4vp-1.0-base': (config) =>
    config.WALLET_FEDERATION_ENABLED && config.OID4VP_VERIFIER_PROFILE === 'oid4vp-1.0-base',
};

/**
 * The experimental items this deployment turns on, in registry order. The
 * server-info screen of the admin console lists them.
 */
export function listEnabledExperimental(
  config: ExperimentalSwitchConfig = env
): readonly ExperimentalItem[] {
  return enabledExperimentalItems(config, EXPERIMENTAL_SWITCHES);
}

/**
 * Log one `warn` line per experimental item that is on (ADR-018 §5), with the
 * item's id and its docs link. `app.ts` calls it once per boot.
 */
export function logExperimentalFeatures(
  log: { warn(object: object, message: string): void },
  config: ExperimentalSwitchConfig = env
): void {
  for (const item of listEnabledExperimental(config)) {
    const warning = experimentalBootWarning(item);
    log.warn({ experimentalFeature: warning.id, docs: warning.docs }, warning.message);
  }
}
