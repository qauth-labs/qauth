import { readUpgradeConfig } from './config';

/**
 * Vitest global setup for the upgrade steps.
 *
 * Runs once, before any test file is collected. A configuration problem — above
 * all a missing `QAUTH_UPGRADE_ALLOW_WRITES=1` — throws here, so the run stops
 * before it sends a request or opens a database connection.
 */
export default function setup(): void {
  const config = readUpgradeConfig();
  console.log(`upgrade-test: target ${config.baseUrl}, state file ${config.statePath}`);
}
