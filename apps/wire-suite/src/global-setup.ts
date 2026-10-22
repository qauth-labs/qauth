import { readWireConfig } from './config';

/**
 * Vitest global setup for the wire suite.
 *
 * Runs once, before any test file is collected. A configuration problem — above
 * all a missing `QAUTH_WIRE_ALLOW_WRITES=1` — throws here, so the run stops
 * before it sends a request.
 */
export default function setup(): void {
  const config = readWireConfig();
  console.log(`wire-suite: target ${config.baseUrl} (admin ${config.adminUrl})`);
}
