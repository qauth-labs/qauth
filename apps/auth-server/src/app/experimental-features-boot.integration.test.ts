import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { DEFAULT_VCT } from '../testing/mock-wallet';

/**
 * The experimental-feature boot warning against a booted server (#476,
 * ADR-018 §5): a deployment that runs wallet sign-in under the
 * `oid4vp-1.0-base` verifier profile logs one `warn` line naming the item,
 * saying it may change in a minor release, and linking its docs section. A
 * deployment that does not, logs none.
 *
 * The unit tests (`config/experimental-features.test.ts`) check the line
 * itself; this suite checks that a real boot, with Postgres and Redis behind
 * it, writes it to the server's log.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

/** pino's numeric level for `warn`. */
const PINO_WARN_LEVEL = 40;

/** One parsed line of the server's own log. */
interface LogLine {
  readonly level: number;
  readonly msg?: string;
  readonly [key: string]: unknown;
}

const DOCS_LINK = 'https://docs.qauth.dev/reference/experimental-features/#oid4vp-10-base';

describe('the experimental-feature boot warning (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  /** Boot a deployment, collect what it logs at `warn` and up while booting, and close it. */
  async function bootLog(overrides: Record<string, string>): Promise<readonly LogLine[]> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    const log: LogLine[] = [];
    let booted: BootedAuthServer | undefined;
    try {
      booted = await bootAuthServer(
        { ...baseEnvironment(infra, jwt), ...overrides },
        { logStream: { write: (line) => log.push(JSON.parse(line) as LogLine) } }
      );
      return log;
    } finally {
      await booted?.close();
    }
  }

  const experimentalLines = (log: readonly LogLine[]) =>
    log.filter((line) => line['experimentalFeature'] !== undefined);

  // The acceptance criterion of #476.
  it('warns once at boot when wallet sign-in runs under oid4vp-1.0-base', async () => {
    const log = await bootLog({
      WALLET_FEDERATION_ENABLED: 'true',
      OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
      OID4VP_REQUESTED_VCT: DEFAULT_VCT,
      OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup',
      OID4VP_SUBJECT_BINDING_CLAIMS: 'given_name,family_name',
    });

    expect(experimentalLines(log)).toEqual([
      expect.objectContaining({
        level: PINO_WARN_LEVEL,
        experimentalFeature: 'oid4vp-1.0-base',
        docs: DOCS_LINK,
        msg: `Experimental feature oid4vp-1.0-base is on. It may change in a minor release, without a deprecation window. See ${DOCS_LINK}`,
      }),
    ]);
  });

  it('does not warn for a default deployment', async () => {
    const log = await bootLog({});

    expect(experimentalLines(log)).toEqual([]);
  });
});
