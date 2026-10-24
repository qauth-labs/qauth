/**
 * The `events:verify-chain` command against real Postgres (issue #827): it
 * runs the script as the Nx target does and reads its exit code, so a
 * monitor can tell a broken chain (1) from a check that could not run (3).
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import path from 'node:path';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createEventsRepository, createRealmsRepository } from '../lib/repositories';
import { type IntegrationDb, setupIntegrationDb } from '../lib/repositories/integration-setup';
import type { AdminEventInput, DbTransaction } from '../types';
import { VERIFY_CHAIN_EXIT } from './event-chain';

/** `libs/infra/db`, the working directory of the Nx target. */
const PROJECT_DIR = path.resolve(__dirname, '..', '..');
const TSX = path.join(PROJECT_DIR, 'node_modules', '.bin', 'tsx');
const SCRIPT = 'src/scripts/verify-event-chain.ts';

/** Nothing listens on port 1: the connection is refused. */
const UNREACHABLE_URL = 'postgresql://qauth:qauth@127.0.0.1:1/qauth';

interface CliRun {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Run the documented command, `pnpm --dir libs/infra/db exec tsx
 * src/scripts/verify-event-chain.ts`: pnpm runs this tsx in this directory
 * and passes its exit code through. The Nx target would not: Nx reports every
 * failure as 1. Only PATH and DATABASE_URL are set.
 */
function verifyChain(databaseUrl: string, ...args: string[]): Promise<CliRun> {
  return new Promise((resolve) => {
    execFile(
      TSX,
      [SCRIPT, ...args],
      {
        cwd: PROJECT_DIR,
        env: { PATH: process.env['PATH'] ?? '', DATABASE_URL: databaseUrl },
        timeout: 60_000,
      },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === 'number' ? error.code : null;
        resolve({ code, stdout, stderr });
      }
    );
  });
}

describe('events:verify-chain (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  function integration(): IntegrationDb {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx;
  }

  /** A realm named `name` with three admin events, and their ids in chain order. */
  async function realmWithEvents(name: string): Promise<{ realmId: string; ids: string[] }> {
    const { db } = integration().database;
    const realm = await createRealmsRepository(db).create({ name });
    const store = createEventsRepository(db);
    const ids: string[] = [];
    for (let i = 0; i < 3; i += 1) {
      const input: AdminEventInput = {
        realm: realm.id,
        actor: { type: 'operator_cli', id: 'root' },
        operation: 'realms.mail.write',
        target: { type: 'realm', id: realm.id },
        before: { fromName: `Ops ${i}` },
        after: { fromName: `Ops ${i + 1}` },
      };
      ids.push(await db.transaction((tx: DbTransaction) => store.emitAdminEvent(tx, input)));
    }
    return { realmId: realm.id, ids };
  }

  it('exits 0 when the chain verifies, by name or by id', async () => {
    const { realmId } = await realmWithEvents('ops');
    const url = integration().connectionString;

    const byName = await verifyChain(url, '--realm=ops');
    expect(byName.code).toBe(VERIFY_CHAIN_EXIT.verified);
    expect(byName.stdout).toContain('verifies from its start: 3 admin event(s) checked');

    const byId = await verifyChain(url, `--realm-id=${realmId}`, '--json');
    expect(byId.code).toBe(VERIFY_CHAIN_EXIT.verified);
    expect(JSON.parse(byId.stdout)).toMatchObject({ ok: true, realmId, rowsChecked: 3 });
  });

  // The acceptance criterion of #827: 1 only for a break.
  it('exits 1 when the chain breaks', async () => {
    const { ids } = await realmWithEvents('ops');
    await integration().database.pool.query('DELETE FROM events WHERE id = $1', [ids[1]]);

    const run = await verifyChain(integration().connectionString, '--realm=ops');
    expect(run.code).toBe(VERIFY_CHAIN_EXIT.broken);
    expect(run.stdout).toContain(`BREAKS from its start, at event ${ids[2]}`);
  });

  it('exits 0 for a deleted realm that left its admin events, named by id', async () => {
    const { realmId } = await realmWithEvents('gone');
    await integration().database.pool.query('DELETE FROM realms WHERE id = $1', [realmId]);

    expect(
      await verifyChain(integration().connectionString, `--realm-id=${realmId}`)
    ).toMatchObject({ code: VERIFY_CHAIN_EXIT.verified });
  });

  // The acceptance criterion of #827: 3 for an unknown realm and for an
  // unreachable database, never 1.
  it('exits 3 for a realm name or id that nothing has', async () => {
    const url = integration().connectionString;

    const byName = await verifyChain(url, '--realm=nowhere');
    expect(byName).toMatchObject({ code: VERIFY_CHAIN_EXIT.cannotRun, stdout: '' });
    expect(byName.stderr).toContain('Realm "nowhere" not found');

    const id = randomUUID();
    const byId = await verifyChain(url, `--realm-id=${id}`, '--json');
    expect(byId).toMatchObject({ code: VERIFY_CHAIN_EXIT.cannotRun, stdout: '' });
    expect(byId.stderr).toContain(`Realm ${id} not found`);
  });

  it('exits 3 when the database cannot be reached', async () => {
    const run = await verifyChain(UNREACHABLE_URL, '--realm=ops');
    expect(run).toMatchObject({ code: VERIFY_CHAIN_EXIT.cannotRun, stdout: '' });
    expect(run.stderr).toContain('The chain could not be checked: connect ECONNREFUSED');
  });

  it('exits 2 on a usage error, before it connects', async () => {
    expect(await verifyChain(UNREACHABLE_URL, '--realm=a', '--fix')).toMatchObject({
      code: VERIFY_CHAIN_EXIT.usage,
    });
    expect(await verifyChain('', '--realm=a')).toMatchObject({ code: VERIFY_CHAIN_EXIT.usage });
  });
});
