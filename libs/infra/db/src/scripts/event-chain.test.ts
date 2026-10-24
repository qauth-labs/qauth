import { describe, expect, it } from 'vitest';

import type { EventChainReport } from '../types';
import { chainReportJson, describeChainReport, parseVerifyChainArgs } from './event-chain';

/**
 * The `events:verify-chain` command's arguments and output (issue #459). The
 * container suite proves `verifyChain` itself.
 */
const argv = (...args: string[]) => ['node', 'verify-event-chain.ts', ...args];
const REALM_ID = '0192f1c4-1111-7000-8000-000000000001';
const HASH = 'ab'.repeat(32);

describe('parseVerifyChainArgs', () => {
  it('takes a realm by name or by id, a starting point and --json', () => {
    expect(parseVerifyChainArgs(argv('--realm=default'))).toEqual({
      realm: 'default',
      json: false,
    });
    expect(
      parseVerifyChainArgs(
        argv(`--realm-id=${REALM_ID}`, '--from-seq=42', `--from-hash=${HASH}`, '--json')
      )
    ).toEqual({ realmId: REALM_ID, from: { seq: 42n, hash: HASH }, json: true });
  });

  it.each([
    ['no realm', []],
    ['two realms', ['--realm=a', `--realm-id=${REALM_ID}`]],
    ['half a starting point', ['--realm=a', '--from-seq=1']],
    ['a seq that is not a number', ['--realm=a', '--from-seq=-1', `--from-hash=${HASH}`]],
    ['a hash that is not 64 hex digits', ['--realm=a', '--from-seq=1', '--from-hash=abc']],
    ['a realm id that is not a UUID', ['--realm-id=default']],
    ['an unknown flag', ['--realm=a', '--fix']],
  ])('refuses %s', (_label, args) => {
    expect(parseVerifyChainArgs(argv(...args))).toBeNull();
  });
});

describe('describeChainReport', () => {
  it('reports a chain that verifies, with the head to start from next time', () => {
    const report: EventChainReport = {
      ok: true,
      realmId: REALM_ID,
      from: { seq: 0n, hash: '00'.repeat(32) },
      rowsChecked: 3,
      head: { id: 'e3', seq: 9n, hash: HASH },
    };
    const lines = describeChainReport(report, 'default');
    expect(lines[0]).toContain('verifies from its start: 3 admin event(s) checked');
    expect(lines[1]).toBe(`Head: event e3, --from-seq=9 --from-hash=${HASH}`);
  });

  // The acceptance of #459's CLI task: it reports the first broken row.
  it('reports the first event that breaks the chain, and why', () => {
    const report: EventChainReport = {
      ok: false,
      realmId: REALM_ID,
      from: { seq: 5n, hash: HASH },
      rowsChecked: 2,
      break: { id: 'e8', seq: 8n, reason: 'prev_hash_mismatch' },
    };
    const lines = describeChainReport(report, 'default');
    expect(lines[0]).toBe(
      `The admin event chain of realm default BREAKS after seq 5 (hash ${HASH}), at event e8 (seq 8):`
    );
    expect(lines[1]).toContain('an event before it was removed');
    expect(
      describeChainReport(
        { ...report, break: { id: null, seq: 5n, reason: 'anchor_missing' } },
        'default'
      )
    ).toEqual([
      `The admin event chain of realm default BREAKS after seq 5 (hash ${HASH}), at seq 5:`,
      'the admin event at the starting point is gone: the chain was cut back to before it.',
      '2 admin event(s) before it verified.',
    ]);
    expect(JSON.parse(chainReportJson(report))).toMatchObject({
      ok: false,
      break: { id: 'e8', seq: '8', reason: 'prev_hash_mismatch' },
    });
  });
});
