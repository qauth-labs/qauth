import {
  isOperationNonce,
  KEK_ROTATE_OPERATION,
  type KekRefCensus,
  KekRewrapRefusedError,
  type KekRewrapReport,
  type KekRotationRecord,
  type RotateKekInput,
} from '@qauth-labs/fastify-plugin-signer';
import { describe, expect, it, vi } from 'vitest';

import {
  describeKeysRewrapError,
  formatKekRefCounts,
  hostKekRotationApproval,
  type KekRotationAuditLog,
  KEYS_REWRAP_INCOMPLETE,
  KEYS_REWRAP_USAGE,
  KeysRewrapUsageError,
  parseKeysRewrapArguments,
  recordHostKekRotation,
  runKeysRewrap,
} from './keys-rewrap';

const OLD = '3f1c0b2a9d8e7f60';
const NEW = 'a1b2c3d4e5f60718';
const STRANGER = 'deadbeefdeadbeef';
const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
/** Stands for the transaction that uses the approval up. */
const TX = Object.freeze({ transaction: 'consume' });

const START: KekRotationRecord = {
  operation: KEK_ROTATE_OPERATION,
  approvalId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6ebb',
  actor: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' },
  operationDigest: Buffer.alloc(32, 0xab),
  from: OLD,
  to: NEW,
  rows: 104,
};

function report(overrides: Partial<KekRewrapReport> = {}): KekRewrapReport {
  return {
    ...START,
    rewrapped: 100,
    moved: 4,
    failures: [],
    kekRefs: [{ kekRef: NEW, rows: 104, current: true, opens: true }],
    complete: true,
    ...overrides,
  };
}

/** The command over fakes: what it printed, and the input the re-wrap got. */
async function run(
  argv: readonly string[],
  answers: {
    rotate?: (input: RotateKekInput) => Promise<KekRewrapReport>;
    census?: readonly KekRefCensus[] | Error;
    record?: number | Error;
  } = {}
) {
  const out: string[] = [];
  const err: string[] = [];
  const rotateKek = vi.fn(
    answers.rotate ??
      (async (input: RotateKekInput) => {
        await input.approval.consume(Buffer.alloc(32), undefined as never);
        await input.onAudit(START, TX as never);
        return report();
      })
  );
  const recordRotation = vi.fn(async (): Promise<number> => {
    if (answers.record instanceof Error) throw answers.record;
    return answers.record ?? 3;
  });
  const countKeysPerKek = vi.fn(async () => {
    if (answers.census instanceof Error) throw answers.census;
    return answers.census ?? [];
  });
  const code = await runKeysRewrap(argv, {
    rotateKek,
    recordRotation,
    countKeysPerKek,
    operatingSystemUser: () => 'qauth-ops',
    out: (line) => out.push(line),
    err: (line) => err.push(line),
  });
  return { code, out, err, rotateKek, recordRotation, countKeysPerKek };
}

describe('parseKeysRewrapArguments', () => {
  it('reads --from, and --to when given', () => {
    expect(parseKeysRewrapArguments([`--from=${OLD}`])).toEqual({ mode: 'rewrap', from: OLD });
    expect(parseKeysRewrapArguments(['--from', OLD, '--to', NEW])).toEqual({
      mode: 'rewrap',
      from: OLD,
      to: NEW,
    });
    expect(parseKeysRewrapArguments(['--status'])).toEqual({ mode: 'status' });
  });

  it.each([
    [[], '--from is required'],
    [['--from='], '--from is required'],
    [[`--from=${OLD}`, '--to='], '--to is a kek_ref'],
    [['--status', `--from=${OLD}`], '--status takes no other option'],
    [[`--from=${OLD}`, '--kek=secret'], "Unknown option '--kek'"],
    [[`--from=${OLD}`, 'extra'], 'extra'],
  ])('refuses %j with the usage', (argv, problem) => {
    let error: unknown;
    try {
      parseKeysRewrapArguments(argv);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(KeysRewrapUsageError);
    expect((error as Error).message).toContain(problem);
    expect((error as Error).message).toContain(KEYS_REWRAP_USAGE);
  });
});

describe('hostKekRotationApproval', () => {
  it('is a kek.rotate approval by the operating-system user, with a fresh nonce, used once', async () => {
    const approval = hostKekRotationApproval('qauth-ops');
    const other = hostKekRotationApproval('qauth-ops');

    expect(approval).toMatchObject({
      operation: 'kek.rotate',
      requester: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' },
    });
    expect(approval.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(isOperationNonce(approval.nonce)).toBe(true);
    expect(other.nonce).not.toBe(approval.nonce);
    await expect(approval.consume(Buffer.alloc(32), undefined as never)).resolves.toBeUndefined();
    await expect(approval.consume(Buffer.alloc(32), undefined as never)).rejects.toThrow(
      'used once'
    );
  });
});

describe('formatKekRefCounts', () => {
  it('prints one line per kek_ref with its count and what this host does with it', () => {
    expect(
      formatKekRefCounts([
        { kekRef: OLD, rows: 7, current: false, opens: true },
        { kekRef: NEW, rows: 104, current: true, opens: true },
        { kekRef: STRANGER, rows: 2, current: false, opens: false, reason: 'KEK_UNKNOWN_REF' },
        { kekRef: 'vanished', rows: 1, current: false, opens: null },
      ])
    ).toEqual([
      'kek_ref           keys  on this host',
      '3f1c0b2a9d8e7f60     7  opens',
      'a1b2c3d4e5f60718   104  wraps new keys, opens',
      'deadbeefdeadbeef     2  cannot open (KEK_UNKNOWN_REF)',
      'vanished             1  not checked: no key of it could be read',
    ]);
    expect(formatKekRefCounts([])).toEqual(['No key is stored.']);
  });
});

describe('recordHostKekRotation', () => {
  function auditLog(realms: readonly string[]) {
    const entries: {
      tx: unknown;
      entry: Parameters<KekRotationAuditLog['appendAdminAudit']>[1];
    }[] = [];
    const pages: (string | null)[] = [];
    const log: KekRotationAuditLog = {
      listRealmIds: async (after, limit, tx) => {
        expect(tx).toBe(TX);
        pages.push(after);
        const start = after === null ? 0 : realms.indexOf(after) + 1;
        return realms.slice(start, start + limit);
      },
      appendAdminAudit: async (tx, entry) => {
        entries.push({ tx, entry });
      },
    };
    return { log, entries, pages };
  }

  it("writes one row per realm that holds a key, naming the host's user, the references and the digest", async () => {
    const realms = ['0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01', '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02'];
    const { log, entries } = auditLog(realms);

    await expect(recordHostKekRotation(log, START, TX as never)).resolves.toBe(2);

    expect(entries.map(({ tx }) => tx)).toEqual([TX, TX]);
    expect(entries.map(({ entry }) => entry.realmId)).toEqual(realms);
    expect(entries[0].entry).toEqual({
      realmId: realms[0],
      actorKind: 'break_glass_operator',
      actorId: 'qauth-ops',
      actorRealmId: null,
      actChain: null,
      operationId: 'kek.rotate',
      operationClass: 'security',
      effects: ['key-custody'],
      outcome: 'succeeded',
      diff: { change: { before: { kekRef: OLD }, after: { kekRef: NEW } }, annotations: {} },
      approvals: [],
      requestDigest: START.operationDigest,
      traceId: START.approvalId,
    });
  });

  it('pages through the realms, and records nothing in a store without keys', async () => {
    const many = Array.from(
      { length: 1001 },
      (_, index) => `0190d7a2-6f4e-7c1a-9b3e-${index.toString(16).padStart(12, '0')}`
    );
    const paged = auditLog(many);
    await expect(recordHostKekRotation(paged.log, START, TX as never)).resolves.toBe(1001);
    expect(paged.pages).toEqual([null, many[499], many[999]]);

    const empty = auditLog([]);
    await expect(recordHostKekRotation(empty.log, START, TX as never)).resolves.toBe(0);
    expect(empty.entries).toEqual([]);
  });

  it("refuses a record whose actor is not this host's operator", async () => {
    const { log, entries } = auditLog(['0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01']);
    const human: KekRotationRecord = {
      ...START,
      actor: { kind: 'human', realmId: REALM, accountId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6ecc' },
    };

    await expect(recordHostKekRotation(log, human, TX as never)).rejects.toThrow(TypeError);
    expect(entries).toEqual([]);
  });
});

describe('describeKeysRewrapError', () => {
  it("prints a failed query's database error, never its parameters", () => {
    class DrizzleQueryError extends Error {
      constructor(
        readonly query: string,
        readonly params: unknown[],
        override readonly cause: Error
      ) {
        super(`Failed query: ${query}\nparams: ${params.join(',')}`);
      }
    }
    const wrapped = Buffer.alloc(40, 0x5a).toString('hex');
    const failed = new DrizzleQueryError(
      'update "realm_keys" set "wrapped_dek" = $1',
      [wrapped],
      new Error('canceling statement due to statement timeout')
    );

    const printed = describeKeysRewrapError(failed);

    expect(printed).toBe(
      'the database refused a query: Error: canceling statement due to statement timeout'
    );
    expect(printed).not.toContain(wrapped);
    expect(describeKeysRewrapError(new TypeError('bad'))).toBe('TypeError: bad');
  });
});

describe('the keys:rewrap command', () => {
  it('prints the start record, the per-kek_ref counts and that KEK_PREVIOUS can go', async () => {
    const { code, out, err, rotateKek, recordRotation } = await run([`--from=${OLD}`]);

    expect(code).toBe(0);
    expect(err).toEqual([]);
    // Recorded in the audit log in the transaction that used the approval up.
    expect(recordRotation).toHaveBeenCalledWith(START, TX);
    // `--to` absent: the wiring re-wraps to the KEK this host wraps under.
    const [input] = rotateKek.mock.calls[0];
    expect(input).toMatchObject({ from: OLD });
    expect(input).not.toHaveProperty('to');
    expect(input.approval.requester).toEqual({
      kind: 'break_glass',
      operatingSystemUser: 'qauth-ops',
    });
    expect(out).toEqual([
      `kek.rotate from ${OLD} to ${NEW}, by qauth-ops on this host, approval ${START.approvalId}, ` +
        `operation digest ${'ab'.repeat(32)}: 104 keys to re-wrap.`,
      'Recorded in the admin audit log of 3 realms.',
      `Re-wrapped 100 keys from ${OLD} to ${NEW}; 4 were moved or deleted by another writer first.`,
      '',
      'Stored keys per kek_ref:',
      'kek_ref           keys  on this host',
      'a1b2c3d4e5f60718   104  wraps new keys, opens',
      '',
      `Every stored key is wrapped under ${NEW}, and this host opened a key of it.`,
      expect.stringContaining('It is safe to remove KEK_PREVIOUS'),
    ]);
  });

  it('passes --to on, and prints what keeps KEK_PREVIOUS, exiting 3', async () => {
    const { code, out, rotateKek } = await run([`--from=${OLD}`, `--to=${NEW}`], {
      rotate: async () =>
        report({
          rewrapped: 98,
          moved: 0,
          complete: false,
          failures: [{ realmId: REALM, kid: 'kid-9', code: 'KEY_DECRYPTION_FAILED' }],
          kekRefs: [
            { kekRef: OLD, rows: 1, current: false, opens: true },
            { kekRef: NEW, rows: 98, current: true, opens: true },
            { kekRef: STRANGER, rows: 5, current: false, opens: false, reason: 'KEK_UNKNOWN_REF' },
          ],
        }),
    });

    expect(code).toBe(KEYS_REWRAP_INCOMPLETE);
    expect(rotateKek.mock.calls[0][0]).toMatchObject({ from: OLD, to: NEW });
    expect(out).toEqual(
      expect.arrayContaining([
        `Did not open under ${OLD}: realm ${REALM}, kid kid-9 (KEY_DECRYPTION_FAILED).`,
        'kek_ref           keys  on this host',
        '3f1c0b2a9d8e7f60     1  opens',
        'a1b2c3d4e5f60718    98  wraps new keys, opens',
        'deadbeefdeadbeef     5  cannot open (KEK_UNKNOWN_REF)',
        'Do not remove KEK_PREVIOUS yet:',
        `- 1 stored keys are still wrapped under ${OLD}.`,
        expect.stringContaining(`- 5 stored keys are wrapped under ${STRANGER}, which this host`),
        `- 1 keys did not open under ${OLD}; they stay wrapped under it.`,
      ])
    );
    expect(out.join('\n')).not.toContain('It is safe to remove');
  });

  it('names keys left under a third KEK the host opens, and does not say KEK_PREVIOUS can go', async () => {
    const THIRD = '0011223344556677';
    const { code, out } = await run([`--from=${OLD}`], {
      rotate: async () =>
        report({
          complete: false,
          kekRefs: [
            { kekRef: NEW, rows: 100, current: true, opens: true },
            { kekRef: THIRD, rows: 4, current: false, opens: true },
          ],
        }),
    });

    expect(code).toBe(KEYS_REWRAP_INCOMPLETE);
    expect(out).toContain(
      `- 4 stored keys are wrapped under ${THIRD}, another old KEK: re-wrap them with --from=${THIRD}.`
    );
    expect(out.join('\n')).not.toContain('It is safe to remove');
  });

  it('with --status, prints the per-kek_ref counts and re-wraps nothing', async () => {
    const { code, out, rotateKek } = await run(['--status'], {
      census: [
        { kekRef: OLD, rows: 3, current: false, opens: true },
        { kekRef: NEW, rows: 1, current: true, opens: true },
      ],
    });

    expect(code).toBe(0);
    expect(rotateKek).not.toHaveBeenCalled();
    expect(out).toEqual([
      'Stored keys per kek_ref:',
      'kek_ref           keys  on this host',
      '3f1c0b2a9d8e7f60     3  opens',
      'a1b2c3d4e5f60718     1  wraps new keys, opens',
    ]);
  });

  it('on a refusal or a stopped run, says why and where the keys stand, exiting 1', async () => {
    const { code, out, err } = await run([`--from=${OLD}`], {
      rotate: async () => {
        throw new KekRewrapRefusedError(
          'FROM_KEK_NOT_HELD',
          `This node holds no KEK named '${OLD}'`
        );
      },
      census: [{ kekRef: OLD, rows: 4, current: false, opens: false, reason: 'KEK_UNKNOWN_REF' }],
    });

    expect(code).toBe(1);
    expect(out).toEqual([]);
    expect(err).toEqual([
      `keys:rewrap: This node holds no KEK named '${OLD}'`,
      'Stored keys per kek_ref:',
      'kek_ref           keys  on this host',
      '3f1c0b2a9d8e7f60     4  cannot open (KEK_UNKNOWN_REF)',
    ]);

    const failed = await run([`--from=${OLD}`], {
      rotate: async () => {
        throw new Error('connection terminated');
      },
      census: new Error('connection terminated'),
    });
    expect(failed.code).toBe(1);
    expect(failed.err).toEqual(['keys:rewrap: Error: connection terminated']);
  });

  it('stops with nothing moved when the audit row cannot be written, exiting 1', async () => {
    let movedAnyKey = false;
    const { code, out, err } = await run([`--from=${OLD}`], {
      record: new Error('permission denied for table admin_audit_log'),
      rotate: async (input) => {
        await input.onAudit(START, TX as never);
        movedAnyKey = true;
        return report();
      },
      census: [{ kekRef: OLD, rows: 104, current: false, opens: true }],
    });

    expect(code).toBe(1);
    expect(movedAnyKey).toBe(false);
    expect(out).toEqual([]);
    expect(err[0]).toBe('keys:rewrap: Error: permission denied for table admin_audit_log');
  });

  it('exits 2 with the usage on a usage error, touching nothing', async () => {
    const { code, err, rotateKek, countKeysPerKek } = await run([]);

    expect(code).toBe(2);
    expect(err[0]).toContain('--from is required');
    expect(rotateKek).not.toHaveBeenCalled();
    expect(countKeysPerKek).not.toHaveBeenCalled();
  });
});
