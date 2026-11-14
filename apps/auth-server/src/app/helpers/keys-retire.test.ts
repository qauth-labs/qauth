import {
  isOperationNonce,
  KEY_RETIRE_OPERATION,
  KeyChangeRefusedError,
  type KeyRetirementRecord,
  MAX_KID_LENGTH,
  OperationApprovalError,
} from '@qauth-labs/fastify-plugin-signer';
import { describe, expect, it, vi } from 'vitest';

import type { KeyRetirementOutcome, RetireKeyNowInput } from './key-retirement';
import {
  type CompromisedKey,
  describeKeysRetireError,
  formatKeyRetirement,
  hostKeyRetirementApproval,
  KEYS_RETIRE_SESSIONS_LEFT,
  KEYS_RETIRE_USAGE,
  KeysRetireUsageError,
  parseKeysRetireArguments,
  runKeysRetire,
} from './keys-retire';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const ACTIVATED = 1_790_000_000_000;
const CREATED = 1_789_000_000_000;

const RECORD: KeyRetirementRecord = {
  operation: KEY_RETIRE_OPERATION,
  approvalId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6ebb',
  actor: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' },
  operationDigest: Buffer.alloc(32, 0xab),
  realmId: REALM,
  purpose: 'token_signing',
  kid: 'ed-1',
  retiredAt: 1_800_000_000_000,
  retired: [{ kid: 'ed-1', algorithm: 'EdDSA', previousStatus: 'active', activateAt: ACTIVATED }],
  replacements: [{ kid: 'ed-2', algorithm: 'EdDSA' }],
  signedSince: ACTIVATED,
};

const OUTCOME: KeyRetirementOutcome = {
  record: RECORD,
  families: { families: 3, tokens: 7 },
  sessions: { ended: 5, batches: 1 },
};

/** The command over fakes: what it printed, and what it called. */
async function run(
  argv: readonly string[],
  answers: {
    retire?: (input: RetireKeyNowInput) => Promise<KeyRetirementOutcome>;
    compromised?: CompromisedKey | Error;
    sessions?: Error;
    realm?: string;
  } = {}
) {
  const out: string[] = [];
  const err: string[] = [];
  const retireKeyNow = vi.fn(
    answers.retire ??
      (async (input: RetireKeyNowInput) => {
        await input.approval.consume(Buffer.alloc(32), undefined as never);
        return OUTCOME;
      })
  );
  const findCompromisedKey = vi.fn(async (): Promise<CompromisedKey | undefined> => {
    if (answers.compromised instanceof Error) throw answers.compromised;
    return answers.compromised;
  });
  const revokeAllForRealm = vi.fn<
    (input: unknown) => Promise<{ readonly ended: number; readonly batches: number }>
  >(async () => {
    if (answers.sessions !== undefined) throw answers.sessions;
    return { ended: 4, batches: 1 };
  });
  const realmIdOf = vi.fn(async (name: string) =>
    name === (answers.realm ?? 'qauth') ? REALM : undefined
  );
  const code = await runKeysRetire(argv, 'qauth', {
    realmIdOf,
    retireKeyNow,
    findCompromisedKey,
    sessions: { revokeAllForRealm },
    operatingSystemUser: () => 'qauth-ops',
    out: (line) => out.push(line),
    err: (line) => err.push(line),
  });
  return { code, out, err, retireKeyNow, findCompromisedKey, revokeAllForRealm, realmIdOf };
}

describe('parseKeysRetireArguments', () => {
  it('reads --kid and --realm, the realm defaulting to DEFAULT_REALM_NAME', () => {
    expect(parseKeysRetireArguments(['--kid', 'ed-1', '--yes'], 'qauth')).toEqual({
      kid: 'ed-1',
      realmName: 'qauth',
    });
    expect(parseKeysRetireArguments(['--kid=ed-1', '--realm=acme', '--yes'], 'qauth')).toEqual({
      kid: 'ed-1',
      realmName: 'acme',
    });
  });

  it.each([
    [['--yes']],
    [['--kid', '', '--yes']],
    [['--kid', 'k'.repeat(MAX_KID_LENGTH + 1), '--yes']],
    [['--kid', 'ed-1']],
    [['--kid', 'ed-1', '--realm=', '--yes']],
    [['--kid', 'ed-1', '--yes', '--force']],
    [['ed-1', '--yes']],
  ])('refuses %j with the usage', (argv) => {
    expect(() => parseKeysRetireArguments(argv, 'qauth')).toThrow(KeysRetireUsageError);
    try {
      parseKeysRetireArguments(argv, 'qauth');
    } catch (error) {
      expect((error as Error).message).toContain(KEYS_RETIRE_USAGE);
    }
  });
});

describe('hostKeyRetirementApproval', () => {
  it('is a keys.retire approval by the operating-system user, with a fresh nonce, used once', async () => {
    const approval = hostKeyRetirementApproval('qauth-ops');
    const other = hostKeyRetirementApproval('qauth-ops');
    expect(approval.operation).toBe(KEY_RETIRE_OPERATION);
    expect(approval.requester).toEqual({ kind: 'break_glass', operatingSystemUser: 'qauth-ops' });
    expect(isOperationNonce(approval.nonce)).toBe(true);
    expect(approval.nonce).not.toBe(other.nonce);
    expect(approval.id).not.toBe(other.id);
    await approval.consume(Buffer.alloc(32), undefined as never);
    await expect(approval.consume(Buffer.alloc(32), undefined as never)).rejects.toBeInstanceOf(
      OperationApprovalError
    );
  });
});

describe('formatKeyRetirement', () => {
  it('prints the operation, the keys retired and created, and what was revoked, never key material', () => {
    const lines = formatKeyRetirement(OUTCOME);
    expect(lines[0]).toContain('keys.retire of kid ed-1');
    expect(lines[0]).toContain('qauth-ops on this host');
    expect(lines[0]).toContain('ab'.repeat(32));
    expect(lines).toContain('Retired ed-1 (EdDSA, was active): compromised.');
    expect(lines).toContain('Signing now with ed-2 (EdDSA).');
    expect(lines.join('\n')).toContain('Revoked 3 refresh token families (7 tokens)');
  });

  it('says so when no key was needed, and nothing revoked for a key that never signed', () => {
    const lines = formatKeyRetirement({
      ...OUTCOME,
      record: { ...RECORD, replacements: [], signedSince: null },
    });
    expect(lines).toContain(
      'No new key was needed: the realm went on signing with the key it had.'
    );
    expect(lines).toContain('The key never signed: no refresh token or session was revoked.');
  });
});

describe('the keys:retire command', () => {
  it('retires the key under a host approval bound to this user, prints the outcome and exits 0', async () => {
    const result = await run(['--kid', 'ed-1', '--yes']);
    expect(result.code).toBe(0);
    expect(result.err).toEqual([]);
    const input = result.retireKeyNow.mock.calls[0]?.[0];
    expect(input).toMatchObject({ realmId: REALM, kid: 'ed-1' });
    expect(input?.approval.requester).toEqual({
      kind: 'break_glass',
      operatingSystemUser: 'qauth-ops',
    });
    expect(result.out.at(-1)).toBe('Ended 5 browser sessions of the realm.');
  });

  it('exits 2 with the usage on a usage error, touching nothing', async () => {
    const result = await run(['--kid', 'ed-1']);
    expect(result.code).toBe(2);
    expect(result.err[0]).toContain(KEYS_RETIRE_USAGE);
    expect(result.realmIdOf).not.toHaveBeenCalled();
    expect(result.retireKeyNow).not.toHaveBeenCalled();
  });

  it('exits 1 for a realm that does not exist', async () => {
    const result = await run(['--kid', 'ed-1', '--realm', 'nowhere', '--yes']);
    expect(result.code).toBe(1);
    expect(result.err[0]).toContain("no realm is named 'nowhere'");
    expect(result.retireKeyNow).not.toHaveBeenCalled();
  });

  it('on a refusal, says why and that nothing changed, exiting 1', async () => {
    for (const refusal of [
      new KeyChangeRefusedError('UNKNOWN_KEY', 'The realm holds no key with that kid'),
      new OperationApprovalError('refused', 'A host approval is used once'),
    ]) {
      const result = await run(['--kid', 'ed-1', '--yes'], {
        retire: async () => {
          throw refusal;
        },
      });
      expect(result.code).toBe(1);
      expect(result.err).toEqual([`keys:retire: ${refusal.message}. Nothing was changed.`]);
      expect(result.findCompromisedKey).not.toHaveBeenCalled();
    }
  });

  it('for a key retired already, ends the sessions again since it began to sign, exiting 0', async () => {
    const result = await run(['--kid', 'ed-1', '--yes'], {
      retire: async () => {
        throw new KeyChangeRefusedError('ALREADY_COMPROMISED', 'The key is compromised already');
      },
      compromised: { activateAt: ACTIVATED, createdAt: CREATED },
    });
    expect(result.code).toBe(0);
    expect(result.revokeAllForRealm).toHaveBeenCalledWith({
      realmId: REALM,
      activeSince: ACTIVATED,
      reason: 'key_retired',
      actor: { type: 'operator_cli', id: 'qauth-ops' },
    });
    expect(result.out.at(-1)).toBe('Ended 4 browser sessions of the realm.');
  });

  it('for a key retired already that never had an activation time, ends the sessions since it was made', async () => {
    const result = await run(['--kid', 'ed-1', '--yes'], {
      retire: async () => {
        throw new KeyChangeRefusedError('ALREADY_COMPROMISED', 'The key is compromised already');
      },
      compromised: { activateAt: null, createdAt: CREATED },
    });
    expect(result.code).toBe(0);
    expect(result.revokeAllForRealm.mock.calls[0]?.[0]).toMatchObject({ activeSince: CREATED });
  });

  it('exits 3 when the sessions of a key retired already cannot be ended', async () => {
    const result = await run(['--kid', 'ed-1', '--yes'], {
      retire: async () => {
        throw new KeyChangeRefusedError('ALREADY_COMPROMISED', 'The key is compromised already');
      },
      compromised: { activateAt: ACTIVATED, createdAt: CREATED },
      sessions: new Error('sessions down'),
    });
    expect(result.code).toBe(KEYS_RETIRE_SESSIONS_LEFT);
    expect(result.err[0]).toContain('Run keys:retire again for the same kid.');
  });

  it('exits 3 when the retirement committed but the session sweep failed', async () => {
    const result = await run(['--kid', 'ed-1', '--yes'], {
      retire: async () => {
        throw new Error('sessions down');
      },
      compromised: { activateAt: ACTIVATED, createdAt: CREATED },
    });
    expect(result.code).toBe(KEYS_RETIRE_SESSIONS_LEFT);
    expect(result.err[0]).toContain('the key is retired');
  });

  it('exits 1 with nothing changed when the retirement failed before its commit', async () => {
    const result = await run(['--kid', 'ed-1', '--yes'], {
      retire: async () => {
        throw new Error('connection reset');
      },
    });
    expect(result.code).toBe(1);
    expect(result.err).toEqual(['keys:retire: Error: connection reset. Nothing was changed.']);
  });
});

describe('describeKeysRetireError', () => {
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
    const secret = Buffer.alloc(40, 0x5a).toString('hex');
    const printed = describeKeysRetireError(
      new DrizzleQueryError(
        'insert into "realm_keys"',
        [secret],
        new Error('canceling statement due to statement timeout')
      )
    );
    expect(printed).toBe(
      'the database refused a query: Error: canceling statement due to statement timeout'
    );
    expect(printed).not.toContain(secret);
    expect(describeKeysRetireError(new TypeError('bad'))).toBe('TypeError: bad');
  });
});
