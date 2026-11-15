import { proveKeyCustody } from '@qauth-labs/fastify-plugin-signer';
import { BREAK_GLASS_COMMAND_NAMES } from '@qauth-labs/shared-events';
import { describe, expect, it, vi } from 'vitest';

import { TWO_ADMIN_WINDOW_MS } from '../admin/approvals/two-admin';
import {
  ADMIN_ENROLMENT_PAGE_PATH,
  BREAK_GLASS_COMMANDS,
  BREAK_GLASS_EXIT,
  BREAK_GLASS_USED_EVENT,
  breakGlassAuditEntry,
  type BreakGlassCommand,
  type BreakGlassDependencies,
  type BreakGlassRun,
  BreakGlassUsageError,
  type EnrolAdminDependencies,
  parseBreakGlassArguments,
  recordedArguments,
  runBreakGlass,
} from './break-glass';
import { hostOperator, runBreakGlassProcess } from './break-glass-host';
import { KEY_RETIRE_EFFECTS } from './key-retirement';
import type { KeysRetireDependencies } from './keys-retire';

/** The break-glass CLI (ADR-019 Decision 7, #602), with its dependencies faked. */

const REALM_ID = '0190a5b2-7c3d-7e4f-8a9b-0c1d2e3f4a5b';
const ACCOUNT_ID = '0190a5b2-7c3d-7e4f-8a9b-0c1d2e3f4a5c';
const GRANT_ID = '0190a5b2-7c3d-7e4f-8a9b-0c1d2e3f4a5d';
const ISSUER = 'https://acme.example.com';
const TOKEN = 'A'.repeat(43);
const NOW = 1_800_000_000_000;
const TX = { tx: 'the transaction' };
const OPERATOR = Object.freeze({ name: 'ops', uid: 1001, host: 'db-host-1' });
const KID = 'kid-1';
const DIGEST = Buffer.alloc(32, 7);

function parsed(argv: readonly string[]): BreakGlassCommand {
  const command = parseBreakGlassArguments(argv);
  if (command === 'help') throw new Error('help');
  return command;
}

/** A function a test does not expect to be called. */
function never(what: string) {
  return vi.fn(() => {
    throw new Error(`${what} was called`);
  });
}

describe('the command list', () => {
  it('holds exactly enrol-admin and retire-key, the event registry’s names', () => {
    expect(Object.keys(BREAK_GLASS_COMMANDS)).toEqual(['enrol-admin', 'retire-key']);
    expect(Object.keys(BREAK_GLASS_COMMANDS)).toEqual([...BREAK_GLASS_COMMAND_NAMES]);
  });

  it('takes exactly these options: none sets a password or carries a key', () => {
    expect(
      Object.fromEntries(
        Object.entries(BREAK_GLASS_COMMANDS).map(([name, spec]) => [
          name,
          Object.keys(spec.options),
        ])
      )
    ).toEqual({
      'enrol-admin': ['realm', 'role', 'expires-in'],
      'retire-key': ['realm', 'kid', 'confirm'],
    });
    for (const spec of Object.values(BREAK_GLASS_COMMANDS)) {
      for (const option of Object.keys(spec.options)) {
        expect(option).not.toMatch(/pass|secret|key|jwk|pem|private|import|file|credential/i);
      }
    }
  });

  it('refuses every other command', () => {
    for (const name of ['set-password', 'import-key', 'verify-account', 'enrol', 'Enrol-Admin']) {
      expect(() => parseBreakGlassArguments([name, '--realm', 'acme'])).toThrow(
        BreakGlassUsageError
      );
    }
  });
});

describe('parseBreakGlassArguments', () => {
  it('answers help for no command or a help flag', () => {
    for (const argv of [[], ['help'], ['--help'], ['-h']]) {
      expect(parseBreakGlassArguments(argv)).toBe('help');
    }
  });

  it('reads enrol-admin, an hour by default', () => {
    expect(parsed(['enrol-admin', '--realm', 'acme', '--role', 'security-admin'])).toEqual({
      name: 'enrol-admin',
      realmName: 'acme',
      role: 'security-admin',
      ttlMs: 60 * 60_000,
      arguments: { values: { realm: 'acme', role: 'security-admin' }, annotations: {} },
    });
    expect(
      parsed(['enrol-admin', '--realm=acme', '--role=viewer', '--expires-in=15'])
    ).toMatchObject({ role: 'viewer', ttlMs: 15 * 60_000 });
    expect(
      parsed(['enrol-admin', '--realm=a', '--role=editor', '--expires-in=1440'])
    ).toMatchObject({ ttlMs: 24 * 60 * 60_000 });
  });

  it('refuses a missing, empty or unknown option, a positional, a custom role and a bad expiry', () => {
    for (const argv of [
      ['enrol-admin', '--realm', 'acme'],
      ['enrol-admin', '--role', 'viewer'],
      ['enrol-admin', '--realm', '', '--role', 'viewer'],
      ['enrol-admin', '--realm', 'acme', '--role', 'owner'],
      ['enrol-admin', '--realm', 'acme', '--role', 'Viewer'],
      ['enrol-admin', '--realm', 'acme', '--role', 'viewer', '--password', 'x'],
      ['enrol-admin', '--realm', 'acme', '--role', 'viewer', 'extra'],
      ['enrol-admin', '--realm', 'acme', '--role', 'viewer', '--expires-in', '0'],
      ['enrol-admin', '--realm', 'acme', '--role', 'viewer', '--expires-in', '1441'],
      ['enrol-admin', '--realm', 'acme', '--role', 'viewer', '--expires-in', '1.5'],
      ['enrol-admin', '--realm', 'acme', '--role', 'viewer', '--expires-in', '060'],
      ['enrol-admin', '--realm', 'a'.repeat(256), '--role', 'viewer'],
    ]) {
      expect(() => parseBreakGlassArguments(argv), argv.join(' ')).toThrow(BreakGlassUsageError);
    }
  });

  it('reads retire-key, which needs --confirm and a kid', () => {
    expect(parsed(['retire-key', '--realm', 'acme', '--kid', KID, '--confirm'])).toEqual({
      name: 'retire-key',
      realmName: 'acme',
      kid: KID,
      arguments: { values: { realm: 'acme', kid: KID, confirm: true }, annotations: {} },
    });
    for (const argv of [
      ['retire-key', '--realm', 'acme', '--kid', KID],
      ['retire-key', '--kid', KID, '--confirm'],
      ['retire-key', '--realm', 'acme', '--kid', 'bad\u0007kid', '--confirm'],
      ['retire-key', '--realm', 'acme', '--kid', KID, '--confirm=yes'],
      ['retire-key', '--realm', 'acme', '--kid', KID, '--confirm', '--yes'],
    ]) {
      expect(() => parseBreakGlassArguments(argv), argv.join(' ')).toThrow(BreakGlassUsageError);
    }
  });
});

describe('the record of a run', () => {
  const run = (command: BreakGlassCommand): BreakGlassRun => ({
    id: 'run-1',
    command,
    operator: OPERATOR,
  });

  it('names the break-glass operator, the user and uid, the host, the command and its arguments', () => {
    const command = parsed(['enrol-admin', '--realm', 'acme', '--role', 'security-admin']);
    expect(breakGlassAuditEntry(run(command), REALM_ID, { account: { id: ACCOUNT_ID } })).toEqual({
      realmId: REALM_ID,
      actorKind: 'break_glass_operator',
      actorId: 'ops',
      actorRealmId: null,
      actChain: null,
      operationId: 'breakGlass.enrolAdmin',
      operationClass: 'security',
      effects: ['administration'],
      outcome: 'succeeded',
      diff: {
        change: {
          before: null,
          after: {
            run: {
              command: 'enrol-admin',
              arguments: { realm: 'acme', role: 'security-admin' },
              operatingSystemUser: { name: 'ops', uid: 1001 },
              host: 'db-host-1',
            },
            account: { id: ACCOUNT_ID },
          },
        },
        annotations: {},
      },
      approvals: [],
      requestDigest: null,
      traceId: 'run-1',
    });
    const retire = parsed(['retire-key', '--realm', 'acme', '--kid', KID, '--confirm']);
    expect(breakGlassAuditEntry(run(retire), REALM_ID, {}, DIGEST)).toMatchObject({
      operationId: 'breakGlass.retireKey',
      effects: [...KEY_RETIRE_EFFECTS],
      requestDigest: DIGEST,
    });
  });

  it('marks a secret argument for masking, by its path in the record', () => {
    const recorded = recordedArguments(
      {
        summary: 'a command with a secret option',
        options: {
          realm: { type: 'string', required: true, description: 'realm' },
          token: { type: 'string', required: true, secret: true, description: 'secret' },
        },
      },
      { realm: 'acme', token: 'hunter2' }
    );
    expect(recorded.annotations).toEqual({ 'arguments.token': 'secret' });
    const command = { ...parsed(['retire-key', '--realm=a', `--kid=${KID}`, '--confirm']) };
    const entry = breakGlassAuditEntry(
      run({ ...command, arguments: recorded } as BreakGlassCommand),
      REALM_ID,
      {}
    );
    expect(entry.diff?.annotations).toEqual({ 'run.arguments.token': 'secret' });
  });

  it('reads the operator from the operating system', () => {
    const operator = hostOperator();
    expect(operator.name).not.toBe('');
    expect(operator.host).not.toBe('');
    expect(operator.uid === null || Number.isInteger(operator.uid)).toBe(true);
  });
});

/** A log of what the fakes were asked to do, in order. */
function enrolmentFakes(
  log: string[],
  overrides: Partial<{ realm: object | undefined; appendFails: boolean; emitFails: boolean }> = {}
) {
  const realm =
    'realm' in overrides
      ? overrides.realm
      : { id: REALM_ID, name: 'acme', enabled: true, issuer: ISSUER };
  const appendAdminAudit = vi.fn<(tx: unknown, entry: unknown) => Promise<never>>(async (tx) => {
    log.push(`audit:${tx === TX}`);
    if (overrides.appendFails) throw new Error('audit log down');
    return {} as never;
  });
  const emit = vi.fn<(tx: unknown, event: unknown) => Promise<string>>(async (tx) => {
    log.push(`event:${tx === TX}`);
    if (overrides.emitFails) throw new Error('event log down');
    return 'event-id';
  });
  const deps: EnrolAdminDependencies = {
    adminAuditLog: { appendAdminAudit },
    events: { emit },
    transaction: vi.fn(async (work) => {
      log.push('begin');
      try {
        const result = await work(TX as never);
        log.push('commit');
        return result;
      } catch (error) {
        log.push('rollback');
        throw error;
      }
    }),
    realms: { findByName: vi.fn(async () => realm as never) },
    adminEnrolments: {
      newAccountId: () => ACCOUNT_ID,
      issue: vi.fn(async (enrolment, tx) => {
        log.push(`account+enrolment:${tx === TX}`);
        return {
          account: { id: enrolment.accountId, realmId: enrolment.realmId, createdAt: NOW },
          enrolment: {} as never,
          token: TOKEN,
        };
      }),
    },
    adminGrants: {
      create: vi.fn(async (_grant, tx) => {
        log.push(`grant:${tx === TX}`);
        return { id: GRANT_ID, createdAt: NOW + 5 } as never;
      }),
    },
    now: () => NOW,
  };
  return { deps, appendAdminAudit, emit };
}

function dependencies(overrides: Partial<BreakGlassDependencies> = {}): BreakGlassDependencies & {
  readonly out: ReturnType<typeof vi.fn>;
  readonly err: ReturnType<typeof vi.fn>;
} {
  return {
    proveKeyCustody: async () => undefined,
    operator: () => OPERATOR,
    newRunId: () => 'run-1',
    records: never('records'),
    enrolment: never('enrolment'),
    keysRetire: never('keysRetire'),
    out: vi.fn(),
    err: vi.fn(),
    ...overrides,
  } as BreakGlassDependencies & {
    readonly out: ReturnType<typeof vi.fn>;
    readonly err: ReturnType<typeof vi.fn>;
  };
}

describe('runBreakGlass: the KEK', () => {
  /** A KEK provider that reports itself unusable, or whose unwrap fails. */
  const failingProviders = {
    unusable: {
      name: 'fake',
      health: async () => ({ ok: false, provider: 'fake', reason: 'backend down' }),
      wrap: async () => {
        throw new Error('not used');
      },
      unwrap: async () => {
        throw new Error('not used');
      },
    },
    refusing: {
      name: 'fake',
      health: async () => ({ ok: true, provider: 'fake' }),
      wrap: async () => {
        throw new Error('not used');
      },
      unwrap: async () => {
        throw new Error('the KMS refused the unwrap');
      },
    },
  } as unknown as Record<string, Parameters<typeof proveKeyCustody>[0]>;

  const store = {
    listKekCanaries: async () => [{ realmId: REALM_ID, kid: KID }],
    getWrappedKey: async () =>
      ({
        realmId: REALM_ID,
        purpose: 'token_signing',
        scopeId: null,
        kid: KID,
        algorithm: 'EdDSA',
        status: 'active',
        kekRef: 'local:1',
        wrappedDek: Buffer.alloc(40),
        dekNonce: Buffer.alloc(12),
        ciphertext: Buffer.alloc(48),
      }) as never,
  };

  for (const [what, provider] of Object.entries(failingProviders)) {
    it(`exits 4 with nothing done when the provider is ${what}`, async () => {
      for (const argv of [
        ['enrol-admin', '--realm', 'acme', '--role', 'security-admin'],
        ['retire-key', '--realm', 'acme', '--kid', KID, '--confirm'],
      ]) {
        const deps = dependencies({ proveKeyCustody: () => proveKeyCustody(provider, store) });
        expect(await runBreakGlass(parsed(argv), deps)).toBe(BREAK_GLASS_EXIT.kekUnproven);
        expect(deps.err).toHaveBeenCalledWith(
          expect.stringMatching(/^break-glass: the KEK provider does not open a stored key/)
        );
        expect(deps.out).not.toHaveBeenCalled();
      }
    });
  }

  it('exits 4 when the KEK opens nothing: the database holds no key', async () => {
    const provider = { ...failingProviders['refusing'], health: async () => ({ ok: true }) };
    const deps = dependencies({
      proveKeyCustody: () =>
        proveKeyCustody(provider as never, {
          listKekCanaries: async () => [],
          getWrappedKey: async () => undefined,
        }),
    });
    expect(
      await runBreakGlass(parsed(['enrol-admin', '--realm=acme', '--role=viewer']), deps)
    ).toBe(BREAK_GLASS_EXIT.kekUnproven);
  });
});

describe('runBreakGlass: enrol-admin', () => {
  const command = () => parsed(['enrol-admin', '--realm', 'acme', '--role', 'security-admin']);

  it('records the run, then creates the account, the enrolment and the grant, in one transaction', async () => {
    const log: string[] = [];
    const { deps: enrolment, appendAdminAudit, emit } = enrolmentFakes(log);
    const deps = dependencies({ enrolment: () => enrolment });

    expect(await runBreakGlass(command(), deps)).toBe(BREAK_GLASS_EXIT.done);
    expect(log).toEqual([
      'begin',
      'audit:true',
      'event:true',
      'account+enrolment:true',
      'grant:true',
      'commit',
    ]);
    expect(appendAdminAudit.mock.calls[0]?.[1]).toMatchObject({
      realmId: REALM_ID,
      actorKind: 'break_glass_operator',
      operationId: 'breakGlass.enrolAdmin',
      traceId: 'run-1',
      diff: {
        change: {
          after: {
            run: { command: 'enrol-admin', host: 'db-host-1' },
            account: { id: ACCOUNT_ID, realmId: REALM_ID },
            grant: { role: 'security-admin', targetRealmId: REALM_ID },
            enrolment: { expiresAt: NOW + 60 * 60_000 },
          },
        },
      },
    });
    expect(emit.mock.calls[0]?.[1]).toEqual({
      type: BREAK_GLASS_USED_EVENT,
      realm: REALM_ID,
      actor: { type: 'operator_cli', id: 'ops' },
      data: { command: 'enrol-admin' },
    });
    expect(enrolment.adminGrants.create).toHaveBeenCalledWith(
      {
        userId: ACCOUNT_ID,
        role: { kind: 'built-in', name: 'security-admin' },
        targetRealmId: REALM_ID,
        createdBy: null,
      },
      TX
    );
    // The token is in nothing the record holds.
    expect(JSON.stringify(appendAdminAudit.mock.calls)).not.toContain(TOKEN);
    expect(JSON.stringify(emit.mock.calls)).not.toContain(TOKEN);

    const printed = deps.out.mock.calls.map(([line]) => line as string);
    expect(printed).toContain(`  ${ISSUER}${ADMIN_ENROLMENT_PAGE_PATH}#token=${TOKEN}`);
    expect(printed.filter((line) => line.includes(TOKEN))).toHaveLength(1);
    expect(printed.join('\n')).toContain(new Date(NOW + 60 * 60_000).toISOString());
    expect(printed.join('\n')).toContain(
      `cannot approve another admin's request before ${new Date(NOW + 5 + TWO_ADMIN_WINDOW_MS).toISOString()}`
    );
    expect(deps.err).not.toHaveBeenCalled();
  });

  for (const [what, overrides] of [
    ['the audit row', { appendFails: true }],
    ['the event', { emitFails: true }],
  ] as const) {
    it(`changes nothing when ${what} cannot be written`, async () => {
      const log: string[] = [];
      const { deps: enrolment } = enrolmentFakes(log, overrides);
      const deps = dependencies({ enrolment: () => enrolment });

      expect(await runBreakGlass(command(), deps)).toBe(BREAK_GLASS_EXIT.failed);
      expect(log).not.toContain('account+enrolment:true');
      expect(log).not.toContain('grant:true');
      expect(log.at(-1)).toBe('rollback');
      expect(deps.out).not.toHaveBeenCalled();
      expect(deps.err).toHaveBeenCalledWith(expect.stringMatching(/Nothing was changed\.$/));
    });
  }

  for (const [what, realm] of [
    ['an unknown realm', undefined],
    ['a disabled realm', { id: REALM_ID, name: 'acme', enabled: false, issuer: ISSUER }],
    ['a realm with no issuer', { id: REALM_ID, name: 'acme', enabled: true, issuer: null }],
  ] as const) {
    it(`refuses ${what} before it writes anything`, async () => {
      const log: string[] = [];
      const { deps: enrolment } = enrolmentFakes(log, { realm });
      const deps = dependencies({ enrolment: () => enrolment });

      expect(await runBreakGlass(command(), deps)).toBe(BREAK_GLASS_EXIT.failed);
      expect(log).toEqual([]);
      expect(deps.err).toHaveBeenCalledWith(expect.stringMatching(/^break-glass enrol-admin: /));
    });
  }
});

describe('runBreakGlass: retire-key', () => {
  const command = () => parsed(['retire-key', '--realm', 'acme', '--kid', KID, '--confirm']);

  function retireFakes(log: string[], appendFails = false) {
    const appendAdminAudit = vi.fn<(tx: unknown, entry: unknown) => Promise<never>>(async (tx) => {
      log.push(`audit:${tx === TX}`);
      if (appendFails) throw new Error('audit log down');
      return {} as never;
    });
    const emit = vi.fn<(tx: unknown, event: unknown) => Promise<string>>(async (tx) => {
      log.push(`event:${tx === TX}`);
      return 'event-id';
    });
    const retireKeyNow = vi.fn<KeysRetireDependencies['retireKeyNow']>(async (input) => {
      // As the key library does: the approval is consumed in the
      // transaction, before the first change.
      await input.approval.consume(DIGEST, TX as never);
      log.push('retired');
      return {
        record: {
          realmId: REALM_ID,
          kid: KID,
          actor: { kind: 'break_glass', operatingSystemUser: 'ops' },
          approvalId: 'approval-1',
          operationDigest: DIGEST,
          retired: [{ kid: KID, algorithm: 'EdDSA', previousStatus: 'active' }],
          replacements: [{ kid: 'kid-2', algorithm: 'EdDSA' }],
          signedSince: null,
          purpose: 'token_signing',
        },
        families: { families: 0, tokens: 0 },
        sessions: { ended: 0, batches: 0 },
      } as never;
    });
    const keysRetire: KeysRetireDependencies = {
      realmIdOf: async (name) => (name === 'acme' ? REALM_ID : undefined),
      retireKeyNow,
      findCompromisedKey: async () => undefined,
      recordRepeat: never('recordRepeat'),
      sessions: { revokeAllForRealm: never('revokeAllForRealm') },
      operatingSystemUser: () => 'ops',
      out: vi.fn(),
      err: vi.fn(),
    };
    return { appendAdminAudit, emit, keysRetire, retireKeyNow };
  }

  it('runs the emergency retirement, its record written when the approval is consumed, before the change', async () => {
    const log: string[] = [];
    const { appendAdminAudit, emit, keysRetire, retireKeyNow } = retireFakes(log);
    const deps = dependencies({
      records: () => ({ adminAuditLog: { appendAdminAudit }, events: { emit } }),
      keysRetire: () => keysRetire,
    });

    expect(await runBreakGlass(command(), deps)).toBe(BREAK_GLASS_EXIT.done);
    expect(retireKeyNow).toHaveBeenCalledTimes(1);
    expect(retireKeyNow.mock.calls[0]?.[0]).toMatchObject({ realmId: REALM_ID, kid: KID });
    expect(log).toEqual(['audit:true', 'event:true', 'retired']);
    expect(appendAdminAudit.mock.calls[0]?.[1]).toMatchObject({
      realmId: REALM_ID,
      operationId: 'breakGlass.retireKey',
      requestDigest: DIGEST,
      diff: {
        change: {
          after: {
            run: {
              command: 'retire-key',
              arguments: { realm: 'acme', kid: KID, confirm: true },
            },
            retirement: { kid: KID, operationDigest: DIGEST.toString('hex') },
          },
        },
      },
    });
    expect(emit.mock.calls[0]?.[1]).toMatchObject({ data: { command: 'retire-key' } });
  });

  it('changes nothing when its record cannot be written', async () => {
    const log: string[] = [];
    const { appendAdminAudit, emit, keysRetire } = retireFakes(log, true);
    const deps = dependencies({
      records: () => ({ adminAuditLog: { appendAdminAudit }, events: { emit } }),
      keysRetire: () => keysRetire,
    });

    expect(await runBreakGlass(command(), deps)).toBe(BREAK_GLASS_EXIT.failed);
    expect(log).toEqual(['audit:true']);
    expect(keysRetire.err).toHaveBeenCalledWith(
      expect.stringMatching(/^break-glass retire-key: .*Nothing was changed\.$/)
    );
  });
});

describe('runBreakGlassProcess', () => {
  const io = () => ({ out: vi.fn(), err: vi.fn() });

  it('prints the usage for help, and exits 2 on a usage error, before it reads anything', async () => {
    const help = io();
    expect(await runBreakGlassProcess(['--help'], {}, help)).toBe(BREAK_GLASS_EXIT.done);
    expect(help.out).toHaveBeenCalledWith(expect.stringMatching(/^Usage: break-glass enrol-admin/));

    const usage = io();
    expect(
      await runBreakGlassProcess(['set-password', '--realm', 'acme'], { DATABASE_URL: 'x' }, usage)
    ).toBe(BREAK_GLASS_EXIT.usage);
    expect(usage.err).toHaveBeenCalledWith(expect.stringContaining('is not a break-glass command'));
  });

  it('exits 2 without DATABASE_URL, before it connects', async () => {
    for (const environ of [{}, { DATABASE_URL: '' }, { DATABASE_URL: '  ' }]) {
      const written = io();
      expect(
        await runBreakGlassProcess(
          ['enrol-admin', '--realm', 'acme', '--role', 'security-admin'],
          environ,
          written
        )
      ).toBe(BREAK_GLASS_EXIT.usage);
      expect(written.err).toHaveBeenCalledWith(
        expect.stringMatching(/^break-glass: set DATABASE_URL/)
      );
      expect(written.out).not.toHaveBeenCalled();
    }
  });
});
