import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

import { isKid } from '@qauth-labs/fastify-plugin-signer';
import { BREAK_GLASS_COMMAND_NAMES } from '@qauth-labs/shared-events';
import type { FastifyInstance } from 'fastify';

import { TWO_ADMIN_WINDOW_MS } from '../admin/approvals/two-admin';
import { BUILT_IN_ROLE_NAMES, type BuiltInRoleName } from './admin-roles';
import { KEY_RETIRE_EFFECTS } from './key-retirement';
import {
  type AuditTransaction,
  describeKeysRetireError,
  type KeysRetireDependencies,
  runKeysRetire,
} from './keys-retire';
import { buildRealmUrl } from './realm-url';

/**
 * THE BREAK-GLASS CLI (ADR-019 Decisions 7 and 9, issue #602):
 * `auth-server:break-glass`, the way in when no admin can act, run on a host
 * that holds the database credentials and the KEK.
 *
 * It has two commands and no other (`BREAK_GLASS_COMMANDS`):
 *
 * - `enrol-admin` creates an admin account with no password and no
 *   credential, its grant, and a one-time enrolment URL it prints once. The
 *   account registers its first passkey through that URL (#621), and cannot
 *   approve another admin's request for 7 days (`TWO_ADMIN_WINDOW_MS`, the
 *   two-admin rule's window, which reads the account's and the grant's
 *   creation).
 * - `retire-key` runs the emergency key retirement (#551), as
 *   `keys:retire` does, and nothing else.
 *
 * No command sets a password or imports a key. The process opens no
 * listener and makes no HTTP call: it connects to the database, and for
 * `retire-key` to Redis, whose sessions the retirement ends.
 *
 * It starts only when `DATABASE_URL` is set and the KEK provider opens a
 * stored key (`proveHostKeyCustody`). Whoever holds the host and the KEK
 * stands outside the two-admin rule, so every run that changes anything is
 * recorded and announced first: in the transaction of the change and before
 * it, an admin audit row of the realm (actor kind `break_glass_operator`,
 * the operating-system user and uid, the host name, the command and its
 * arguments, a secret one masked) and a critical `admin.break_glass_used`
 * event, which every event route of the realm sends. If either cannot be
 * written, the run aborts with nothing changed. A run refused before any
 * change (an unknown realm or kid, a usage error, a KEK that opens nothing)
 * writes nothing.
 *
 * Everything but the process's wiring (`break-glass-host.ts`) is here: a
 * unit test runs the commands with their dependencies faked, and an
 * integration test over a booted server's.
 */

/** One option of a command. */
export interface BreakGlassOption {
  readonly type: 'string' | 'boolean';
  readonly required: boolean;
  /** A value the audit row records masked. No option of today's commands is one. */
  readonly secret?: true;
  readonly description: string;
}

/** One command of the group. */
export interface BreakGlassCommandSpec {
  readonly summary: string;
  readonly options: Readonly<Record<string, BreakGlassOption>>;
}

/** A command's name. */
export type BreakGlassCommandName = (typeof BREAK_GLASS_COMMAND_NAMES)[number];

/** The longest an enrolment URL may be valid, in minutes: a day. */
export const MAX_ENROLMENT_MINUTES = 24 * 60;

/** How long an enrolment URL is valid by default, in minutes: an hour. */
export const DEFAULT_ENROLMENT_MINUTES = 60;

/**
 * THE COMMAND LIST: exactly these two (ADR-019 Decision 7). The event that
 * announces a run names the command from the same list
 * (`BREAK_GLASS_COMMAND_NAMES` of the event registry). A command that set a
 * password or imported a key would hand the host's holder a credential or a
 * key that no record shows: there is none.
 */
export const BREAK_GLASS_COMMANDS = Object.freeze({
  'enrol-admin': Object.freeze({
    summary:
      'Create an admin account with no password and no credential, its admin grant on the realm, ' +
      'and a one-time enrolment URL, printed once.',
    options: Object.freeze({
      realm: Object.freeze({
        type: 'string',
        required: true,
        description: 'The realm the account lives in and administers, by name.',
      }),
      role: Object.freeze({
        type: 'string',
        required: true,
        description: `A built-in admin role: ${BUILT_IN_ROLE_NAMES.join(', ')}.`,
      }),
      'expires-in': Object.freeze({
        type: 'string',
        required: false,
        description: `Minutes until the URL expires, 1 to ${MAX_ENROLMENT_MINUTES}. Default: ${DEFAULT_ENROLMENT_MINUTES}.`,
      }),
    }),
  }),
  'retire-key': Object.freeze({
    summary:
      'Retire a token-signing key at once because it may be compromised, as keys:retire does.',
    options: Object.freeze({
      realm: Object.freeze({
        type: 'string',
        required: true,
        description: "The key's realm, by name.",
      }),
      kid: Object.freeze({
        type: 'string',
        required: true,
        description: 'The kid of the key to retire, as the realm’s JWKS lists it.',
      }),
      confirm: Object.freeze({
        type: 'boolean',
        required: true,
        description:
          'Confirm: the key leaves at once, and the sessions of the realm used since it began to sign end.',
      }),
    }),
  }),
} satisfies Record<BreakGlassCommandName, BreakGlassCommandSpec>);

/** The page that turns an enrolment URL into the account's first passkey (#621), on the realm's issuer. */
export const ADMIN_ENROLMENT_PAGE_PATH = '/ui/admin-enrolment';

/** The operation ids the audit row of a run names, by command. */
export const BREAK_GLASS_OPERATIONS = Object.freeze({
  'enrol-admin': 'breakGlass.enrolAdmin',
  'retire-key': 'breakGlass.retireKey',
} satisfies Record<BreakGlassCommandName, string>);

/** The effects a run's audit row carries (ADR-019 Decision 7), by command. */
const BREAK_GLASS_EFFECTS: Readonly<Record<BreakGlassCommandName, readonly string[]>> =
  Object.freeze({
    'enrol-admin': Object.freeze(['administration']),
    'retire-key': KEY_RETIRE_EFFECTS,
  });

/** The event type that announces a run. */
export const BREAK_GLASS_USED_EVENT = 'urn:qauth:event:admin.break_glass_used:v1-rc.0' as const;

/** Exit codes. */
export const BREAK_GLASS_EXIT = Object.freeze({
  done: 0,
  /** Refused or failed, with nothing changed. */
  failed: 1,
  /** A usage error, or no `DATABASE_URL`. */
  usage: 2,
  /** `retire-key`: the key is retired, or may be, but its sessions were not all ended. Run it again. */
  sessionsLeft: 3,
  /** The KEK provider does not open a stored key: nothing was done. */
  kekUnproven: 4,
});

export const BREAK_GLASS_USAGE = `Usage: break-glass enrol-admin --realm <name> --role <role> [--expires-in <minutes>]
       break-glass retire-key --realm <name> --kid <kid> --confirm

The way in when no admin can act (ADR-019 Decision 7). Run it on a host that holds the database
credentials and the KEK, with the server's environment: DATABASE_URL (a role that may write the
realm's accounts, admin grants, keys, tokens and sessions, the admin audit log and the events: the
owner's, not one process role's in a split deployment), the KEK (KEK, KEK_PATH or a key service
adapter's settings), and for retire-key Redis. It starts only when the KEK opens a stored key.

enrol-admin   ${BREAK_GLASS_COMMANDS['enrol-admin'].summary}
  --realm       ${BREAK_GLASS_COMMANDS['enrol-admin'].options.realm.description}
  --role        ${BREAK_GLASS_COMMANDS['enrol-admin'].options.role.description}
  --expires-in  ${BREAK_GLASS_COMMANDS['enrol-admin'].options['expires-in'].description}
              The URL works once. Whoever opens it registers the account's first passkey, so hand
              it to the new admin only, over a channel you trust. The account cannot approve another
              admin's request for 7 days.

retire-key    ${BREAK_GLASS_COMMANDS['retire-key'].summary}
  --realm       ${BREAK_GLASS_COMMANDS['retire-key'].options.realm.description}
  --kid         ${BREAK_GLASS_COMMANDS['retire-key'].options.kid.description}
  --confirm     ${BREAK_GLASS_COMMANDS['retire-key'].options.confirm.description}

Every run that changes anything writes, before the change and in its transaction, an admin audit
row of the realm (the operating-system user and uid, the host name, the command and its arguments)
and a critical admin.break_glass_used event, which every event route of the realm sends. If either
cannot be written, nothing changes. No command sets a password or imports a key.

Exit codes: 0 done, 1 refused or failed with nothing changed, 2 a usage error or no DATABASE_URL,
3 retire-key must run again (the key is retired, or may be, but its sessions were not all ended),
4 the KEK does not open a stored key.

Example:

  pnpm nx run auth-server:break-glass -- enrol-admin --realm=operator --role=security-admin`;

/** Thrown for arguments the group does not take; the message ends with the usage. */
export class BreakGlassUsageError extends Error {
  constructor(problem: string) {
    super(`${problem}\n\n${BREAK_GLASS_USAGE}`);
    this.name = 'BreakGlassUsageError';
  }
}

/** A run's arguments as the audit row records them: by option, a secret one masked. */
export interface RecordedArguments {
  readonly values: Readonly<Record<string, string | boolean>>;
  /** The field marks `maskSecrets` reads, by path inside the recorded run. */
  readonly annotations: Readonly<Record<string, 'secret'>>;
}

/** What the group was asked to do. */
export type BreakGlassCommand =
  | {
      readonly name: 'enrol-admin';
      readonly realmName: string;
      readonly role: BuiltInRoleName;
      /** How long the URL is valid, in ms. */
      readonly ttlMs: number;
      readonly arguments: RecordedArguments;
    }
  | {
      readonly name: 'retire-key';
      readonly realmName: string;
      readonly kid: string;
      readonly arguments: RecordedArguments;
    };

/**
 * The arguments of `spec`'s options as recorded, under `arguments.<option>`,
 * each secret one marked for `maskSecrets`.
 */
export function recordedArguments(
  spec: BreakGlassCommandSpec,
  values: Readonly<Record<string, string | boolean | undefined>>
): RecordedArguments {
  const recorded: Record<string, string | boolean> = {};
  const annotations: Record<string, 'secret'> = {};
  for (const [option, definition] of Object.entries(spec.options)) {
    const value = values[option];
    if (value === undefined) continue;
    recorded[option] = value;
    if (definition.secret === true) annotations[`arguments.${option}`] = 'secret';
  }
  return Object.freeze({
    values: Object.freeze(recorded),
    annotations: Object.freeze(annotations),
  });
}

function isCommandName(name: string): name is BreakGlassCommandName {
  return Object.hasOwn(BREAK_GLASS_COMMANDS, name);
}

/**
 * Read the group's arguments: the command, then its options.
 *
 * @returns `'help'` for no command, `help`, `--help` or `-h`
 * @throws BreakGlassUsageError for an unknown command or option, a
 *   positional argument, a missing or malformed option
 */
export function parseBreakGlassArguments(argv: readonly string[]): BreakGlassCommand | 'help' {
  const [name, ...rest] = argv;
  if (name === undefined || name === 'help' || name === '--help' || name === '-h') return 'help';
  if (!isCommandName(name)) {
    throw new BreakGlassUsageError(
      `'${name}' is not a break-glass command: the commands are ${Object.keys(BREAK_GLASS_COMMANDS).join(' and ')}.`
    );
  }
  const spec: BreakGlassCommandSpec = BREAK_GLASS_COMMANDS[name];
  let values: Record<string, string | boolean | undefined>;
  try {
    values = parseArgs({
      args: rest,
      options: Object.fromEntries(
        Object.entries(spec.options).map(([option, { type }]) => [option, { type }])
      ),
      strict: true,
      allowPositionals: false,
    }).values as Record<string, string | boolean | undefined>;
  } catch (error) {
    throw new BreakGlassUsageError(error instanceof Error ? error.message : String(error));
  }
  for (const [option, definition] of Object.entries(spec.options)) {
    if (definition.required && values[option] === undefined) {
      throw new BreakGlassUsageError(`--${option} is required: ${definition.description}`);
    }
  }
  const realmName = values['realm'];
  if (typeof realmName !== 'string' || realmName.length === 0 || realmName.length > 255) {
    throw new BreakGlassUsageError('--realm is a realm name.');
  }
  const recorded = recordedArguments(spec, values);

  if (name === 'enrol-admin') {
    const role = BUILT_IN_ROLE_NAMES.find((builtIn) => builtIn === values['role']);
    if (role === undefined) {
      throw new BreakGlassUsageError(
        `--role is a built-in admin role: ${BUILT_IN_ROLE_NAMES.join(', ')}.`
      );
    }
    const expiresIn = values['expires-in'];
    let minutes = DEFAULT_ENROLMENT_MINUTES;
    if (expiresIn !== undefined) {
      minutes = /^[1-9][0-9]{0,3}$/.test(String(expiresIn)) ? Number(expiresIn) : Number.NaN;
      if (!(minutes >= 1 && minutes <= MAX_ENROLMENT_MINUTES)) {
        throw new BreakGlassUsageError(
          `--expires-in is a whole number of minutes, 1 to ${MAX_ENROLMENT_MINUTES}.`
        );
      }
    }
    return Object.freeze({
      name,
      realmName,
      role,
      ttlMs: minutes * 60_000,
      arguments: recorded,
    });
  }

  const kid = values['kid'];
  if (typeof kid !== 'string' || !isKid(kid)) {
    throw new BreakGlassUsageError('--kid is the kid of the key, as the JWKS lists it.');
  }
  if (values['confirm'] !== true) {
    throw new BreakGlassUsageError(
      `--confirm is required: ${BREAK_GLASS_COMMANDS['retire-key'].options.confirm.description}`
    );
  }
  return Object.freeze({ name, realmName, kid, arguments: recorded });
}

/** Who ran the command, and where, as the operating system names them. */
export interface BreakGlassOperator {
  /** The operating-system user's name, or `uid:<uid>` when it has none. */
  readonly name: string;
  /** The user's id, or `null` where the platform has none. */
  readonly uid: number | null;
  /** The host's name. */
  readonly host: string;
}

/** One run of a command, as its record names it. */
export interface BreakGlassRun {
  /** A fresh id: the audit row's trace id, which the printed report names too. */
  readonly id: string;
  readonly command: BreakGlassCommand;
  readonly operator: BreakGlassOperator;
}

/** The admin audit log's entry type. */
type AdminAuditEntry = Parameters<
  FastifyInstance['repositories']['adminAuditLog']['appendAdminAudit']
>[1];

/** A JSON object, as a diff holds it. */
type JsonObject = NonNullable<NonNullable<AdminAuditEntry['diff']>['change']['after']>;

/**
 * The admin audit row of a run, written before the change: who ran which
 * command with which arguments on which host, and what the run is about to
 * change (`change`).
 */
export function breakGlassAuditEntry(
  run: BreakGlassRun,
  realmId: string,
  change: JsonObject,
  requestDigest: Buffer | null = null
): AdminAuditEntry {
  const { command, operator } = run;
  return {
    realmId,
    actorKind: 'break_glass_operator',
    actorId: operator.name,
    actorRealmId: null,
    actChain: null,
    operationId: BREAK_GLASS_OPERATIONS[command.name],
    operationClass: 'security',
    effects: [...BREAK_GLASS_EFFECTS[command.name]],
    outcome: 'succeeded',
    diff: {
      change: {
        before: null,
        after: {
          run: {
            command: command.name,
            arguments: { ...command.arguments.values },
            operatingSystemUser: { name: operator.name, uid: operator.uid },
            host: operator.host,
          },
          ...change,
        },
      },
      annotations: Object.fromEntries(
        Object.entries(command.arguments.annotations).map(([path, mark]) => [`run.${path}`, mark])
      ),
    },
    approvals: [],
    requestDigest,
    traceId: run.id,
  };
}

/** The `admin.break_glass_used` event of a run. */
export function breakGlassUsedEvent(run: BreakGlassRun, realmId: string) {
  return {
    type: BREAK_GLASS_USED_EVENT,
    realm: realmId,
    actor: { type: 'operator_cli' as const, id: run.operator.name },
    data: { command: run.command.name },
  };
}

/** What a run's record writes to. */
export interface BreakGlassRecordDependencies {
  readonly adminAuditLog: Pick<
    FastifyInstance['repositories']['adminAuditLog'],
    'appendAdminAudit'
  >;
  readonly events: Pick<FastifyInstance['repositories']['events'], 'emit'>;
}

/**
 * Record a run in `tx`, before its change: the admin audit row, then the
 * event. Each throws when it cannot be written, which aborts the
 * transaction and so the change.
 */
export async function recordBreakGlassRun(
  deps: BreakGlassRecordDependencies,
  tx: AuditTransaction,
  run: BreakGlassRun,
  realmId: string,
  change: JsonObject,
  requestDigest: Buffer | null = null
): Promise<void> {
  await deps.adminAuditLog.appendAdminAudit(
    tx,
    breakGlassAuditEntry(run, realmId, change, requestDigest)
  );
  await deps.events.emit(tx, breakGlassUsedEvent(run, realmId));
}

/** What `enrol-admin` reads and writes. */
export interface EnrolAdminDependencies extends BreakGlassRecordDependencies {
  readonly transaction: <T>(work: (tx: AuditTransaction) => Promise<T>) => Promise<T>;
  readonly realms: Pick<FastifyInstance['repositories']['realms'], 'findByName'>;
  readonly adminEnrolments: Pick<
    FastifyInstance['repositories']['adminEnrolments'],
    'newAccountId' | 'issue'
  >;
  readonly adminGrants: Pick<FastifyInstance['repositories']['adminGrants'], 'create'>;
  /** The clock, in epoch ms. */
  readonly now: () => number;
}

/** What `enrol-admin` made. */
export interface EnrolledAdmin {
  readonly realm: { readonly id: string; readonly name: string };
  readonly accountId: string;
  readonly grantId: string;
  readonly role: BuiltInRoleName;
  readonly createdAt: number;
  readonly expiresAt: number;
  /** The enrolment URL: the only copy of the token. Print it once and keep it nowhere. */
  readonly url: string;
  /** From this moment the account may approve another admin's request (the two-admin rule's rule 3). */
  readonly approvesFrom: number;
}

/** Why `enrol-admin` refused a realm, with nothing changed. */
export class EnrolAdminRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EnrolAdminRefusedError';
  }
}

/**
 * Enrol an admin: in one transaction, the run's record, then the account
 * with no password and no credential, its enrolment token (only its hash is
 * stored) and its grant on the realm. The enrolment URL starts at the
 * realm's issuer, from the realm row; its token travels in the fragment, so
 * no server, proxy or `Referer` sees it.
 *
 * @throws EnrolAdminRefusedError for an unknown or disabled realm, or one
 *   with no issuer, with nothing written
 * @throws the repositories' errors, with nothing written
 */
export async function enrolAdmin(
  deps: EnrolAdminDependencies,
  run: BreakGlassRun & { readonly command: Extract<BreakGlassCommand, { name: 'enrol-admin' }> }
): Promise<EnrolledAdmin> {
  const { command } = run;
  const realm = await deps.realms.findByName(command.realmName);
  if (realm === undefined) {
    throw new EnrolAdminRefusedError(`no realm is named '${command.realmName}'`);
  }
  if (!realm.enabled) {
    throw new EnrolAdminRefusedError(`the realm '${realm.name}' is disabled`);
  }
  if (realm.issuer === null) {
    throw new EnrolAdminRefusedError(
      `the realm '${realm.name}' has no issuer, so no enrolment URL can be built for it`
    );
  }
  const accountId = deps.adminEnrolments.newAccountId();
  const createdAt = deps.now();
  const expiresAt = createdAt + command.ttlMs;

  const written = await deps.transaction(async (tx) => {
    await recordBreakGlassRun(deps, tx, run, realm.id, {
      account: { id: accountId, realmId: realm.id },
      grant: { role: command.role, targetRealmId: realm.id },
      enrolment: { expiresAt },
    });
    const issued = await deps.adminEnrolments.issue(
      { realmId: realm.id, accountId, createdAt, expiresAt },
      tx
    );
    const grant = await deps.adminGrants.create(
      {
        userId: issued.account.id,
        role: { kind: 'built-in', name: command.role },
        targetRealmId: realm.id,
        createdBy: null,
      },
      tx
    );
    return { issued, grant };
  });

  return Object.freeze({
    realm: { id: realm.id, name: realm.name },
    accountId: written.issued.account.id,
    grantId: written.grant.id,
    role: command.role,
    createdAt,
    expiresAt,
    url: buildRealmUrl(realm, `${ADMIN_ENROLMENT_PAGE_PATH}#token=${written.issued.token}`),
    // The later of the account's and the grant's creation, plus the window.
    approvesFrom: Math.max(createdAt, written.grant.createdAt) + TWO_ADMIN_WINDOW_MS,
  });
}

/** What the group reads and writes, besides its arguments. */
export interface BreakGlassDependencies {
  /** Resolve when the host's KEK opens a stored key (`proveHostKeyCustody`). */
  readonly proveKeyCustody: () => Promise<void>;
  /** Who runs the command, and where. */
  readonly operator: () => BreakGlassOperator;
  /** A fresh run id. Default: a random UUID. */
  readonly newRunId?: () => string;
  /** Where a run's record is written: this host's admin audit log and event log. */
  readonly records: () => BreakGlassRecordDependencies;
  /** `enrol-admin`'s dependencies, over this host's database. */
  readonly enrolment: () => EnrolAdminDependencies;
  /** `keys:retire`'s dependencies, over this host's database, Redis and KEK. */
  readonly keysRetire: () => KeysRetireDependencies;
  /** Writes one line of the report. */
  readonly out: (line: string) => void;
  /** Writes one line of an error. */
  readonly err: (line: string) => void;
}

/** An epoch-ms time as the group prints it. */
function isoTime(ms: number): string {
  return new Date(ms).toISOString();
}

/**
 * Run a parsed command: prove the KEK, then run it.
 *
 * @returns the exit code ({@link BREAK_GLASS_EXIT})
 */
export async function runBreakGlass(
  command: BreakGlassCommand,
  deps: BreakGlassDependencies
): Promise<number> {
  try {
    await deps.proveKeyCustody();
  } catch (error) {
    deps.err(
      `break-glass: the KEK provider does not open a stored key (${describeKeysRetireError(error)}). ` +
        'The command runs only on a host that holds the KEK. Nothing was done.'
    );
    return BREAK_GLASS_EXIT.kekUnproven;
  }
  const run: BreakGlassRun = Object.freeze({
    id: (deps.newRunId ?? randomUUID)(),
    command,
    operator: deps.operator(),
  });

  if (command.name === 'retire-key') {
    const records = deps.records();
    return runKeysRetire(
      ['--kid', command.kid, '--realm', command.realmName, '--yes'],
      command.realmName,
      deps.keysRetire(),
      {
        command: 'break-glass retire-key',
        recordUse: (tx, use) =>
          recordBreakGlassRun(
            records,
            tx,
            run,
            use.realmId,
            { retirement: { kid: use.kid, operationDigest: use.operationDigest.toString('hex') } },
            use.operationDigest
          ),
      }
    );
  }

  let enrolled: EnrolledAdmin;
  try {
    enrolled = await enrolAdmin(deps.enrolment(), { ...run, command });
  } catch (error) {
    const reason =
      error instanceof EnrolAdminRefusedError ? error.message : describeKeysRetireError(error);
    deps.err(`break-glass enrol-admin: ${reason}. Nothing was changed.`);
    return BREAK_GLASS_EXIT.failed;
  }
  deps.out(
    `Enrolled admin account ${enrolled.accountId} in realm ${enrolled.realm.name} ` +
      `(${enrolled.realm.id}) with the role ${enrolled.role}, run ${run.id} by ` +
      `${run.operator.name} on ${run.operator.host}.`
  );
  deps.out(
    `Enrolment URL, valid once until ${isoTime(enrolled.expiresAt)}. It is shown only now and ` +
      'stored nowhere: hand it to the new admin only, over a channel you trust.'
  );
  deps.out('');
  deps.out(`  ${enrolled.url}`);
  deps.out('');
  deps.out(
    `The account cannot approve another admin's request before ${isoTime(enrolled.approvesFrom)} ` +
      '(7 days). Recorded in the admin audit log as breakGlass.enrolAdmin, and announced as ' +
      'admin.break_glass_used.'
  );
  return BREAK_GLASS_EXIT.done;
}
