import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

import {
  type CompromisedKey,
  compromisedKeyOf,
  isKid,
  KEY_RETIRE_OPERATION,
  KeyChangeRefusedError,
  keyRetirementOperation,
  newOperationNonce,
  OperationApprovalError,
  operationDigest,
  retireKey,
} from '@qauth-labs/fastify-plugin-signer';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

import { invalidateKeyDenylist } from './key-denylist';
import {
  type KeyRetirementOutcome,
  type KeyRetirementRepeat,
  recordKeyRetirementRepeat,
  retireKeyNow,
  type RetireKeyNowInput,
  revokeSessionsOfRetiredKey,
} from './key-retirement';

export type { CompromisedKey };

/**
 * The break-glass command `auth-server:keys:retire` (ADR-019 Decisions 7 and
 * 9, issue #551): retire a realm's token-signing key at once, on a host that
 * holds the database credentials and the KEK, when the key may be
 * compromised.
 *
 * Everything but the plugins' registration is here: a unit test runs the
 * command with its dependencies faked, and an integration test runs it with
 * {@link keysRetireDependencies} over a booted server's.
 */

export const KEYS_RETIRE_USAGE = `Usage: keys:retire --kid <kid> [--realm <name>] --yes

Retire a token-signing key at once because it may be compromised (ADR-019 Decision 9). In one
transaction the key, and its hybrid partner, are marked compromised and leave the realm's JWKS,
their kids go on the denylist every verifier checks, a new key signs in place of an active one with
no pre-publication, and every refresh token family of the realm created or used since the key began
to sign is revoked, Authority Trees included. Then every browser session of the realm used since
then is ended, with back-channel logout. A critical security event names each retired kid.

Every node refuses the key's tokens within seconds. A relying party that cached the JWKS keeps the
key until it fetches the JWKS again, unless it acts on the security event.

  --kid    The kid of the key to retire, as the realm's JWKS lists it.
  --realm  The realm's name. Default: DEFAULT_REALM_NAME.
  --yes    Confirm: signing in again is required for everyone whose session ends.

Run it again for a key retired already to end the sessions again, if a run stopped before it ended
them: the run is recorded and announced too. Exit codes: 0 done, 3 run it again (the key is
retired, or may be, but its sessions were not all ended), 2 a usage error, 1 any other error, with
nothing changed.

Example:

  pnpm nx run auth-server:keys:retire --kid=<kid> --yes`;

/** Thrown for arguments the command does not take; the message ends with the usage. */
export class KeysRetireUsageError extends Error {
  constructor(problem: string) {
    super(`${problem}\n\n${KEYS_RETIRE_USAGE}`);
    this.name = 'KeysRetireUsageError';
  }
}

/** What the command was asked to do. */
export interface KeysRetireCommand {
  readonly kid: string;
  readonly realmName: string;
}

/**
 * Read the command's arguments.
 *
 * @throws KeysRetireUsageError for an unknown option, a missing or malformed
 *   `--kid`, an empty `--realm`, or no `--yes`
 */
export function parseKeysRetireArguments(
  argv: readonly string[],
  defaultRealmName: string
): KeysRetireCommand {
  let values: { kid?: string; realm?: string; yes?: boolean };
  try {
    ({ values } = parseArgs({
      args: [...argv],
      options: {
        kid: { type: 'string' },
        realm: { type: 'string' },
        yes: { type: 'boolean' },
      },
      strict: true,
      allowPositionals: false,
    }));
  } catch (error) {
    throw new KeysRetireUsageError(error instanceof Error ? error.message : String(error));
  }
  const { kid, realm, yes } = values;
  if (kid === undefined || !isKid(kid)) {
    throw new KeysRetireUsageError('--kid is required: the kid of the key, as the JWKS lists it.');
  }
  if (realm !== undefined && realm.length === 0) {
    throw new KeysRetireUsageError('--realm is a realm name.');
  }
  if (yes !== true) {
    throw new KeysRetireUsageError(
      '--yes is required: the key leaves at once, and the sessions of the realm used since it began to sign end.'
    );
  }
  return { kid, realmName: realm ?? defaultRealmName };
}

/**
 * The approval the command runs the retirement under, made on the host.
 *
 * An emergency retirement is a security operation (ADR-019 Decisions 7 and
 * 9). From the admin API it runs only under an approval its approvers gave.
 * This command runs where the database credentials and the KEK are: whoever
 * holds them can open and replace every stored key whatever an approval
 * says, and stands outside the approval rule (ADR-019 Decision 7), so the
 * command approves its own run. The approval is still bound to the
 * retirement it runs (the realm, the kid, the operating-system user and a
 * fresh nonce) and is used once; the run is recorded in the realm's admin
 * audit log and announced by a critical security event.
 */
export function hostKeyRetirementApproval(
  operatingSystemUser: string,
  onConsume?: (operationDigest: Buffer, tx: AuditTransaction) => Promise<void>
): RetireKeyNowInput['approval'] {
  let used = false;
  return Object.freeze({
    id: randomUUID(),
    operation: KEY_RETIRE_OPERATION,
    requester: Object.freeze({ kind: 'break_glass' as const, operatingSystemUser }),
    nonce: newOperationNonce(),
    async consume(digest: Buffer, tx: unknown): Promise<void> {
      if (used) throw new OperationApprovalError('refused', 'A host approval is used once');
      used = true;
      // The key library consumes the approval inside the retirement's
      // transaction, after its reads and before its first change: what the
      // hook writes commits with the change, or neither does.
      await onConsume?.(Buffer.from(digest), tx as AuditTransaction);
    },
  });
}

/** The transaction the admin audit log and the event log write in. */
export type AuditTransaction = Parameters<
  FastifyInstance['repositories']['adminAuditLog']['appendAdminAudit']
>[0];

/**
 * What a run writes before it changes anything, in the transaction of the
 * change (the break-glass CLI's record of its run, #602): called once the
 * key is found and before it is marked compromised, or, for a key
 * compromised already, before the run is recorded again. A failure aborts
 * the run with nothing changed.
 */
export type KeysRetireRecordUse = (
  tx: AuditTransaction,
  use: { readonly realmId: string; readonly kid: string; readonly operationDigest: Buffer }
) => Promise<void>;

/** How the command is run: by itself, or as the break-glass CLI's `retire-key`. */
export interface KeysRetireOptions {
  /** The command's name, as its messages name it. Default: `keys:retire`. */
  readonly command?: string;
  /** Writes the run's own record first ({@link KeysRetireRecordUse}). */
  readonly recordUse?: KeysRetireRecordUse;
}

/** What the command reads and writes, besides its arguments. */
export interface KeysRetireDependencies {
  /** The realm's id, by name, or `undefined`. */
  readonly realmIdOf: (name: string) => Promise<string | undefined>;
  /** `retireKeyNow` over this host's database, Redis and KEK. */
  readonly retireKeyNow: (input: RetireKeyNowInput) => Promise<KeyRetirementOutcome>;
  /** The token-signing key with `kid` of the realm when it is compromised, else `undefined`. */
  readonly findCompromisedKey: (
    realmId: string,
    kid: string
  ) => Promise<CompromisedKey | undefined>;
  /**
   * Record a run for a key compromised already: its audit row and event, in
   * one transaction, which `before` writes in first when given.
   */
  readonly recordRepeat: (
    repeat: KeyRetirementRepeat,
    before?: (tx: AuditTransaction) => Promise<void>
  ) => Promise<void>;
  /** `sessionService.revokeAllForRealm` of this host. */
  readonly sessions: Parameters<typeof revokeSessionsOfRetiredKey>[0];
  /** The user the command runs as, as the operating system names it. */
  readonly operatingSystemUser: () => string;
  /** Writes one line of the report. */
  readonly out: (line: string) => void;
  /** Writes one line of an error. */
  readonly err: (line: string) => void;
}

/** The decorators of the process the command reads: its database, cache and session plugins'. */
export interface KeysRetireHost {
  readonly db: FastifyInstance['db'];
  readonly redis: FastifyInstance['redis'];
  readonly log: FastifyBaseLogger;
  readonly repositories: Pick<
    FastifyInstance['repositories'],
    'realms' | 'refreshTokens' | 'events' | 'adminAuditLog' | 'realmPublicKeys'
  >;
  readonly sessionService: FastifyInstance['sessionService'];
}

/** The settings the command reads from the environment, and where it writes. */
export interface KeysRetireSettings {
  /** The KEK provider's settings: the process environment. */
  readonly kekEnv: Parameters<typeof retireKey>[0]['kekEnv'];
  readonly enabledSignatureAlgorithms: Parameters<
    typeof retireKey
  >[0]['enabledSignatureAlgorithms'];
  readonly hybridSigning: boolean;
  readonly operatingSystemUser: () => string;
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
}

/**
 * The command's dependencies over a process's plugins: the retirement runs
 * with this host's KEK provider and database, and, as the process holds no
 * copy of the denylist, stores the database's list as the Redis snapshot
 * after the commit, so every node learns the change at its next read.
 */
export function keysRetireDependencies(
  host: KeysRetireHost,
  settings: KeysRetireSettings
): KeysRetireDependencies {
  const retireDeps = {
    db: host.db,
    kekEnv: settings.kekEnv,
    warn: ({ variable, message }: { variable: string; message: string }) =>
      host.log.warn({ variable }, message),
    enabledSignatureAlgorithms: settings.enabledSignatureAlgorithms,
    hybridSigning: settings.hybridSigning,
  };
  return {
    realmIdOf: async (name) => (await host.repositories.realms.findByName(name))?.id,
    retireKeyNow: (input) =>
      retireKeyNow(
        {
          retire: (retireInput) => retireKey(retireDeps, retireInput),
          refreshTokens: host.repositories.refreshTokens,
          events: host.repositories.events,
          adminAuditLog: host.repositories.adminAuditLog,
          sessions: host.sessionService,
          invalidateDenylist: (retired) =>
            invalidateKeyDenylist(
              null,
              {
                redis: () => host.redis,
                listDenied: () => host.repositories.realmPublicKeys.listDenied(),
              },
              host.log,
              retired
            ),
        },
        input
      ),
    findCompromisedKey: (realmId, kid) => compromisedKeyOf(host.db, realmId, kid),
    recordRepeat: (repeat, before) =>
      recordKeyRetirementRepeat(
        {
          transaction: (run) => host.db.transaction(run),
          events: host.repositories.events,
          adminAuditLog: host.repositories.adminAuditLog,
        },
        repeat,
        before
      ),
    sessions: host.sessionService,
    operatingSystemUser: settings.operatingSystemUser,
    out: settings.out,
    err: settings.err,
  };
}

/**
 * The exit code of a run to repeat: it retired the key, or may have, but did
 * not end all its sessions.
 */
export const KEYS_RETIRE_SESSIONS_LEFT = 3;

/** An epoch-ms time as the command prints it. */
function isoTime(ms: number): string {
  return new Date(ms).toISOString();
}

/** What the command prints once the retirement committed. */
export function formatKeyRetirement(outcome: Omit<KeyRetirementOutcome, 'sessions'>): string[] {
  const { record, families } = outcome;
  const actor =
    record.actor.kind === 'break_glass'
      ? `${record.actor.operatingSystemUser} on this host`
      : `${record.actor.kind} ${record.actor.accountId}`;
  const lines = [
    `keys.retire of kid ${record.kid} in realm ${record.realmId}, by ${actor}, approval ` +
      `${record.approvalId}, operation digest ${record.operationDigest.toString('hex')}.`,
  ];
  for (const key of record.retired) {
    lines.push(`Retired ${key.kid} (${key.algorithm}, was ${key.previousStatus}): compromised.`);
  }
  for (const key of record.replacements) {
    lines.push(`Signing now with ${key.kid} (${key.algorithm}).`);
  }
  if (record.replacements.length === 0) {
    lines.push('No new key was needed: the realm went on signing with the key it had.');
  }
  lines.push(
    record.signedSince === null
      ? 'The key never signed: no refresh token or session was revoked.'
      : `Revoked ${families.families} refresh token families (${families.tokens} tokens) created ` +
          `or used since ${isoTime(record.signedSince)}, Authority Trees included.`,
    'Recorded in the admin audit log, and announced as key.emergency_retired.'
  );
  return lines;
}

/**
 * Run the command with `argv`, the arguments after the script name.
 *
 * @returns the exit code: 0 done, 3 run it again (the key is retired, or may
 *   be, but its sessions were not all ended), 2 a usage error, 1 any other
 *   error (nothing changed)
 */
export async function runKeysRetire(
  argv: readonly string[],
  defaultRealmName: string,
  deps: KeysRetireDependencies,
  options: KeysRetireOptions = {}
): Promise<number> {
  const name = options.command ?? 'keys:retire';
  let command: KeysRetireCommand;
  try {
    command = parseKeysRetireArguments(argv, defaultRealmName);
  } catch (error) {
    if (!(error instanceof KeysRetireUsageError)) throw error;
    deps.err(error.message);
    return 2;
  }

  const realmId = await deps.realmIdOf(command.realmName);
  if (realmId === undefined) {
    deps.err(`${name}: no realm is named '${command.realmName}'.`);
    return 1;
  }
  const operatingSystemUser = deps.operatingSystemUser();
  const actor = Object.freeze({ kind: 'break_glass' as const, operatingSystemUser });

  try {
    const { recordUse } = options;
    const outcome = await deps.retireKeyNow({
      realmId,
      kid: command.kid,
      approval: hostKeyRetirementApproval(
        operatingSystemUser,
        recordUse === undefined
          ? undefined
          : (operationDigest, tx) => recordUse(tx, { realmId, kid: command.kid, operationDigest })
      ),
    });
    for (const line of formatKeyRetirement(outcome)) deps.out(line);
    deps.out(`Ended ${outcome.sessions.ended} browser sessions of the realm.`);
    return 0;
  } catch (error) {
    if (error instanceof KeyChangeRefusedError && error.reason === 'ALREADY_COMPROMISED') {
      return endSessionsAgain(deps, realmId, command.kid, actor, { ...options, command: name });
    }
    if (isRefusal(error)) {
      deps.err(`${name}: ${sentence(describeKeysRetireError(error))} Nothing was changed.`);
      return 1;
    }
    // Retired or not depends on where it failed: a failure before the commit
    // changed nothing, one after it (the session sweep) left the key retired.
    let retired: CompromisedKey | undefined;
    try {
      retired = await deps.findCompromisedKey(realmId, command.kid);
    } catch (lookupError) {
      // The database may have gone after the commit: the key may be retired.
      deps.err(
        `${name}: ${sentence(describeKeysRetireError(error))} Whether the key was retired ` +
          `cannot be read: ${sentence(describeKeysRetireError(lookupError))} Run ${name} ` +
          'again for the same kid once the database answers.'
      );
      return KEYS_RETIRE_SESSIONS_LEFT;
    }
    if (retired === undefined) {
      deps.err(`${name}: ${sentence(describeKeysRetireError(error))} Nothing was changed.`);
      return 1;
    }
    deps.err(
      `${name}: the key is retired, but ending the realm's sessions failed: ` +
        `${sentence(describeKeysRetireError(error))} Run ${name} again for the same kid to end them.`
    );
    return KEYS_RETIRE_SESSIONS_LEFT;
  }
}

/**
 * For a key retired already: record and announce the run, as every run is,
 * then end the realm's sessions used since the key may have signed, again.
 */
async function endSessionsAgain(
  deps: KeysRetireDependencies,
  realmId: string,
  kid: string,
  actor: { readonly kind: 'break_glass'; readonly operatingSystemUser: string },
  options: KeysRetireOptions & { readonly command: string }
): Promise<number> {
  const name = options.command;
  const key = await deps.findCompromisedKey(realmId, kid);
  if (key === undefined) {
    deps.err(`${name}: the key is no longer compromised; nothing was changed.`);
    return 1;
  }
  const approval = hostKeyRetirementApproval(actor.operatingSystemUser);
  const digest = operationDigest(
    keyRetirementOperation({ realmId, kid, requester: actor, nonce: approval.nonce })
  );
  const { recordUse } = options;
  try {
    await deps.recordRepeat(
      {
        realmId,
        kid,
        algorithm: key.algorithm,
        actor,
        approvalId: approval.id,
        operationDigest: Buffer.from(digest),
        signedSince: key.signedSince,
      },
      recordUse === undefined
        ? undefined
        : (tx) => recordUse(tx, { realmId, kid, operationDigest: Buffer.from(digest) })
    );
  } catch (error) {
    deps.err(
      `${name}: the run could not be recorded: ${sentence(describeKeysRetireError(error))} ` +
        'Nothing was changed.'
    );
    return 1;
  }
  deps.out(
    `keys.retire of kid ${kid} in realm ${realmId}, by ${actor.operatingSystemUser} on this host, ` +
      `approval ${approval.id}: the key is retired already. Recorded in the admin audit log, ` +
      'and announced as key.emergency_retired again.'
  );
  if (key.signedSince === null) {
    deps.out('The key never signed: no session was ended.');
    return 0;
  }
  deps.out(`Ending the realm's sessions used since ${isoTime(key.signedSince)} again.`);
  try {
    const sessions = await revokeSessionsOfRetiredKey(deps.sessions, {
      realmId,
      signedSince: key.signedSince,
      actor,
    });
    deps.out(`Ended ${sessions.ended} browser sessions of the realm.`);
    return 0;
  } catch (error) {
    deps.err(
      `${name}: ending the realm's sessions failed: ${sentence(describeKeysRetireError(error))} ` +
        `Run ${name} again for the same kid.`
    );
    return KEYS_RETIRE_SESSIONS_LEFT;
  }
}

function isRefusal(error: unknown): boolean {
  return error instanceof KeyChangeRefusedError || error instanceof OperationApprovalError;
}

/** `text` as a sentence: with a full stop at its end. */
function sentence(text: string): string {
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

/**
 * An error as the command prints it. A failed query's message carries the
 * query's parameters, so only the database's own error under it is printed.
 */
export function describeKeysRetireError(error: unknown): string {
  if (isRefusal(error)) return (error as Error).message;
  if (!(error instanceof Error)) return String(error);
  if (error.constructor.name === 'DrizzleQueryError' || 'params' in error) {
    const { cause } = error;
    return cause instanceof Error
      ? `the database refused a query: ${cause.name}: ${cause.message}`
      : 'the database refused a query';
  }
  return `${error.name}: ${error.message}`;
}
