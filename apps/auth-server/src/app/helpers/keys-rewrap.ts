import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

import {
  KEK_ROTATE_OPERATION,
  type KekRefCensus,
  KekRewrapRefusedError,
  type KekRewrapReport,
  type KekRotationRecord,
  newOperationNonce,
  type RotateKekInput,
} from '@qauth-labs/fastify-plugin-signer';
import type { FastifyInstance } from 'fastify';

import { RESERVED_OPERATIONS } from './admin-operations-reserved';

/**
 * The operator command `auth-server:keys:rewrap` (ADR-019 Decision 9, issue
 * #545): a KEK rotation on a host that holds both KEKs. It re-wraps every
 * stored key's data key from the old KEK to the new one, then prints the
 * stored keys per `kek_ref` and whether the old KEK may go.
 *
 * Everything but the database and the KEK provider is here, so a unit test
 * runs the command with both faked.
 */

export const KEYS_REWRAP_USAGE = `Usage: keys:rewrap --from <kek_ref> [--to <kek_ref>]
       keys:rewrap --status

Re-wrap every stored key's data key from the old KEK to the new one: a KEK rotation. Run it on a
host that holds both, the new KEK as KEK (or KEK_PATH) and the old one as KEK_PREVIOUS (or
KEK_PREVIOUS_PATH), after every signer node runs with both. Only the data keys change; signing
goes on throughout. A run that stops can be run again: it moves what is left.

  --from    The kek_ref the keys move from: the old KEK. --status shows the kek_refs in use.
  --to      The kek_ref they move to. Default: the KEK this host wraps under.
  --status  Count the stored keys per kek_ref and say which this host opens. Changes nothing.

It prints the stored keys per kek_ref, and whether KEK_PREVIOUS can be removed. Exit codes: 0
done, 3 keys still need the old KEK or a KEK this host cannot open, 2 a usage error, 1 any
other error.

Example:

  pnpm nx run auth-server:keys:rewrap --status
  pnpm nx run auth-server:keys:rewrap --from=<the old kek_ref>`;

/** Thrown for arguments the command does not take; the message ends with the usage. */
export class KeysRewrapUsageError extends Error {
  constructor(problem: string) {
    super(`${problem}\n\n${KEYS_REWRAP_USAGE}`);
    this.name = 'KeysRewrapUsageError';
  }
}

/** What the command was asked to do. */
export type KeysRewrapCommand =
  | { readonly mode: 'status' }
  | { readonly mode: 'rewrap'; readonly from: string; readonly to?: string };

/**
 * Read the command's arguments.
 *
 * @throws KeysRewrapUsageError for an unknown option, `--status` with another
 *   option, or a re-wrap without `--from`
 */
export function parseKeysRewrapArguments(argv: readonly string[]): KeysRewrapCommand {
  let values: { from?: string; to?: string; status?: boolean };
  try {
    ({ values } = parseArgs({
      args: [...argv],
      options: {
        from: { type: 'string' },
        to: { type: 'string' },
        status: { type: 'boolean' },
      },
      strict: true,
      allowPositionals: false,
    }));
  } catch (error) {
    throw new KeysRewrapUsageError(error instanceof Error ? error.message : String(error));
  }

  const { from, to, status } = values;
  if (status === true) {
    if (from !== undefined || to !== undefined) {
      throw new KeysRewrapUsageError('--status takes no other option.');
    }
    return { mode: 'status' };
  }
  if (from === undefined || from.length === 0) {
    throw new KeysRewrapUsageError(
      '--from is required: the kek_ref of the old KEK. --status shows the kek_refs in use.'
    );
  }
  if (to !== undefined && to.length === 0) {
    throw new KeysRewrapUsageError('--to is a kek_ref.');
  }
  return { mode: 'rewrap', from, ...(to === undefined ? {} : { to }) };
}

/**
 * The approval the command runs the KEK rotation under, made on the host.
 *
 * A KEK rotation is a security operation (ADR-019 Decisions 7 and 9). From
 * the admin API it runs only under an approval its approvers gave. This
 * command runs where the KEKs are: whoever holds the host and both KEKs can
 * open every stored key whatever an approval says, and stands outside the
 * approval rule (ADR-019 Decision 7), so the command approves its own run.
 * The approval is still bound to the rotation it runs (the two references,
 * the operating-system user and a fresh nonce) and is used once.
 */
export function hostKekRotationApproval(operatingSystemUser: string): RotateKekInput['approval'] {
  let used = false;
  return Object.freeze({
    id: randomUUID(),
    operation: KEK_ROTATE_OPERATION,
    requester: Object.freeze({ kind: 'break_glass' as const, operatingSystemUser }),
    nonce: newOperationNonce(),
    async consume(): Promise<void> {
      if (used) throw new Error('A host approval is used once');
      used = true;
    },
  });
}

type AdminAuditLog = FastifyInstance['repositories']['adminAuditLog'];

/** One row of the admin audit log, as the repository takes it. */
type AdminAuditEntry = Parameters<AdminAuditLog['appendAdminAudit']>[1];

/** The transaction the rotation uses its approval up in, which the audit rows commit in. */
type DbTransaction = Parameters<AdminAuditLog['appendAdminAudit']>[0];

/** Where the command records a run: the admin audit log, and the realms whose keys it moves. */
export interface KekRotationAuditLog {
  /**
   * The realms that hold a stored key, after `afterRealmId`, in realm id
   * order (`listRealmIdsWithKeys` of the signer's wiring).
   */
  readonly listRealmIds: (
    afterRealmId: string | null,
    limit: number,
    tx: DbTransaction
  ) => Promise<readonly string[]>;
  /** `appendAdminAudit` of the admin audit log repository. */
  readonly appendAdminAudit: (tx: DbTransaction, entry: AdminAuditEntry) => Promise<unknown>;
}

/** How many realms the audit write lists at a time. */
const AUDIT_REALM_PAGE = 500;

/** The effects of `kek.rotate`, as the reserved operation ids name them. */
const KEK_ROTATE_EFFECTS = (() => {
  const reserved = RESERVED_OPERATIONS.find((entry) => entry.id === KEK_ROTATE_OPERATION);
  if (reserved === undefined) throw new Error(`'${KEK_ROTATE_OPERATION}' is not reserved`);
  return reserved.effects;
})();

/**
 * Record a host run of the KEK rotation in the admin audit log, inside the
 * transaction that uses its approval up, before any key moves: one row in the
 * chain of every realm that holds a stored key, as the realms' keys are what
 * it re-wraps. Each row names the operating-system user (actor
 * `break_glass_operator`), the operation `kek.rotate` with its effects, the
 * two KEK references, the operation digest and the approval id, so the rows
 * of one run are found together. ADR-019 Decision 7: a run that stands
 * outside the approval rule is recorded, and a failed write stops the run
 * with nothing moved.
 *
 * The rows record that the rotation started under the approval; where the
 * keys stand afterwards is what the command prints.
 *
 * @returns how many realms' logs recorded it
 * @throws TypeError when the record's actor is not this host's operator
 */
export async function recordHostKekRotation(
  log: KekRotationAuditLog,
  record: KekRotationRecord,
  tx: DbTransaction
): Promise<number> {
  const { actor } = record;
  if (actor.kind !== 'break_glass') {
    throw new TypeError("The host command records only its own run, by this host's operator");
  }
  let written = 0;
  let after: string | null = null;
  for (;;) {
    const page = await log.listRealmIds(after, AUDIT_REALM_PAGE, tx);
    // In realm id order, the order appends to several realms take their locks in.
    for (const realmId of page) {
      await log.appendAdminAudit(tx, {
        realmId,
        actorKind: 'break_glass_operator',
        actorId: actor.operatingSystemUser,
        actorRealmId: null,
        actChain: null,
        operationId: KEK_ROTATE_OPERATION,
        operationClass: 'security',
        effects: KEK_ROTATE_EFFECTS,
        outcome: 'succeeded',
        diff: {
          change: { before: { kekRef: record.from }, after: { kekRef: record.to } },
          annotations: {},
        },
        approvals: [],
        requestDigest: Buffer.from(record.operationDigest),
        traceId: record.approvalId,
      });
      written += 1;
    }
    if (page.length < AUDIT_REALM_PAGE) return written;
    after = page[page.length - 1];
  }
}

/** What the command reads and writes, besides its arguments. */
export interface KeysRewrapDependencies {
  /** `rotateKek` of the signer's wiring, over the database and this host's KEK settings. */
  readonly rotateKek: (input: RotateKekInput) => Promise<KekRewrapReport>;
  /**
   * Records the run in the admin audit log, in the transaction that uses its
   * approval up ({@link recordHostKekRotation}). Returns how many realms'
   * logs recorded it.
   */
  readonly recordRotation: (record: KekRotationRecord, tx: DbTransaction) => Promise<number>;
  /** `countKeysPerKek` of the signer's wiring, likewise. */
  readonly countKeysPerKek: () => Promise<readonly KekRefCensus[]>;
  /** The user the command runs as, as the operating system names it. */
  readonly operatingSystemUser: () => string;
  /** Writes one line of the report. */
  readonly out: (line: string) => void;
  /** Writes one line of an error. */
  readonly err: (line: string) => void;
}

/** The exit code of a run that left keys on the old KEK, or on a KEK this host cannot open. */
export const KEYS_REWRAP_INCOMPLETE = 3;

/** What this host does with a KEK reference. */
function onThisHost(entry: KekRefCensus): string {
  const opens =
    entry.opens === true
      ? 'opens'
      : entry.opens === null
        ? 'not checked: no key of it could be read'
        : `cannot open (${entry.reason ?? 'unknown reason'})`;
  return entry.current ? `wraps new keys, ${opens}` : opens;
}

/**
 * The stored keys per `kek_ref`, as the command prints them: one line per
 * reference, with its count and what this host does with it.
 */
export function formatKekRefCounts(entries: readonly KekRefCensus[]): string[] {
  if (entries.length === 0) return ['No key is stored.'];
  const header = ['kek_ref', 'keys', 'on this host'] as const;
  const rows = entries.map((entry) => [entry.kekRef, String(entry.rows), onThisHost(entry)]);
  const refWidth = Math.max(header[0].length, ...rows.map((row) => row[0].length));
  const countWidth = Math.max(header[1].length, ...rows.map((row) => row[1].length));
  return [header, ...rows].map(
    ([ref, keys, host]) => `${ref.padEnd(refWidth)}  ${keys.padStart(countWidth)}  ${host}`
  );
}

/** The line the command prints when the rotation starts: its audit record. */
export function formatKekRotationStart(record: KekRotationRecord): string {
  const actor =
    record.actor.kind === 'break_glass'
      ? `${record.actor.operatingSystemUser} on this host`
      : `${record.actor.kind} ${record.actor.accountId}`;
  return (
    `kek.rotate from ${record.from} to ${record.to}, by ${actor}, approval ${record.approvalId}, ` +
    `operation digest ${record.operationDigest.toString('hex')}: ${record.rows} keys to re-wrap.`
  );
}

/**
 * What the command prints after a run, and its exit code: what moved, the
 * keys that did not open, the stored keys per `kek_ref`, and whether
 * `KEK_PREVIOUS` may be removed.
 */
export function formatKekRewrapReport(report: KekRewrapReport): {
  readonly lines: string[];
  readonly exitCode: 0 | typeof KEYS_REWRAP_INCOMPLETE;
} {
  const lines = [
    `Re-wrapped ${report.rewrapped} keys from ${report.from} to ${report.to}; ` +
      `${report.moved} were moved or deleted by another writer first.`,
  ];
  for (const failure of report.failures) {
    lines.push(
      `Did not open under ${report.from}: realm ${failure.realmId}, kid ${failure.kid} (${failure.code}).`
    );
  }
  lines.push('', 'Stored keys per kek_ref:', ...formatKekRefCounts(report.kekRefs), '');

  if (report.complete) {
    lines.push(
      `Every stored key is wrapped under ${report.to}, and this host opened a key of it.`,
      `It is safe to remove KEK_PREVIOUS (or KEK_PREVIOUS_PATH), or to retire ${report.from} in ` +
        'your key service, once every signer node runs with the new KEK as KEK. If a node wrapped ' +
        'a key under the old KEK since, run keys:rewrap again first.'
    );
    return { lines, exitCode: 0 };
  }

  lines.push('Do not remove KEK_PREVIOUS yet:');
  const left = report.kekRefs.find((entry) => entry.kekRef === report.from);
  if (left !== undefined) {
    lines.push(`- ${left.rows} stored keys are still wrapped under ${report.from}.`);
  }
  for (const entry of report.kekRefs) {
    if (entry.kekRef === report.from || (entry.kekRef === report.to && entry.opens === true)) {
      continue;
    }
    if (entry.opens === true) {
      lines.push(
        `- ${entry.rows} stored keys are wrapped under ${entry.kekRef}, another old KEK: ` +
          `re-wrap them with --from=${entry.kekRef}.`
      );
    } else {
      lines.push(
        `- ${entry.rows} stored keys are wrapped under ${entry.kekRef}, which this host cannot open: ` +
          'set that KEK on this host and re-wrap them, or find where they came from.'
      );
    }
  }
  if (report.failures.length > 0) {
    lines.push(
      `- ${report.failures.length} keys did not open under ${report.from}; they stay wrapped under it.`
    );
  }
  lines.push('Run keys:rewrap again once the cause is fixed: it moves what is left.');
  return { lines, exitCode: KEYS_REWRAP_INCOMPLETE };
}

/**
 * Run the command with `argv`, the arguments after the script name.
 *
 * @returns the exit code: 0 done (or `--status`), 3 keys still need the old
 *   KEK or one this host cannot open, 2 a usage error, 1 any other error
 */
export async function runKeysRewrap(
  argv: readonly string[],
  deps: KeysRewrapDependencies
): Promise<number> {
  let command: KeysRewrapCommand;
  try {
    command = parseKeysRewrapArguments(argv);
  } catch (error) {
    if (!(error instanceof KeysRewrapUsageError)) throw error;
    deps.err(error.message);
    return 2;
  }

  if (command.mode === 'status') {
    try {
      const census = await deps.countKeysPerKek();
      deps.out('Stored keys per kek_ref:');
      for (const line of formatKekRefCounts(census)) deps.out(line);
      return 0;
    } catch (error) {
      deps.err(`keys:rewrap: ${describeKeysRewrapError(error)}`);
      return 1;
    }
  }

  let report: KekRewrapReport;
  try {
    report = await deps.rotateKek({
      from: command.from,
      ...(command.to === undefined ? {} : { to: command.to }),
      approval: hostKekRotationApproval(deps.operatingSystemUser()),
      onAudit: async (record, tx) => {
        const realms = await deps.recordRotation(record, tx);
        deps.out(formatKekRotationStart(record));
        deps.out(`Recorded in the admin audit log of ${realms} realms.`);
      },
    });
  } catch (error) {
    deps.err(`keys:rewrap: ${describeKeysRewrapError(error)}`);
    // Where the keys stand: a run that stopped halfway left each key under
    // one KEK or the other, and a second run moves the rest.
    try {
      const census = await deps.countKeysPerKek();
      deps.err('Stored keys per kek_ref:');
      for (const line of formatKekRefCounts(census)) deps.err(line);
    } catch {
      // The count failed for the same cause; the error above says it.
    }
    return 1;
  }

  const { lines, exitCode } = formatKekRewrapReport(report);
  for (const line of lines) deps.out(line);
  return exitCode;
}

/**
 * An error as the command prints it. A failed query's message carries the
 * query's parameters, among them a key's wrapped data key, so only the
 * database's own error under it is printed.
 */
export function describeKeysRewrapError(error: unknown): string {
  if (error instanceof KekRewrapRefusedError) return error.message;
  if (!(error instanceof Error)) return String(error);
  if (error.constructor.name === 'DrizzleQueryError' || 'params' in error) {
    const { cause } = error;
    return cause instanceof Error
      ? `the database refused a query: ${cause.name}: ${cause.message}`
      : 'the database refused a query';
  }
  return `${error.name}: ${error.message}`;
}
