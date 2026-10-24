/**
 * Verification of a realm's admin event chain from the command line (issues
 * #459 and #827): `events:verify-chain` reports the first admin event that
 * breaks the chain, or the head when none does.
 *
 * An operator runs it on a host that holds the database credentials, like
 * the other operator scripts. It only reads. The logic lives here, apart from
 * the CLI in `verify-event-chain.ts`, so it can be tested without running the
 * script.
 */
import type { EventChainBreakReason, EventChainPoint, EventChainReport } from '../types';

export interface VerifyChainArgs {
  /** The realm, by name. */
  realm?: string;
  /** The realm, by id: also a realm that no longer exists. */
  realmId?: string;
  /** The point to verify from: the head an earlier run printed. */
  from?: EventChainPoint;
  /** Print the report as JSON. */
  json: boolean;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256_HEX = /^[0-9a-f]{64}$/i;

/**
 * The exit codes of `events:verify-chain`, so a monitor tells a broken chain
 * from a check that could not run, such as during a database outage.
 */
export const VERIFY_CHAIN_EXIT = Object.freeze({
  /** Every admin event after the starting point verifies. */
  verified: 0,
  /** The chain breaks: an admin event was changed or removed. */
  broken: 1,
  /** The arguments or the environment are wrong; nothing was read. */
  usage: 2,
  /** The check could not run: the database unreachable or failing, or the realm not found. */
  cannotRun: 3,
} as const);

export const VERIFY_CHAIN_USAGE =
  'Usage: verify-event-chain.ts (--realm=<realm name> | --realm-id=<uuid>)\n' +
  '                             [--from-seq=<seq> --from-hash=<hex>] [--json]\n' +
  "       Checks the realm's admin event chain and reports the first event that breaks it.\n" +
  '       --from-seq and --from-hash start after the head an earlier run printed.\n' +
  '       Set DATABASE_URL in the environment. Exits 0 when the chain verifies, 1 when it\n' +
  '       breaks, 2 on a usage error, and 3 when the check could not run (the database\n' +
  '       unreachable or failing, the realm not found).';

/**
 * Parse the arguments from `process.argv`. Returns null when the realm is
 * missing, named twice or not a UUID, when only one half of the starting
 * point is given or either half is malformed, or on an unknown flag, so the
 * caller prints the usage and exits 2 instead of reporting a break.
 */
export function parseVerifyChainArgs(argv: readonly string[]): VerifyChainArgs | null {
  let realm: string | undefined;
  let realmId: string | undefined;
  let fromSeq: string | undefined;
  let fromHash: string | undefined;
  let json = false;
  for (const arg of argv.slice(2)) {
    if (arg.startsWith('--realm=')) realm = arg.slice('--realm='.length);
    else if (arg.startsWith('--realm-id=')) realmId = arg.slice('--realm-id='.length);
    else if (arg.startsWith('--from-seq=')) fromSeq = arg.slice('--from-seq='.length);
    else if (arg.startsWith('--from-hash=')) fromHash = arg.slice('--from-hash='.length);
    else if (arg === '--json') json = true;
    else return null;
  }
  if (!realm === !realmId) return null;
  if (realmId !== undefined && !UUID_PATTERN.test(realmId)) return null;
  if ((fromSeq === undefined) !== (fromHash === undefined)) return null;
  let from: EventChainPoint | undefined;
  if (fromSeq !== undefined && fromHash !== undefined) {
    if (!/^(0|[1-9][0-9]*)$/.test(fromSeq) || !SHA256_HEX.test(fromHash)) return null;
    from = { seq: BigInt(fromSeq), hash: fromHash.toLowerCase() };
  }
  return {
    ...(realm ? { realm } : {}),
    ...(realmId ? { realmId } : {}),
    ...(from ? { from } : {}),
    json,
  };
}

const REASONS: Readonly<Record<EventChainBreakReason, string>> = {
  prev_hash_mismatch:
    'its prev_hash is not the hash of the admin event before it: an event before it was removed, or changed and given a new hash',
  hash_mismatch: 'it does not hash to its stored hash: it was changed',
  unreadable_row: 'it cannot be read back into an event that hashes',
  anchor_missing:
    'the admin event at the starting point is gone: the chain was cut back to before it',
  anchor_mismatch:
    'the admin event at the starting point no longer carries the hash given, or no longer hashes to it: it, or the chain up to it, was rewritten',
};

/** A report as JSON: `bigint` values as decimal strings. */
export function chainReportJson(report: EventChainReport): string {
  return JSON.stringify(
    report,
    (_key, value: unknown) => (typeof value === 'bigint' ? value.toString() : value),
    2
  );
}

/** A report as the lines the CLI prints. */
export function describeChainReport(report: EventChainReport, realmLabel: string): string[] {
  const from =
    report.from.seq === 0n
      ? 'from its start'
      : `after seq ${report.from.seq} (hash ${report.from.hash})`;
  if (report.ok) {
    return [
      `The admin event chain of realm ${realmLabel} verifies ${from}: ${report.rowsChecked} admin event(s) checked.`,
      report.head
        ? `Head: event ${report.head.id}, --from-seq=${report.head.seq} --from-hash=${report.head.hash}`
        : 'No admin event follows the starting point.',
      'Keep the head outside the database: a later run from it fails when the chain up to it was cut or rewritten.',
    ];
  }
  const at =
    report.break.id === null
      ? `at seq ${report.break.seq}`
      : `at event ${report.break.id} (seq ${report.break.seq})`;
  return [
    `The admin event chain of realm ${realmLabel} BREAKS ${from}, ${at}:`,
    `${REASONS[report.break.reason]}.`,
    `${report.rowsChecked} admin event(s) before it verified.`,
  ];
}
