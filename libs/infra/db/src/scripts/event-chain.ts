/**
 * Verification of a realm's admin event chain from the command line (issue
 * #459): `events:verify-chain` reports the first admin event that breaks the
 * chain, or the head when none does.
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

export const VERIFY_CHAIN_USAGE =
  'Usage: verify-event-chain.ts (--realm=<realm name> | --realm-id=<uuid>)\n' +
  '                             [--from-seq=<seq> --from-hash=<hex>] [--json]\n' +
  "       Checks the realm's admin event chain and reports the first event that breaks it.\n" +
  '       --from-seq and --from-hash start after the head an earlier run printed.\n' +
  '       Exits 0 when the chain verifies, 1 when it breaks. Set DATABASE_URL in the environment.';

/**
 * Parse the arguments from `process.argv`. Returns null when the realm is
 * missing or named twice, when only one half of the starting point is given,
 * or on an unknown flag, so the caller prints the usage instead of guessing.
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
  if ((fromSeq === undefined) !== (fromHash === undefined)) return null;
  let from: EventChainPoint | undefined;
  if (fromSeq !== undefined && fromHash !== undefined) {
    if (!/^(0|[1-9][0-9]*)$/.test(fromSeq)) return null;
    from = { seq: BigInt(fromSeq), hash: fromHash };
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
      'Keep the head outside the database: a later run from it shows the newest events cut or rewritten.',
    ];
  }
  return [
    `The admin event chain of realm ${realmLabel} BREAKS ${from}, at event ${report.break.id} (seq ${report.break.seq}):`,
    `${REASONS[report.break.reason]}.`,
    `${report.rowsChecked} admin event(s) before it verified.`,
  ];
}
