import { existsSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Freshness check for `docs/spec-pin-log.md` (#401).
 *
 * The pin log is itself a status surface, and status surfaces decay. Adding one
 * to fix status drift is only defensible if it fails LOUDLY — a table of dates
 * that looks maintained and is not is worse than no table, because a reader
 * trusts it. So this is a hard failure, never a warning, and the log says so in
 * its own header.
 *
 * Two things are checkable without a network:
 *
 *   1. A `Re-check by` date that has passed. The whole point of the column.
 *   2. A `Consumers` path that no longer exists. A pin nothing consumes is a
 *      pin nobody will notice going stale — and a moved file is the ordinary
 *      way that happens.
 *
 * What is NOT checkable here, and is left to the human pass: whether a pinned
 * revision still exists upstream, and whether a `derived` row's basis document
 * still references that revision. Those are the questions the quarterly pass
 * exists to answer.
 */

export type PinBasis = 'derived' | 'latest' | 'deliberate';

export interface SpecPinRow {
  spec: string;
  revision: string;
  basis: string;
  lastVerified: string;
  recheckBy: string;
  verdict: string;
  consumers: string[];
  /** 1-indexed line in the source document, for the failure message. */
  line: number;
}

export interface SpecPinViolation {
  spec: string;
  line: number;
  reason: string;
}

const VALID_BASES: readonly string[] = ['derived', 'latest', 'deliberate'];

/** `2026-11-22`, optionally wrapped in the backticks the table uses. */
function parseDate(cell: string): string | null {
  const match = cell.match(/(\d{4})-(\d{2})-(\d{2})/);
  return match ? match[0] : null;
}

function stripCode(cell: string): string {
  return cell.replace(/`/g, '').trim();
}

/**
 * Parse the pin table out of the log.
 *
 * Reads the FIRST table whose header row names both `Pin basis` and
 * `Re-check by`, so the "three bases" explainer table above it and the pass
 * ledger below cannot be mistaken for it. Returns `[]` when no such table
 * exists — which the caller must treat as a failure, not a clean bill.
 */
export function parseSpecPinTable(markdown: string): SpecPinRow[] {
  const lines = markdown.split(/\r?\n/);

  const headerIndex = lines.findIndex(
    (line) => line.includes('|') && line.includes('Pin basis') && line.includes('Re-check by')
  );
  if (headerIndex === -1) return [];

  const columns = lines[headerIndex]
    .split('|')
    .slice(1, -1)
    .map((cell) => cell.trim().toLowerCase());
  const indexOf = (name: string) => columns.findIndex((column) => column === name);

  const at = {
    spec: indexOf('spec'),
    revision: indexOf('pinned revision'),
    basis: indexOf('pin basis'),
    lastVerified: indexOf('last verified'),
    recheckBy: indexOf('re-check by'),
    verdict: indexOf('verdict'),
    consumers: indexOf('consumers'),
  };
  if (Object.values(at).some((index) => index === -1)) return [];

  const rows: SpecPinRow[] = [];
  // +2 skips the header and the `|---|---|` separator.
  for (let i = headerIndex + 2; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line.trim().startsWith('|')) break; // the table ended
    const cells = line.split('|').slice(1, -1);
    if (cells.length < columns.length) continue;

    rows.push({
      spec: stripCode(cells[at.spec]),
      revision: stripCode(cells[at.revision]),
      basis: stripCode(cells[at.basis]),
      lastVerified: stripCode(cells[at.lastVerified]),
      recheckBy: stripCode(cells[at.recheckBy]),
      verdict: cells[at.verdict].trim(),
      consumers: cells[at.consumers]
        .split(',')
        .map((consumer) => stripCode(consumer))
        // Drop markdown links and prose fragments — a consumer is a path.
        .filter((consumer) => consumer.length > 0 && !consumer.startsWith('[')),
      line: i + 1,
    });
  }

  return rows;
}

/**
 * Every reason this log is not currently trustworthy.
 *
 * `today` is a parameter rather than `new Date()` so the tests can pin it: a
 * freshness check whose own tests drift with the wall clock is the joke that
 * writes itself.
 */
export function findStaleSpecPins(
  rows: SpecPinRow[],
  repoRoot: string,
  today: string
): SpecPinViolation[] {
  const violations: SpecPinViolation[] = [];

  for (const row of rows) {
    if (!VALID_BASES.includes(row.basis)) {
      violations.push({
        spec: row.spec,
        line: row.line,
        reason: `pin basis "${row.basis}" is not one of ${VALID_BASES.join(', ')} — a row without a basis cannot be re-checked correctly`,
      });
    }

    const recheck = parseDate(row.recheckBy);
    if (!recheck) {
      violations.push({
        spec: row.spec,
        line: row.line,
        reason: `"Re-check by" is not an ISO date (${row.recheckBy || 'empty'})`,
      });
    } else if (recheck < today) {
      // ISO-8601 strings compare correctly as strings; no Date parsing, no
      // timezone surprises.
      violations.push({
        spec: row.spec,
        line: row.line,
        reason: `re-check was due ${recheck} — run the pass and update this row (see the Method section)`,
      });
    }

    if (!parseDate(row.lastVerified)) {
      violations.push({
        spec: row.spec,
        line: row.line,
        reason: `"Last verified" is not an ISO date (${row.lastVerified || 'empty'})`,
      });
    }

    if (row.consumers.length === 0) {
      violations.push({
        spec: row.spec,
        line: row.line,
        reason:
          'no consumers listed — a pin nothing consumes is one nobody will notice going stale',
      });
    }

    for (const consumer of row.consumers) {
      if (!existsSync(join(repoRoot, consumer))) {
        violations.push({
          spec: row.spec,
          line: row.line,
          reason: `consumer path "${consumer}" no longer exists`,
        });
      }
    }
  }

  return violations;
}
