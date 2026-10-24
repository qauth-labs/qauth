import { readFileSync } from 'node:fs';
import * as path from 'node:path';

/**
 * The migration list a build of QAuth carries (issue #474): drizzle-kit's
 * journal, `drizzle/meta/_journal.json`, read the way drizzle's own migrator
 * reads it.
 */

/** One generated migration, as the journal lists it. */
export interface MigrationEntry {
  /** The file name without `.sql`, such as `0035_event_deliveries`. */
  readonly tag: string;
  /**
   * When drizzle-kit generated it, in epoch milliseconds. Drizzle stores this
   * as `created_at` when it applies the migration and compares it to decide
   * what is pending.
   */
  readonly when: number;
}

/**
 * The generated migrations folder of this source tree.
 *
 * Resolved from this file, so it holds wherever the library's sources run:
 * the workspace, and the auth-server image, which carries the library with
 * its `drizzle/` folder. The bundled migration runner has its own copy beside
 * its program and passes that folder instead.
 */
export const QAUTH_MIGRATIONS_FOLDER = path.resolve(__dirname, '../../../drizzle');

/** A migrations folder whose journal cannot be read. */
export class MigrationJournalError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'MigrationJournalError';
  }
}

/**
 * Read the migrations a folder holds, oldest first.
 *
 * @throws MigrationJournalError when the journal is missing or malformed.
 *   Drizzle's migrator would refuse the same folder.
 */
export function readMigrationJournal(
  migrationsFolder: string = QAUTH_MIGRATIONS_FOLDER
): MigrationEntry[] {
  const journalPath = path.join(migrationsFolder, 'meta', '_journal.json');
  let journal: unknown;
  try {
    journal = JSON.parse(readFileSync(journalPath, 'utf8'));
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new MigrationJournalError(`Cannot read the migration journal ${journalPath}: ${reason}`, {
      cause: error,
    });
  }
  const entries = (journal as { entries?: unknown } | null)?.entries;
  if (!Array.isArray(entries)) {
    throw new MigrationJournalError(`The migration journal ${journalPath} has no entries list`);
  }
  return entries.map((entry: unknown, index) => {
    const { tag, when } = (entry ?? {}) as { tag?: unknown; when?: unknown };
    if (typeof tag !== 'string' || tag === '' || typeof when !== 'number') {
      throw new MigrationJournalError(
        `Entry ${index} of the migration journal ${journalPath} has no tag or time`
      );
    }
    return { tag, when };
  });
}
