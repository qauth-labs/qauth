/**
 * migration-policy rules (#473, ADR-018 §5). Pure functions over file
 * contents; `check.mjs` is the glue to git, the file system and the job
 * summary.
 *
 * ADR-018 §5 promises that every upgrade within 1.x completes by running the
 * migration runner, with no manual step, and that no 1.x migration is
 * destructive. This module reads the SQL drizzle-kit generates (and the custom
 * SQL written beside it) and finds the statements that break that promise:
 *
 *   drop-table           DROP TABLE, DROP SCHEMA
 *   drop-column          ALTER TABLE … DROP [COLUMN]
 *   drop-constraint      ALTER TABLE … DROP CONSTRAINT
 *   alter-column-type    ALTER TABLE … ALTER [COLUMN] … [SET DATA] TYPE
 *   rename               any ALTER … RENAME
 *   truncate             TRUNCATE
 *   delete-from          DELETE FROM, and MERGE … THEN DELETE
 *   set-not-null         ALTER TABLE … ALTER [COLUMN] … SET NOT NULL
 *   add-column-not-null  ALTER TABLE … ADD [COLUMN] … NOT NULL (or PRIMARY KEY)
 *                        with no DEFAULT and no GENERATED
 *   raise-exception      RAISE at level EXCEPTION (the default level) or
 *                        ASSERT in a DO block: a precondition that stops the
 *                        upgrade until someone acts by hand
 *
 * A statement it does not know is not refused: an ALTER form or action
 * outside the known list, a DROP of anything but a table, and dynamic SQL
 * (EXECUTE) in a DO block are printed for review.
 *
 * What runs at migration time is what is checked. The body of a DO block runs
 * then, so it is read as SQL. The body of CREATE FUNCTION or CREATE PROCEDURE
 * only runs when something calls it later, so it is not: a trigger function
 * that raises to refuse a write is a guard, not a migration step.
 *
 * Zero runtime dependencies — Node's standard library only.
 */

import { compareReleases, parseReleaseTag } from '../stable-surface/lib.mjs';

/** The directory of the migrations, from the repository root. */
export const MIGRATIONS_DIR = 'libs/infra/db/drizzle';
/** drizzle-kit's journal, from the repository root. */
export const JOURNAL_PATH = `${MIGRATIONS_DIR}/meta/_journal.json`;
/** The exceptions file, from the repository root. */
export const EXCEPTIONS_PATH = `${MIGRATIONS_DIR}/policy-exceptions.json`;

/** The statement kinds the policy refuses, in the order the report lists them. */
export const STATEMENT_KINDS = Object.freeze([
  'drop-table',
  'drop-column',
  'drop-constraint',
  'alter-column-type',
  'rename',
  'truncate',
  'delete-from',
  'set-not-null',
  'add-column-not-null',
  'raise-exception',
]);

/** Why each kind breaks the promise, for the report and the docs page. */
export const KIND_REASONS = Object.freeze({
  'drop-table': 'drops a table and every row in it',
  'drop-column': 'drops a column and its data',
  'drop-constraint': 'drops a constraint the old release relies on',
  'alter-column-type': 'changes a column type: it can narrow it or rewrite the table',
  rename: 'renames what the old release still uses by its old name',
  truncate: 'deletes every row of a table',
  'delete-from': 'deletes rows',
  'set-not-null': 'fails on existing NULLs and refuses the writes of the old release',
  'add-column-not-null':
    'fails on a table that has rows, and refuses the inserts of the old release',
  'raise-exception': 'can stop the upgrade until someone acts by hand',
});

/** A migration file name, as drizzle-kit writes it: `0074_admin_grants_security_change.sql`. */
export const MIGRATION_FILE = /^(\d{4})_[a-z0-9_]+\.sql$/;

const ISSUE_REFERENCE = /^#[1-9]\d*$/;

/** A refused input: a malformed exceptions file, journal or argument. */
export class PolicyInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyInputError';
  }
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

/**
 * The release the check compares with: the highest `vMAJOR.MINOR.PATCH[-PRE]`
 * tag reachable from the commit under check, pre-releases included. Unlike
 * the stable-surface baseline, a release candidate counts: its testers ran
 * its migrations, so a file it shipped must not change either.
 *
 * @param {string[]} tags tag names reachable from the commit under check
 * @returns {string|null}
 */
export function selectBaselineTag(tags) {
  const releases = tags.map(parseReleaseTag).filter(Boolean);
  if (releases.length === 0) return null;
  return releases.reduce((latest, r) => (compareReleases(r, latest) > 0 ? r : latest)).tag;
}

// ---------------------------------------------------------------------------
// SQL scanning
// ---------------------------------------------------------------------------

const IDENTIFIER_CHAR = /[A-Za-z0-9_$]/;
const DOLLAR_TAG = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/;

function lineAt(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/**
 * Split SQL into its statements. A statement ends at a top-level `;` or at
 * drizzle-kit's `--> statement-breakpoint` marker. Each statement carries:
 *
 *   - `line`, the 1-based line of its first character, offset by `firstLine - 1`;
 *   - `text`, its source with whitespace collapsed, for the report;
 *   - `code`, the same with comments removed, string literals blanked to `''`,
 *     quoted identifiers blanked to `"_"`, dollar-quoted bodies blanked to
 *     `$$`, whitespace collapsed and letters upper-cased, for matching;
 *   - `bodies`, each dollar-quoted body as `{ text, line }`.
 *
 * @param {string} sql
 * @param {number} [firstLine] the line `sql` starts at in its file
 */
export function splitStatements(sql, firstLine = 1) {
  const statements = [];
  let code = '';
  let start = -1;
  let bodies = [];

  const finish = (end) => {
    if (start >= 0) {
      const collapsed = code.replace(/\s+/g, ' ').trim();
      if (collapsed !== '') {
        statements.push({
          line: lineAt(sql, start) + firstLine - 1,
          text: sql.slice(start, end).replace(/\s+/g, ' ').trim(),
          code: collapsed.toUpperCase(),
          bodies,
        });
      }
    }
    code = '';
    start = -1;
    bodies = [];
  };
  const begin = (i) => {
    if (start < 0) start = i;
  };

  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    const next = sql[i + 1];
    if (c === '-' && next === '-') {
      const end = sql.indexOf('\n', i);
      const comment = sql.slice(i, end < 0 ? sql.length : end);
      if (/^-->\s*statement-breakpoint\b/.test(comment)) finish(i);
      else code += ' ';
      i = end < 0 ? sql.length : end;
      continue;
    }
    if (c === '/' && next === '*') {
      let depth = 1;
      let j = i + 2;
      while (j < sql.length && depth > 0) {
        if (sql[j] === '/' && sql[j + 1] === '*') {
          depth++;
          j += 2;
        } else if (sql[j] === '*' && sql[j + 1] === '/') {
          depth--;
          j += 2;
        } else j++;
      }
      code += ' ';
      i = j;
      continue;
    }
    if (c === ';') {
      finish(i);
      i++;
      continue;
    }
    if (/\s/.test(c)) {
      code += c;
      i++;
      continue;
    }
    begin(i);
    if (c === "'") {
      const escapes = /[Ee]/.test(sql[i - 1] ?? '') && !IDENTIFIER_CHAR.test(sql[i - 2] ?? '');
      let j = i + 1;
      while (j < sql.length) {
        if (escapes && sql[j] === '\\') j += 2;
        else if (sql[j] === "'" && sql[j + 1] === "'") j += 2;
        else if (sql[j] === "'") break;
        else j++;
      }
      code += "''";
      i = j + 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === '"' && sql[j + 1] === '"') j += 2;
        else if (sql[j] === '"') break;
        else j++;
      }
      code += '"_"';
      i = j + 1;
      continue;
    }
    if (c === '$' && !IDENTIFIER_CHAR.test(sql[i - 1] ?? '')) {
      const tag = DOLLAR_TAG.exec(sql.slice(i, i + 64));
      if (tag) {
        const open = tag[0];
        const bodyStart = i + open.length;
        const close = sql.indexOf(open, bodyStart);
        const bodyEnd = close < 0 ? sql.length : close;
        bodies.push({
          text: sql.slice(bodyStart, bodyEnd),
          line: lineAt(sql, bodyStart) + firstLine - 1,
        });
        code += '$$';
        i = close < 0 ? sql.length : close + open.length;
        continue;
      }
    }
    code += c;
    i++;
  }
  finish(sql.length);
  return statements;
}

/** Split an ALTER TABLE action list on its top-level commas. */
function splitActions(text) {
  const actions = [];
  let depth = 0;
  let current = '';
  for (const c of text) {
    if (c === '(') depth++;
    if (c === ')') depth--;
    if (c === ',' && depth === 0) {
      actions.push(current.trim());
      current = '';
    } else current += c;
  }
  if (current.trim() !== '') actions.push(current.trim());
  return actions;
}

const ALTER_TABLE = /\bALTER TABLE (?:IF EXISTS )?(?:ONLY )?\S+(?: \*)? (.*)$/;
const COLUMN = '(?:COLUMN )?(?:IF EXISTS )?\\S+';
const SAFE_COLUMN_ACTION = new RegExp(
  `^ALTER ${COLUMN} (?:SET DEFAULT\\b|DROP DEFAULT$|DROP NOT NULL$|SET STATISTICS\\b|SET STORAGE\\b|SET COMPRESSION\\b)`
);
const SAFE_TABLE_ACTION =
  /^(?:ADD (?:CONSTRAINT|PRIMARY KEY|UNIQUE|CHECK|FOREIGN KEY|EXCLUDE)\b|VALIDATE CONSTRAINT\b|ALTER CONSTRAINT\b|(?:ENABLE|DISABLE|FORCE|NO FORCE) ROW LEVEL SECURITY$|(?:ENABLE|DISABLE)(?: ALWAYS| REPLICA)? TRIGGER\b|OWNER TO\b|REPLICA IDENTITY\b|SET \()/;
const TABLE_CONSTRAINT = /^ADD (?:CONSTRAINT|PRIMARY KEY|UNIQUE|CHECK|FOREIGN KEY|EXCLUDE)\b/;

/**
 * The kinds one ALTER TABLE action is, or `null` when the check does not know
 * the action.
 *
 * @param {string} action one action, from `code`
 * @returns {string[]|null}
 */
function classifyTableAction(action) {
  if (/^DROP CONSTRAINT\b/.test(action)) return ['drop-constraint'];
  if (/^DROP\b/.test(action)) return ['drop-column'];
  if (new RegExp(`^ALTER ${COLUMN} (?:SET DATA )?TYPE\\b`).test(action))
    return ['alter-column-type'];
  if (new RegExp(`^ALTER ${COLUMN} SET NOT NULL$`).test(action)) return ['set-not-null'];
  if (SAFE_COLUMN_ACTION.test(action) || SAFE_TABLE_ACTION.test(action)) return [];
  if (/^ADD\b/.test(action) && !TABLE_CONSTRAINT.test(action)) {
    // `IS NOT NULL` inside a CHECK is a condition, not the column's constraint.
    const requiresValue = /(?<!\bIS )\bNOT NULL\b|\bPRIMARY KEY\b/.test(action);
    const fills = /\bDEFAULT\b|\bGENERATED\b/.test(action);
    return requiresValue && !fills ? ['add-column-not-null'] : [];
  }
  return null;
}

/** ALTER forms whose every action is additive, outside ALTER TABLE. */
const SAFE_ALTER = /^ALTER TYPE \S+ ADD VALUE\b/;

const NOT_A_COMMAND = /^(?:GRANT|REVOKE|COMMENT)\b/;

/**
 * Where a command starts: the statement's start, or, in a PL/pgSQL body, the
 * keyword before it (`BEGIN DROP INDEX …`, `IF … THEN ASSERT …`).
 */
const COMMAND_START = '(?:^|\\b(?:BEGIN|THEN|ELSE|LOOP) )';

/**
 * Classify one statement. Returns the refused kinds, each with the statement,
 * and the notes for review.
 *
 * @param {{line: number, text: string, code: string, bodies: {text: string, line: number}[]}} statement
 * @param {{inDoBlock?: boolean}} [context]
 * @returns {{findings: {kind: string, line: number, statement: string}[], reviews: {line: number, statement: string, note: string}[]}}
 */
export function classifyStatement(statement, { inDoBlock = false } = {}) {
  const findings = [];
  const reviews = [];
  const { code, line, text } = statement;
  const kinds = new Set();
  const review = (note) => reviews.push({ line, statement: text, note });

  // GRANT, REVOKE and COMMENT name privileges and trigger events (TRUNCATE,
  // DELETE) without running them.
  if (!NOT_A_COMMAND.test(code)) {
    if (/\bDROP TABLE\b/.test(code)) kinds.add('drop-table');
    if (/\bDROP SCHEMA\b/.test(code)) kinds.add('drop-table');
    if (/\bTRUNCATE\b(?! *(?:ON\b|OR\b|,|\)))/.test(code)) kinds.add('truncate');
    if (/\bDELETE FROM\b/.test(code) || /\bMERGE\b.*\bTHEN DELETE\b/.test(code))
      kinds.add('delete-from');
    if (/\bALTER\b.*\bRENAME\b/.test(code)) kinds.add('rename');
    const otherDrop = new RegExp(
      `${COMMAND_START}DROP (?!TABLE\\b|SCHEMA\\b)((?:MATERIALIZED )?[A-Z]+)\\b`
    ).exec(code);
    // A migration's own pg_temp helpers end with the session; dropping them
    // touches nothing the old release uses.
    const temporary = /^DROP [A-Z ]+? (?:IF EXISTS )?PG_TEMP\./.test(code);
    if (otherDrop && !temporary) {
      review(
        `DROP ${otherDrop[1]}: not refused, but what the old release still uses must stay${
          /\bCASCADE\b/.test(code) ? '; CASCADE also drops every object that depends on it' : ''
        }`
      );
    }
  }

  if (inDoBlock) {
    if (/\bRAISE\b(?! *(?:DEBUG|LOG|INFO|NOTICE|WARNING)\b)/.test(code))
      kinds.add('raise-exception');
    if (new RegExp(`${COMMAND_START}ASSERT\\b`).test(code)) kinds.add('raise-exception');
    if (/\bEXECUTE\b/.test(code)) review('dynamic SQL in a DO block: the check cannot read it');
  }

  const alterTable = ALTER_TABLE.exec(code);
  if (alterTable && !/^RENAME\b/.test(alterTable[1])) {
    const rest = alterTable[1];
    if (/^(?:SET SCHEMA|ATTACH PARTITION|DETACH PARTITION|SET TABLESPACE)\b/.test(rest)) {
      review('an ALTER TABLE form the check does not know');
    } else {
      for (const action of splitActions(rest)) {
        const actionKinds = classifyTableAction(action);
        if (actionKinds === null)
          review(`an ALTER TABLE action the check does not know: ${action}`);
        else for (const kind of actionKinds) kinds.add(kind);
      }
    }
  } else if (
    /^ALTER\b/.test(code) &&
    !alterTable &&
    !kinds.has('rename') &&
    !SAFE_ALTER.test(code)
  ) {
    review('an ALTER form the check does not know');
  }

  for (const kind of STATEMENT_KINDS) {
    if (kinds.has(kind)) findings.push({ kind, line, statement: text });
  }

  // A DO block's body runs now; a function's body runs when it is called.
  const isDoBlock = /^DO\b/.test(code);
  const definesRoutine = /^CREATE (?:OR REPLACE )?(?:FUNCTION|PROCEDURE)\b/.test(code);
  if (!definesRoutine) {
    for (const body of statement.bodies) {
      for (const inner of splitStatements(body.text, body.line)) {
        const nested = classifyStatement(inner, { inDoBlock: inDoBlock || isDoBlock });
        findings.push(...nested.findings);
        reviews.push(...nested.reviews);
      }
    }
  }
  return { findings, reviews };
}

/**
 * Scan one migration file.
 *
 * @param {string} file the file name, `0075_example.sql`
 * @param {string} sql its contents
 */
export function scanMigration(file, sql) {
  const findings = [];
  const reviews = [];
  for (const statement of splitStatements(sql)) {
    const result = classifyStatement(statement);
    findings.push(...result.findings.map((f) => ({ file, ...f })));
    reviews.push(...result.reviews.map((r) => ({ file, ...r })));
  }
  return { findings, reviews };
}

// ---------------------------------------------------------------------------
// The exceptions file
// ---------------------------------------------------------------------------

/** The key that names one exception: one statement kind in one migration. */
export const exceptionKey = (entry) => `${entry.migration} ${entry.statement}`;

/**
 * Parse `policy-exceptions.json`. A missing file (`null`) is the empty, open
 * list: the baseline of a release before #473 has none.
 *
 * @param {string|null} text
 * @param {string} what the file, for the error message
 * @returns {{frozen: boolean, exceptions: {migration: string, statement: string, reason: string, issue: string}[], errors: string[]}}
 */
export function parseExceptions(text, what = EXCEPTIONS_PATH) {
  if (text === null) return { frozen: false, exceptions: [], errors: [] };
  let data;
  try {
    data = JSON.parse(text);
  } catch (error) {
    throw new PolicyInputError(`${what} is not valid JSON: ${error.message}`);
  }
  const errors = [];
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    throw new PolicyInputError(`${what} must hold an object with "frozen" and "exceptions"`);
  }
  for (const key of Object.keys(data)) {
    if (key !== 'frozen' && key !== 'exceptions') errors.push(`${what}: unknown field "${key}"`);
  }
  if (typeof data.frozen !== 'boolean') errors.push(`${what}: "frozen" must be true or false`);
  if (!Array.isArray(data.exceptions)) {
    errors.push(`${what}: "exceptions" must be an array`);
    return { frozen: data.frozen === true, exceptions: [], errors };
  }

  const exceptions = [];
  const seen = new Set();
  data.exceptions.forEach((entry, index) => {
    const at = `${what}: exception ${index + 1}`;
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      errors.push(`${at} must be an object`);
      return;
    }
    const problems = [];
    for (const key of Object.keys(entry)) {
      if (!['migration', 'statement', 'reason', 'issue'].includes(key)) {
        problems.push(`unknown field "${key}"`);
      }
    }
    if (typeof entry.migration !== 'string' || !MIGRATION_FILE.test(entry.migration)) {
      problems.push('"migration" must be a migration file name such as "0075_example.sql"');
    }
    if (!STATEMENT_KINDS.includes(entry.statement)) {
      problems.push(`"statement" must be one of ${STATEMENT_KINDS.join(', ')}`);
    }
    if (typeof entry.reason !== 'string' || entry.reason.trim() === '') {
      problems.push('"reason" must say why the statement is safe or needed');
    }
    if (typeof entry.issue !== 'string' || !ISSUE_REFERENCE.test(entry.issue)) {
      problems.push('"issue" must be an issue reference such as "#473"');
    }
    if (problems.length > 0) {
      errors.push(`${at}: ${problems.join('; ')}`);
      return;
    }
    const key = exceptionKey(entry);
    if (seen.has(key)) {
      errors.push(`${at}: ${entry.statement} in ${entry.migration} is listed twice`);
      return;
    }
    seen.add(key);
    exceptions.push({
      migration: entry.migration,
      statement: entry.statement,
      reason: entry.reason,
      issue: entry.issue,
    });
  });
  return { frozen: data.frozen === true, exceptions, errors };
}

/**
 * The freeze. Once the file says `frozen: true`, the list may not gain an
 * exception the reference does not hold, and once the reference is frozen,
 * the file may not lift the freeze.
 *
 * @param {{frozen: boolean, exceptions: object[]}} current the working copy
 * @param {{frozen: boolean, exceptions: object[]}} reference the list at the reference ref
 * @param {string} referenceName the ref, for the message
 * @returns {string[]} errors
 */
export function checkFreeze(current, reference, referenceName) {
  const errors = [];
  if (reference.frozen && !current.frozen) {
    errors.push(
      `the exception list is frozen at ${referenceName}: "frozen" cannot go back to false`
    );
  }
  if (current.frozen) {
    const known = new Set(reference.exceptions.map(exceptionKey));
    for (const entry of current.exceptions) {
      if (!known.has(exceptionKey(entry))) {
        errors.push(
          `the exception list is frozen: ${entry.statement} in ${entry.migration} (${entry.issue}) is not in the list at ${referenceName}`
        );
      }
    }
  }
  return errors;
}

/**
 * Match the findings of the checked migrations against the exceptions.
 *
 * @param {{file: string, kind: string}[]} findings
 * @param {{migration: string, statement: string}[]} exceptions
 * @param {{checked: string[], present: string[]}} files the checked migration
 *   files, and every migration file of the working copy
 * @returns {{refused: object[], excused: object[], errors: string[]}}
 */
export function applyExceptions(findings, exceptions, { checked, present }) {
  const listed = new Map(exceptions.map((e) => [exceptionKey(e), e]));
  const used = new Set();
  const refused = [];
  const excused = [];
  for (const finding of findings) {
    const key = exceptionKey({ migration: finding.file, statement: finding.kind });
    const entry = listed.get(key);
    if (entry) {
      used.add(key);
      excused.push({ ...finding, issue: entry.issue });
    } else refused.push(finding);
  }
  const errors = [];
  const checkedSet = new Set(checked);
  const presentSet = new Set(present);
  for (const entry of exceptions) {
    if (!presentSet.has(entry.migration)) {
      errors.push(`exception for ${entry.migration} names no migration file`);
    } else if (checkedSet.has(entry.migration) && !used.has(exceptionKey(entry))) {
      errors.push(
        `exception for ${entry.statement} in ${entry.migration} matches no statement: remove it`
      );
    }
  }
  return { refused, excused, errors };
}

// ---------------------------------------------------------------------------
// The journal and the files of the baseline
// ---------------------------------------------------------------------------

/**
 * Parse drizzle-kit's `meta/_journal.json`.
 *
 * @param {string} text
 * @param {string} what the file and ref, for the error message
 */
export function parseJournal(text, what) {
  let data;
  try {
    data = JSON.parse(text);
  } catch (error) {
    throw new PolicyInputError(`${what} is not valid JSON: ${error.message}`);
  }
  if (data === null || typeof data !== 'object' || !Array.isArray(data.entries)) {
    throw new PolicyInputError(`${what} has no "entries" array`);
  }
  return data;
}

const stable = (value) => JSON.stringify(value, Object.keys(value ?? {}).sort());

/**
 * The journal only grows. Every entry of the baseline stays as it is, in its
 * place, and every new entry follows the last with the next `idx` and a later
 * `when`: drizzle's migrator applies only the migrations whose `when` is later
 * than the last one a database ran, so an entry dated earlier is skipped on
 * every database already upgraded.
 *
 * @param {{entries: object[]}} baseline
 * @param {{entries: object[]}} current
 * @param {string} baselineName
 * @returns {string[]} errors
 */
export function checkJournal(baseline, current, baselineName) {
  const errors = [];
  const { entries: baseEntries, ...baseRest } = baseline;
  const { entries, ...rest } = current;
  if (stable(baseRest) !== stable(rest)) {
    errors.push(`the journal's header changed since ${baselineName}`);
  }
  baseEntries.forEach((entry, index) => {
    const now = entries[index];
    if (now === undefined) {
      errors.push(`journal entry ${entry.tag} of ${baselineName} is gone`);
    } else if (stable(entry) !== stable(now)) {
      errors.push(
        `journal entry ${index} changed since ${baselineName}: ${JSON.stringify(entry)} is now ${JSON.stringify(now)}`
      );
    }
  });
  const tags = new Set();
  entries.forEach((entry, index) => {
    if (typeof entry?.tag === 'string') {
      if (tags.has(entry.tag)) errors.push(`journal entry ${entry.tag} appears twice`);
      tags.add(entry.tag);
    }
    if (index < baseEntries.length) return;
    const name = typeof entry?.tag === 'string' ? entry.tag : `at index ${index}`;
    if (entry?.idx !== index) errors.push(`new journal entry ${name} must have idx ${index}`);
    if (typeof entry?.tag !== 'string' || !MIGRATION_FILE.test(`${entry.tag}.sql`)) {
      errors.push(`new journal entry ${name} has no migration tag such as "0075_example"`);
    } else if (Number(entry.tag.slice(0, 4)) !== index) {
      errors.push(
        `new journal entry ${entry.tag} must be numbered ${String(index).padStart(4, '0')}`
      );
    }
    const previous = entries[index - 1];
    if (!Number.isSafeInteger(entry?.when)) {
      errors.push(`new journal entry ${name} has no "when" timestamp`);
    } else if (previous && Number.isSafeInteger(previous.when) && entry.when <= previous.when) {
      errors.push(
        `new journal entry ${name} is dated no later than ${previous.tag}: the migrator would skip it on every upgraded database (regenerate it with drizzle-kit)`
      );
    }
  });
  return errors;
}

/**
 * Every migration file of the baseline is still here, at the same name, with
 * the same contents; and the journal and the files name each other.
 *
 * @param {Map<string, string>} baselineFiles file name → git blob id at the baseline
 * @param {Map<string, string>} currentFiles file name → git blob id in the working copy
 * @param {string[]} journalTags the tags of the working copy's journal
 * @param {string} baselineName
 * @returns {string[]} errors
 */
export function checkBaselineFiles(baselineFiles, currentFiles, journalTags, baselineName) {
  const errors = [];
  const byBlob = new Map([...currentFiles].map(([name, blob]) => [blob, name]));
  for (const [name, blob] of baselineFiles) {
    const now = currentFiles.get(name);
    if (now === undefined) {
      const movedTo = byBlob.get(blob);
      errors.push(
        movedTo
          ? `${name} of ${baselineName} moved to ${movedTo}: a released migration keeps its name`
          : `${name} of ${baselineName} is gone: a released migration stays`
      );
    } else if (now !== blob) {
      errors.push(
        `${name} changed since ${baselineName}: a released migration never changes; write a new one`
      );
    }
  }
  const tags = new Set(journalTags);
  for (const name of currentFiles.keys()) {
    if (!tags.has(name.replace(/\.sql$/, ''))) {
      errors.push(`${name} is not in the journal: the migrator never runs it`);
    }
  }
  for (const tag of tags) {
    if (!currentFiles.has(`${tag}.sql`)) errors.push(`journal entry ${tag} has no ${tag}.sql`);
  }
  return errors;
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

const cell = (text) => String(text).replace(/\|/g, '\\|').replace(/\s+/g, ' ');
const shorten = (text, max = 160) => (text.length > max ? `${text.slice(0, max - 1)}…` : text);

/**
 * The Markdown report: the job summary and the console output.
 *
 * @param {{baseline: string, freezeRef: string, checked: string[], errors: string[],
 *   refused: object[], excused: object[], reviews: object[],
 *   exceptions: {frozen: boolean, exceptions: object[]}}} report
 */
export function renderSummary(report) {
  const lines = ['## Migration policy', ''];
  const failed = report.errors.length > 0 || report.refused.length > 0;
  lines.push(
    `${failed ? '❌ Fails' : '✅ Passes'} · baseline \`${report.baseline}\` · ${
      report.checked.length === 0
        ? 'no migration added since it'
        : `${report.checked.length} migration${report.checked.length === 1 ? '' : 's'} checked: ${report.checked.map((f) => `\`${f}\``).join(', ')}`
    }`
  );
  lines.push('');

  if (report.errors.length > 0) {
    lines.push('### Errors', '');
    for (const error of report.errors) lines.push(`- ${error}`);
    lines.push('');
  }
  if (report.refused.length > 0) {
    lines.push('### Refused statements', '');
    lines.push(
      'List each in `libs/infra/db/drizzle/policy-exceptions.json` with a reason and an issue, or write the change as expand-then-switch (see the migration policy page).',
      ''
    );
    lines.push(
      '| Migration | Line | Statement kind | Why | Statement |',
      '| --- | --- | --- | --- | --- |'
    );
    for (const f of report.refused) {
      lines.push(
        `| ${cell(f.file)} | ${f.line} | ${f.kind} | ${cell(KIND_REASONS[f.kind])} | \`${cell(shorten(f.statement))}\` |`
      );
    }
    lines.push('');
  }
  if (report.reviews.length > 0) {
    lines.push('### For review (not refused)', '');
    lines.push('| Migration | Line | Note | Statement |', '| --- | --- | --- | --- |');
    for (const r of report.reviews) {
      lines.push(
        `| ${cell(r.file)} | ${r.line} | ${cell(r.note)} | \`${cell(shorten(r.statement))}\` |`
      );
    }
    lines.push('');
  }

  const { frozen, exceptions } = report.exceptions;
  lines.push(`### Exceptions (${exceptions.length}, ${frozen ? 'frozen' : 'open'})`, '');
  if (exceptions.length === 0) {
    lines.push('None.');
  } else {
    const applied = new Set(
      report.excused.map((f) => exceptionKey({ migration: f.file, statement: f.kind }))
    );
    lines.push(
      '| Migration | Statement kind | Issue | Reason | Used now |',
      '| --- | --- | --- | --- | --- |'
    );
    for (const e of exceptions) {
      lines.push(
        `| ${cell(e.migration)} | ${e.statement} | ${e.issue} | ${cell(e.reason)} | ${applied.has(exceptionKey(e)) ? 'yes' : 'no'} |`
      );
    }
  }
  if (frozen)
    lines.push('', `Frozen: no exception may be added (compared with \`${report.freezeRef}\`).`);
  lines.push('');
  return lines.join('\n');
}
