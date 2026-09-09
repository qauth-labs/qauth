#!/usr/bin/env node
/**
 * spec-matrix — join QAuth's hand-authored normative requirement rows to the
 * tests that prove them, and gate CI on the result.
 *
 * QAuth's requirements are written by the IETF and the OIDF, not by us, and the
 * test suite already cites them in `describe`/`it` titles. What was missing was
 * the join. This script reads:
 *
 *   - `docs/conformance/specs.json`               — the spec alias registry
 *   - `docs/conformance/requirements/<id>.json`   — the requirement rows
 *   - a Vitest JSON report                        — the run that proves them
 *
 * and writes `matrix.md` (for a human or an OIDF certification reviewer),
 * `matrix.json` (for machines) and a GitHub job summary.
 *
 * Deliberately NOT an Nx project: it consumes a repo-wide test report that no
 * single project owns, so it would cache on the wrong inputs.
 *
 * Zero runtime dependencies — Node's standard library only.
 *
 * Exit codes:
 *   0  clean
 *   1  gate failure (an unproven `covered` row, evidence that only ever skips,
 *      a malformed waiver, an unresolvable `decision`/`evidenceRef`, or an
 *      orphan citation in a sealed spec)
 *   2  input error (missing, empty or shape-changed report; unreadable or
 *      unparseable conformance data; bad arguments)
 *
 * A missing, empty or shape-changed report MUST exit non-zero and must never
 * render as "everything proven". Certification evidence that fails open is
 * worse than no evidence at all. `scripts/spec-matrix.test.ts` holds that
 * property down.
 *
 * The join key is `(specId, section)`, and a spec section is frequently coarser
 * than a requirement — OIDC Core §2 declares the whole ID Token claim set. A
 * row may therefore carry `evidenceMatch`, a pattern the citing test's
 * `fullName` must ALSO match before it counts as proof of that row, so the
 * Evidence column names a test that really proves the sentence beside it.
 *
 * Usage:
 *   node scripts/spec-matrix.mjs --vitest-report dist/vitest/unit-report.json
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Repo-relative when the path is inside the repo, absolute when it is not. */
function repoPath(absolute) {
  const rel = relative(REPO_ROOT, absolute);
  return rel === '' || rel.startsWith('..') ? absolute : rel;
}

const EXIT_OK = 0;
const EXIT_GATE = 1;
const EXIT_INPUT = 2;

/** RFC 2119 / RFC 8174 keywords a requirement row may carry as its `level`. */
const LEVELS = new Set([
  'MUST',
  'MUST NOT',
  'SHALL',
  'SHALL NOT',
  'REQUIRED',
  'SHOULD',
  'SHOULD NOT',
  'RECOMMENDED',
  'NOT RECOMMENDED',
  'MAY',
  'OPTIONAL',
]);

const STATUSES = new Set(['covered', 'manual', 'waived', 'n/a']);

/** A section number as cited and as declared: dotted decimals, no `§`. */
const SECTION_SHAPE = /^\d+(?:\.\d+)*$/;

/**
 * Spec-name tokens that are NOT in the registry but must still anchor a
 * section reference, so that a bare `§X.Y` is never mis-attributed to a
 * registered spec named earlier in the same test name. `describe('key
 * attestation (HAIP §4.5.1)') > it('applies the §5.9.3 prohibition')` must
 * attribute both sections to HAIP — i.e. to nothing — rather than to whatever
 * registered spec an outer `describe` happened to mention.
 */
const FOREIGN_ANCHOR =
  'RFC\\s?\\d{4}[a-z]*|draft-[A-Za-z0-9.-]+|ADR-\\d+|OID4VCI|OID4VP|HAIP|CIMD|SD-JWT|eIDAS|ISO\\/IEC|OpenID|OIDC|OAuth';

/** `§4.2.1.3`, `§2`, or the spelled-out `Section 4.2`. */
const SECTION_TOKEN = /(?:§|Section\s+)(\d+(?:\.\d+)*)/g;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

class InputError extends Error {}

/** A gate failure: rendered as a `::error` annotation and exits 1. */
class Finding {
  constructor({ file, line, title, message }) {
    this.file = file;
    this.line = line;
    this.title = title;
    this.message = message;
  }
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

const USAGE = `Usage: node scripts/spec-matrix.mjs --vitest-report <path> [options]

Options:
  --vitest-report <path>   Vitest JSON report to join against (required)
  --conformance-dir <dir>  default: docs/conformance
  --out-dir <dir>          default: dist/spec-matrix
  --summary <path>         Markdown job summary sink
                           (default: $GITHUB_STEP_SUMMARY, when set)
  --no-summary             Never write a job summary
  --help                   Print this and exit 0
`;

function parseArgs(argv) {
  const opts = {
    vitestReport: null,
    conformanceDir: join(REPO_ROOT, 'docs', 'conformance'),
    outDir: join(REPO_ROOT, 'dist', 'spec-matrix'),
    summary: process.env.GITHUB_STEP_SUMMARY || null,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => {
      const value = argv[++i];
      if (value === undefined) throw new InputError(`${arg} requires a value`);
      return value;
    };
    switch (arg) {
      case '--vitest-report':
        opts.vitestReport = next();
        break;
      case '--conformance-dir':
        opts.conformanceDir = resolve(next());
        break;
      case '--out-dir':
        opts.outDir = resolve(next());
        break;
      case '--summary':
        opts.summary = resolve(next());
        break;
      case '--no-summary':
        opts.summary = null;
        break;
      case '--help':
      case '-h':
        opts.help = true;
        break;
      default:
        throw new InputError(`unknown argument: ${arg}`);
    }
  }
  if (!opts.help && !opts.vitestReport) {
    throw new InputError('--vitest-report is required');
  }
  if (opts.vitestReport) opts.vitestReport = resolve(opts.vitestReport);
  return opts;
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

function readJson(path, what) {
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    throw new InputError(`cannot read ${what} at ${path}: ${err.message}`);
  }
  if (raw.trim() === '') throw new InputError(`${what} at ${path} is empty`);
  try {
    return { raw, data: JSON.parse(raw) };
  } catch (err) {
    throw new InputError(`${what} at ${path} is not valid JSON: ${err.message}`);
  }
}

function loadRegistry(conformanceDir) {
  const path = join(conformanceDir, 'specs.json');
  const { data } = readJson(path, 'the spec registry');
  if (!data || typeof data !== 'object' || !Array.isArray(data.specs)) {
    throw new InputError(`${path} must be an object with a "specs" array`);
  }
  const specs = [];
  const seen = new Set();
  for (const spec of data.specs) {
    if (!spec || typeof spec.id !== 'string' || spec.id === '') {
      throw new InputError(`${path}: every spec needs a non-empty string "id"`);
    }
    if (seen.has(spec.id)) throw new InputError(`${path}: duplicate spec id "${spec.id}"`);
    seen.add(spec.id);
    if (!Array.isArray(spec.aliases) || spec.aliases.length === 0) {
      throw new InputError(`${path}: spec "${spec.id}" needs a non-empty "aliases" array`);
    }
    if (typeof spec.sealed !== 'boolean') {
      throw new InputError(`${path}: spec "${spec.id}" needs a boolean "sealed"`);
    }
    specs.push({
      id: spec.id,
      name: typeof spec.name === 'string' ? spec.name : spec.id,
      url: typeof spec.url === 'string' ? spec.url : null,
      aliases: spec.aliases,
      sealed: spec.sealed,
      scopeNote: typeof spec.scopeNote === 'string' ? spec.scopeNote : null,
    });
  }
  if (specs.length === 0) throw new InputError(`${path} registers no specs`);
  return specs;
}

function loadRequirements(conformanceDir, specs) {
  for (const spec of specs) {
    const path = join(conformanceDir, 'requirements', `${spec.id}.json`);
    const { raw, data } = readJson(path, `the requirement rows for "${spec.id}"`);
    if (!data || typeof data !== 'object' || !Array.isArray(data.requirements)) {
      throw new InputError(`${path} must be an object with a "requirements" array`);
    }
    if (data.specId !== spec.id) {
      throw new InputError(`${path}: "specId" is "${data.specId}", expected "${spec.id}"`);
    }
    spec.file = repoPath(path);
    spec.rawLines = raw.split('\n');
    spec.requirements = data.requirements;
  }
}

/**
 * Load and hard-validate the Vitest JSON report.
 *
 * This is the fail-closed seam. A report that is missing, empty, or no longer
 * the shape we read is an input error, never "no citations found".
 */
function loadReport(path) {
  if (!existsSync(path)) {
    throw new InputError(
      `no Vitest report at ${path}. The gate needs a complete report; run the suite with ` +
        `\`--reporter=json --outputFile.json=${repoPath(path)}\` first.`
    );
  }
  const { data } = readJson(path, 'the Vitest report');
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new InputError(`${path}: expected a JSON object at the top level`);
  }
  if (!Array.isArray(data.testResults)) {
    throw new InputError(`${path}: expected a "testResults" array — the reporter shape changed`);
  }
  const assertions = [];
  for (const suite of data.testResults) {
    if (!suite || !Array.isArray(suite.assertionResults)) continue;
    for (const assertion of suite.assertionResults) {
      assertions.push({
        ...assertion,
        suiteName: typeof suite.name === 'string' ? suite.name : '',
      });
    }
  }
  if (assertions.length === 0) {
    throw new InputError(
      `${path} contains no test assertions. An empty report cannot prove anything, ` +
        `so it is treated as a failure rather than as a clean matrix.`
    );
  }
  const first = assertions[0];
  if (typeof first.fullName !== 'string' || typeof first.status !== 'string') {
    throw new InputError(
      `${path}: the first assertion is missing a string "fullName" or "status" — ` +
        `the reporter shape changed and the join key is no longer readable.`
    );
  }
  return assertions;
}

// ---------------------------------------------------------------------------
// Citation extraction
// ---------------------------------------------------------------------------

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Build one anchor matcher over every registered alias (longest first, so
 * `OIDC Core 1.0` wins over `OIDC Core`) followed by the foreign anchors.
 */
function buildAnchorMatcher(specs) {
  const aliasToSpec = new Map();
  const aliases = [];
  for (const spec of specs) {
    for (const alias of spec.aliases) {
      aliasToSpec.set(alias.toLowerCase(), spec.id);
      aliases.push(alias);
    }
  }
  aliases.sort((a, b) => b.length - a.length);
  // Registered aliases first, so `OIDC Core 1.0` wins over `OIDC Core` and both
  // win over the bare `OIDC` foreign anchor at the same position.
  const source = `(?<![A-Za-z0-9])(?:${aliases.map(escapeRegExp).join('|')}|${FOREIGN_ANCHOR})(?![A-Za-z0-9])`;
  return { regex: new RegExp(source, 'gi'), aliasToSpec };
}

/**
 * Extract `(specId, section)` citations from one test's full name.
 *
 * Each section token is attributed to the nearest anchor to its left, so a
 * `describe`-level spec name carries down to bare `§X.Y` references in its
 * leaves, and `draft-14 §5/§6` yields two citations. A section whose nearest
 * anchor is unregistered (or which has no anchor at all) is dropped.
 */
function extractCitations(fullName, matcher) {
  const anchors = [];
  matcher.regex.lastIndex = 0;
  for (const match of fullName.matchAll(matcher.regex)) {
    anchors.push({
      index: match.index,
      specId: matcher.aliasToSpec.get(match[0].toLowerCase()) ?? null,
    });
  }
  const citations = [];
  SECTION_TOKEN.lastIndex = 0;
  for (const match of fullName.matchAll(SECTION_TOKEN)) {
    let anchor = null;
    for (const candidate of anchors) {
      if (candidate.index < match.index) anchor = candidate;
      else break;
    }
    if (!anchor || !anchor.specId) continue;
    citations.push({ specId: anchor.specId, section: match[1] });
  }
  return citations;
}

/** A test citing §2.4 proves a row declared at §2.4 or at §2 — never at §2.4.1. */
function citationProves(citedSection, rowSection) {
  return citedSection === rowSection || citedSection.startsWith(`${rowSection}.`);
}

/**
 * Compile a row's optional `evidenceMatch` narrowing pattern.
 *
 * The join key is `(specId, section)`, and a section is often far coarser than
 * a requirement: OIDC Core §2 declares the whole ID Token claim set and RFC
 * 8414 §2 the whole metadata document, so EVERY test citing §2 would otherwise
 * count as proof of EVERY §2 row. That is how a certification artifact ends up
 * citing an `acr`-value test as its evidence that the ID Token carries `iss` —
 * and how deleting the test that really proves `iss` leaves the gate green.
 *
 * `evidenceMatch` closes that: a citing test counts as evidence for the row
 * only if its `fullName` also matches this pattern (case-insensitive). It can
 * only ever REMOVE evidence, never add it, so a row that carries one is
 * strictly harder to prove than one that does not.
 *
 * Returns `null` when the row declares no narrowing.
 */
function compileEvidenceMatch(row) {
  if (row?.evidenceMatch === undefined) return null;
  return new RegExp(row.evidenceMatch, 'i');
}

// ---------------------------------------------------------------------------
// Validation and join
// ---------------------------------------------------------------------------

/** Line of the row's `"id"` member in its source file, for the annotation. */
function findRowLine(spec, rowId) {
  const needle = `"id": ${JSON.stringify(rowId)}`;
  const index = spec.rawLines.findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

/** GitHub's heading slug: lowercase, drop punctuation, spaces become hyphens. */
function slugify(heading) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .replace(/\s/g, '-');
}

/** `path`, or `path#anchor` where the anchor must exist as a markdown heading. */
function resolveReference(reference) {
  const [path, anchor] = reference.split('#');
  if (path === '') return `"${reference}" has no path`;
  const absolute = isAbsolute(path) ? path : join(REPO_ROOT, path);
  if (!existsSync(absolute)) return `"${path}" does not exist`;
  if (!anchor) return null;
  let contents;
  try {
    contents = readFileSync(absolute, 'utf8');
  } catch (err) {
    return `"${path}" could not be read: ${err.message}`;
  }
  const slugs = new Set(
    contents
      .split('\n')
      .filter((line) => /^#{1,6}\s+/.test(line))
      .map((line) => slugify(line.replace(/^#{1,6}\s+/, '')))
  );
  return slugs.has(anchor) ? null : `"${path}" has no heading anchored at "#${anchor}"`;
}

const ISSUE_REF = /^#\d+$/;
const ISSUE_URL = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/issues\/\d+$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Validate one row's shape and its status-specific obligations. Returns the
 * findings; an empty array means the row is well formed.
 */
function validateRow(spec, row, index) {
  const findings = [];
  const where = typeof row?.id === 'string' ? row.id : `row #${index + 1}`;
  const line = typeof row?.id === 'string' ? findRowLine(spec, row.id) : 1;
  const fail = (message) =>
    findings.push(
      new Finding({ file: spec.file, line, title: `${spec.id} ${where}`, message: message })
    );

  if (!row || typeof row !== 'object' || Array.isArray(row)) {
    fail('a requirement must be a JSON object');
    return findings;
  }
  if (typeof row.id !== 'string' || row.id === '') fail('missing a non-empty string "id"');
  if (typeof row.section !== 'string' || !SECTION_SHAPE.test(row.section)) {
    fail('"section" must be dotted decimals with no "§", e.g. "3.1.2.1"');
  }
  if (typeof row.level !== 'string' || !LEVELS.has(row.level)) {
    fail(`"level" must be one of: ${[...LEVELS].join(', ')}`);
  }
  if (typeof row.quote !== 'string' || row.quote.trim() === '') {
    fail('"quote" must be the verbatim normative sentence');
  }
  if (typeof row.status !== 'string' || !STATUSES.has(row.status)) {
    fail(`"status" must be one of: ${[...STATUSES].join(', ')}`);
    return findings;
  }

  if (row.evidenceMatch !== undefined) {
    if (row.status !== 'covered') {
      fail(
        '"evidenceMatch" narrows which citing tests count as proof, so it only means anything on a "covered" row'
      );
    }
    if (typeof row.evidenceMatch !== 'string' || row.evidenceMatch === '') {
      fail('"evidenceMatch" must be a non-empty regular-expression source string');
    } else {
      try {
        compileEvidenceMatch(row);
      } catch (err) {
        fail(`"evidenceMatch" is not a valid regular expression: ${err.message}`);
      }
    }
  }

  if (row.status === 'manual') {
    if (typeof row.evidenceRef !== 'string' || row.evidenceRef === '') {
      fail('a "manual" row must carry an "evidenceRef" path to the evidence');
    } else {
      const problem = resolveReference(row.evidenceRef);
      if (problem) fail(`"evidenceRef" does not resolve: ${problem}`);
    }
  }

  if (row.status === 'waived') {
    if (typeof row.reason !== 'string' || row.reason.trim() === '') {
      fail('a "waived" row must carry a "reason" — what applies and why we do not satisfy it');
    }
    if (typeof row.decision !== 'string' || row.decision === '') {
      fail('a "waived" row must carry a "decision" — an issue reference or a path in the repo');
    } else if (!ISSUE_REF.test(row.decision) && !ISSUE_URL.test(row.decision)) {
      const problem = resolveReference(row.decision);
      if (problem)
        fail(`"decision" is neither an issue reference nor a resolvable path: ${problem}`);
    }
    if (
      typeof row.revisit !== 'string' ||
      (row.revisit !== 'never' && !ISO_DATE.test(row.revisit))
    ) {
      fail('a "waived" row must carry a "revisit" — an ISO date (YYYY-MM-DD) or "never"');
    } else if (row.revisit !== 'never' && Number.isNaN(Date.parse(row.revisit))) {
      fail(`"revisit" is not a real date: ${row.revisit}`);
    }
  }

  if (row.status === 'n/a' && (typeof row.reason !== 'string' || row.reason.trim() === '')) {
    fail('an "n/a" row must carry a "reason" — why the requirement never applied');
  }

  return findings;
}

/**
 * Join rows to citing tests and decide the gate.
 */
function buildMatrix(specs, assertions, matcher) {
  const findings = [];

  // Index every citation in the run by spec.
  const citationsBySpec = new Map(specs.map((spec) => [spec.id, []]));
  // How much of the suite the joiner can actually see. Derived here on every
  // run so no document has to hand-copy the figure and watch it go stale.
  const citing = { assertions: 0, files: new Set() };
  for (const assertion of assertions) {
    const fullName = typeof assertion.fullName === 'string' ? assertion.fullName : '';
    if (fullName === '') continue;
    const extracted = extractCitations(fullName, matcher);
    if (extracted.length > 0) {
      citing.assertions++;
      if (assertion.suiteName) citing.files.add(assertion.suiteName);
    }
    for (const citation of extracted) {
      citationsBySpec.get(citation.specId)?.push({
        section: citation.section,
        fullName,
        status: typeof assertion.status === 'string' ? assertion.status : 'unknown',
        file: assertion.suiteName ? repoPath(assertion.suiteName) : '',
        matched: false,
      });
    }
  }

  const rendered = [];
  for (const spec of specs) {
    const citations = citationsBySpec.get(spec.id) ?? [];
    const rows = [];
    spec.requirements.forEach((row, index) => {
      const rowFindings = validateRow(spec, row, index);
      findings.push(...rowFindings);
      if (rowFindings.length > 0 && !STATUSES.has(row?.status)) return;

      // A broken `evidenceMatch` must never widen the evidence back out, so a
      // pattern that will not compile matches nothing at all. `validateRow`
      // has already raised the finding that explains why.
      let narrow;
      try {
        narrow = compileEvidenceMatch(row);
      } catch {
        narrow = /(?!)/;
      }

      const proving = [];
      const skipped = [];
      if (typeof row?.section === 'string') {
        for (const citation of citations) {
          if (!citationProves(citation.section, row.section)) continue;
          // The section match alone answers the citation. Narrowing decides
          // whether this ROW may lean on it, and must not turn a sibling row's
          // legitimate test into an orphan.
          citation.matched = true;
          if (narrow && !narrow.test(citation.fullName)) continue;
          if (citation.status === 'passed') proving.push(citation);
          else skipped.push(citation);
        }
      }

      if (row?.status === 'covered' && proving.length === 0) {
        const line = typeof row.id === 'string' ? findRowLine(spec, row.id) : 1;
        const pinned = narrow ? ` and matches its evidenceMatch \`${row.evidenceMatch}\`` : '';
        const detail =
          skipped.length > 0
            ? `its only citing tests did not pass (${skipped
                .map((c) => `${c.status}: ${c.fullName}`)
                .slice(0, 3)
                .join('; ')})`
            : `no passing test in the report cites it${pinned}`;
        findings.push(
          new Finding({
            file: spec.file,
            line,
            title: `unproven: ${spec.id} §${row.section}`,
            message:
              `${spec.name} §${row.section} (${row.id}) is declared "covered" but ${detail}. ` +
              `Cite it from the test that proves it, e.g. "(${spec.aliases[0]} §${row.section})" ` +
              `in the describe or it title, or change the row's status.`,
          })
        );
      }

      rows.push({
        ...row,
        provingTests: proving.map((c) => ({ fullName: c.fullName, file: c.file })),
        nonPassingTests: skipped.map((c) => ({
          fullName: c.fullName,
          file: c.file,
          status: c.status,
        })),
      });
    });

    // Orphan citations: a test points at this spec but no row answers it.
    const orphans = new Map();
    for (const citation of citations) {
      if (citation.matched) continue;
      const key = citation.section;
      if (!orphans.has(key)) orphans.set(key, []);
      orphans.get(key).push(citation.fullName);
    }
    for (const [section, tests] of orphans) {
      if (!spec.sealed) continue;
      findings.push(
        new Finding({
          file: spec.file,
          line: 1,
          title: `orphan citation: ${spec.id} §${section}`,
          message:
            `${tests.length} test(s) cite ${spec.name} §${section} but no requirement row ` +
            `covers that section, and this spec is sealed. Add the row, or unseal the spec ` +
            `in docs/conformance/specs.json. First: ${tests[0]}`,
        })
      );
    }

    rendered.push({
      id: spec.id,
      name: spec.name,
      url: spec.url,
      sealed: spec.sealed,
      scopeNote: spec.scopeNote,
      file: spec.file,
      rows,
      orphans: [...orphans].map(([section, tests]) => ({ section, tests })),
      citationCount: citations.length,
    });
  }

  return {
    specs: rendered,
    findings,
    citing: { assertions: citing.assertions, files: citing.files.size },
  };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const STATUS_LABEL = {
  covered: 'covered',
  manual: 'manual',
  waived: 'waived',
  'n/a': 'n/a',
};

function tally(matrix) {
  const counts = { covered: 0, manual: 0, waived: 0, 'n/a': 0, total: 0 };
  for (const spec of matrix.specs) {
    for (const row of spec.rows) {
      counts.total++;
      if (row.status in counts) counts[row.status]++;
    }
  }
  return counts;
}

function escapeCell(text) {
  return String(text).replace(/\|/g, '\\|').replace(/\n+/g, ' ').trim();
}

function renderMarkdown(matrix, meta) {
  const counts = tally(matrix);
  const out = [];
  out.push('# QAuth spec-conformance matrix');
  out.push('');
  out.push(
    'Which normative requirements QAuth satisfies, and which it knowingly does not. ' +
      'Generated by `scripts/spec-matrix.mjs` — do not edit; edit the rows under ' +
      '`docs/conformance/requirements/` instead.'
  );
  out.push('');
  out.push(`- Generated: ${meta.generatedAt}`);
  out.push(`- Vitest report: \`${meta.report}\` (${meta.assertionCount} assertions)`);
  out.push(
    `- Joinable corpus: **${meta.citingAssertionCount}** of those assertions ` +
      `(${((meta.citingAssertionCount / meta.assertionCount) * 100).toFixed(1)}%) cite a ` +
      `registered spec section in a \`describe\` or \`it\` title, across ` +
      `${meta.citingFileCount} test file(s). Everything else is out of scope by design ` +
      `— see \`docs/conformance/README.md\`.`
  );
  out.push(
    `- Rows: **${counts.total}** — ${counts.covered} covered, ${counts.manual} manual, ` +
      `${counts.waived} waived, ${counts['n/a']} n/a`
  );
  out.push(
    `- Gate: ${meta.findingCount === 0 ? '**pass**' : `**${meta.findingCount} failure(s)**`}`
  );
  out.push('');

  out.push('## Proven by the suite');
  out.push('');
  for (const spec of matrix.specs) {
    const rows = spec.rows.filter((row) => row.status === 'covered' || row.status === 'manual');
    out.push(`### ${spec.name}${spec.sealed ? '' : ' (unsealed)'}`);
    out.push('');
    if (spec.url) out.push(`<${spec.url}>`);
    if (spec.scopeNote) out.push(`\n${spec.scopeNote}`);
    out.push('');
    if (rows.length === 0) {
      out.push('_No rows yet._');
      out.push('');
      continue;
    }
    out.push('| Section | Level | Status | Requirement | Evidence |');
    out.push('| --- | --- | --- | --- | --- |');
    for (const row of rows) {
      const evidence =
        row.status === 'manual'
          ? `\`${row.evidenceRef}\``
          : row.provingTests.length === 0
            ? '**none**'
            : `${row.provingTests.length} test(s), e.g. ${escapeCell(row.provingTests[0].fullName)}`;
      out.push(
        `| §${row.section} | ${row.level} | ${STATUS_LABEL[row.status]} | ` +
          `${escapeCell(row.quote)} | ${escapeCell(evidence)} |`
      );
    }
    out.push('');
  }

  out.push('## Knowingly not satisfied, and out of profile');
  out.push('');
  out.push(
    'A **waived** row applied to QAuth and we chose not to satisfy it. An **n/a** row never ' +
      'applied — a client-side obligation, or a flow QAuth does not implement. Collapsing the ' +
      'two would destroy the document for a certification reviewer.'
  );
  out.push('');

  const waived = matrix.specs.flatMap((spec) =>
    spec.rows.filter((row) => row.status === 'waived').map((row) => ({ spec, row }))
  );
  out.push('### Waived');
  out.push('');
  if (waived.length === 0) {
    out.push('_Nothing waived._');
  } else {
    out.push('| Spec | Section | Level | Requirement | Why not | Decision | Revisit |');
    out.push('| --- | --- | --- | --- | --- | --- | --- |');
    for (const { spec, row } of waived) {
      out.push(
        `| ${spec.name} | §${row.section} | ${row.level} | ${escapeCell(row.quote)} | ` +
          `${escapeCell(row.reason)} | ${escapeCell(row.decision)} | ${row.revisit} |`
      );
    }
  }
  out.push('');

  const notApplicable = matrix.specs.flatMap((spec) =>
    spec.rows.filter((row) => row.status === 'n/a').map((row) => ({ spec, row }))
  );
  out.push('### Not applicable');
  out.push('');
  if (notApplicable.length === 0) {
    out.push('_Nothing marked n/a._');
  } else {
    out.push('| Spec | Section | Level | Requirement | Why it never applied |');
    out.push('| --- | --- | --- | --- | --- |');
    for (const { spec, row } of notApplicable) {
      out.push(
        `| ${spec.name} | §${row.section} | ${row.level} | ${escapeCell(row.quote)} | ` +
          `${escapeCell(row.reason)} |`
      );
    }
  }
  out.push('');

  const orphans = matrix.specs.filter((spec) => spec.orphans.length > 0);
  if (orphans.length > 0) {
    out.push('## Citations with no row');
    out.push('');
    out.push(
      'Tests citing a registered spec at a section no requirement row covers. In a sealed ' +
        'spec this is a build failure; in an unsealed one it is the backlog.'
    );
    out.push('');
    out.push('| Spec | Section | Sealed | Tests |');
    out.push('| --- | --- | --- | --- |');
    for (const spec of orphans) {
      for (const orphan of spec.orphans) {
        out.push(
          `| ${spec.name} | §${orphan.section} | ${spec.sealed ? 'yes' : 'no'} | ` +
            `${orphan.tests.length} |`
        );
      }
    }
    out.push('');
  }

  return `${out.join('\n')}\n`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function emitAnnotations(findings) {
  for (const finding of findings) {
    const props = [`file=${finding.file}`, `line=${finding.line}`, `title=${finding.title}`].join(
      ','
    );
    const message = finding.message.replace(/\r?\n/g, '%0A');
    process.stderr.write(`::error ${props}::${message}\n`);
  }
}

function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`spec-matrix: ${err.message}\n\n${USAGE}`);
    return EXIT_INPUT;
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    return EXIT_OK;
  }

  let specs;
  let assertions;
  try {
    specs = loadRegistry(opts.conformanceDir);
    loadRequirements(opts.conformanceDir, specs);
    assertions = loadReport(opts.vitestReport);
  } catch (err) {
    if (!(err instanceof InputError)) throw err;
    process.stderr.write(`spec-matrix: ${err.message}\n`);
    return EXIT_INPUT;
  }

  const matcher = buildAnchorMatcher(specs);
  const { specs: rendered, findings, citing } = buildMatrix(specs, assertions, matcher);
  const matrix = { specs: rendered };

  const meta = {
    generatedAt: new Date().toISOString(),
    report: repoPath(opts.vitestReport),
    assertionCount: assertions.length,
    citingAssertionCount: citing.assertions,
    citingFileCount: citing.files,
    findingCount: findings.length,
  };

  const markdown = renderMarkdown(matrix, meta);
  mkdirSync(opts.outDir, { recursive: true });
  writeFileSync(join(opts.outDir, 'matrix.md'), markdown);
  writeFileSync(
    join(opts.outDir, 'matrix.json'),
    `${JSON.stringify(
      {
        meta,
        counts: tally(matrix),
        findings: findings.map((f) => ({ ...f })),
        specs: rendered,
      },
      null,
      2
    )}\n`
  );

  if (opts.summary) {
    try {
      appendFileSync(opts.summary, markdown);
    } catch (err) {
      process.stderr.write(`spec-matrix: could not write the job summary: ${err.message}\n`);
    }
  }

  const counts = tally(matrix);
  process.stdout.write(
    `spec-matrix: ${counts.total} rows across ${rendered.length} specs — ` +
      `${counts.covered} covered, ${counts.manual} manual, ${counts.waived} waived, ` +
      `${counts['n/a']} n/a; ${assertions.length} assertions read from ${meta.report}, ` +
      `${meta.citingAssertionCount} of them citing a registered spec across ` +
      `${meta.citingFileCount} file(s)\n`
  );
  process.stdout.write(`spec-matrix: wrote ${repoPath(opts.outDir)}/matrix.{md,json}\n`);

  if (findings.length > 0) {
    emitAnnotations(findings);
    process.stderr.write(`spec-matrix: ${findings.length} gate failure(s)\n`);
    return EXIT_GATE;
  }
  return EXIT_OK;
}

process.exitCode = main();
