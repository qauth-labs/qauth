#!/usr/bin/env node
/**
 * Spec-conformance matrix (#400): join hand-authored normative requirements to
 * the tests that prove them.
 *
 * "Which normative requirements do we satisfy, and which do we knowingly not"
 * is currently unanswerable without reading the whole suite — and it is a
 * deliverable for OpenID Foundation OP certification, not overhead
 * (`docs/oidf-op-certification-runbook.md` already anticipates it).
 *
 * Node ESM, zero runtime dependencies, deliberately NOT an Nx project: it reads
 * a repo-wide artifact no single project owns and would cache on the wrong
 * inputs.
 *
 * Exit codes:
 *   0  clean
 *   1  gate failure — an unproven `covered` row, evidence that is only skipped,
 *      a malformed waiver, an unresolvable `decision`/`evidenceRef`, or an
 *      orphan citation in a SEALED spec. Emitted as `::error` annotations so
 *      they land on the PR diff.
 *   2  input error — a missing, empty or shape-changed report; unreadable
 *      registry or requirement files.
 *
 * The exit-2 class is the important one. Certification evidence that fails OPEN
 * is worse than none: a report that silently arrived empty would render every
 * row as "no citing tests" or, worse, let a `covered` row pass unnoticed. So the
 * report is asserted to have assertions, and the first one is asserted to carry
 * `fullName` and `status`, before anything is joined.
 *
 * Usage:
 *   node scripts/spec-matrix.mjs --vitest-report <path> [--out dist/conformance]
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CONFORMANCE_DIR = join(REPO_ROOT, 'docs', 'conformance');

const VALID_STATUSES = ['covered', 'manual', 'waived', 'n/a'];

function inputError(message) {
  process.stderr.write(`spec-matrix: ${message}\n`);
  process.exit(2);
}

function parseArgs(argv) {
  const args = { report: null, out: join(REPO_ROOT, 'dist', 'conformance') };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--vitest-report') args.report = argv[++i];
    else if (argv[i] === '--out') args.out = argv[++i];
  }
  if (!args.report) inputError('--vitest-report <path> is required');
  return args;
}

function readJson(path, what) {
  if (!existsSync(path)) inputError(`${what} not found at ${path}`);
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    inputError(`${what} at ${path} is not valid JSON: ${err.message}`);
  }
}

/* -------------------------------------------------------------------------- */
/*                                  Inputs                                     */
/* -------------------------------------------------------------------------- */

function loadRegistry() {
  const registry = readJson(join(CONFORMANCE_DIR, 'specs.json'), 'spec registry');
  if (!Array.isArray(registry.specs) || registry.specs.length === 0) {
    inputError('spec registry has no `specs` array');
  }
  return registry.specs;
}

function loadRequirements(specs) {
  const dir = join(CONFORMANCE_DIR, 'requirements');
  if (!existsSync(dir)) inputError(`requirements directory not found at ${dir}`);

  const known = new Set(specs.map((spec) => spec.id));
  const rows = [];

  for (const file of readdirSync(dir)
    .filter((name) => name.endsWith('.json'))
    .sort()) {
    const doc = readJson(join(dir, file), `requirements file ${file}`);
    if (!known.has(doc.spec)) {
      inputError(`${file} declares spec "${doc.spec}", which is not in specs.json`);
    }
    for (const requirement of doc.requirements ?? []) {
      rows.push({
        ...requirement,
        specId: doc.spec,
        sourceFile: `docs/conformance/requirements/${file}`,
      });
    }
  }
  return rows;
}

/**
 * Read the Vitest JSON report, asserting enough of its shape that a silently
 * changed or truncated one cannot render as "everything proven".
 */
function loadAssertions(reportPath) {
  const report = readJson(reportPath, 'vitest report');
  const files = report.testResults;
  if (!Array.isArray(files) || files.length === 0) {
    inputError(
      'vitest report has no testResults — a partial or empty run must never render as proven'
    );
  }

  const assertions = files.flatMap((file) => file.assertionResults ?? []);
  if (assertions.length === 0) {
    inputError('vitest report contains no assertions');
  }

  const first = assertions[0];
  if (typeof first.fullName !== 'string' || typeof first.status !== 'string') {
    inputError(
      'vitest report assertions lack `fullName`/`status` — the reporter shape changed; ' +
        'refusing to join against a format this script does not understand'
    );
  }
  return assertions;
}

/* -------------------------------------------------------------------------- */
/*                                  The join                                   */
/* -------------------------------------------------------------------------- */

/**
 * Every `(specId, section)` a test title cites.
 *
 * Matched against `fullName`, so a `describe`-level citation propagates to every
 * leaf beneath it — which is what lifts the joinable base far above the naive
 * `it`-level count.
 *
 * MEASURED ON HEAD 2026-08-31, because #400's own figures were not reliable:
 * 550 of 4288 leaf assertions (12.8%) across 77 files carry any spec reference,
 * and only 82 (1.9%, 20 files) use the `RFC NNNN §X.Y` grammar the issue calls
 * dominant. The extractor therefore accepts a section that follows the alias
 * with or without the `§`, and tolerates intervening punctuation, rather than
 * assuming one shape.
 */
function extractCitations(assertions, specs) {
  const citations = [];

  for (const assertion of assertions) {
    const name = assertion.fullName ?? '';
    for (const spec of specs) {
      for (const alias of spec.aliases) {
        const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        // The alias, then an OPTIONAL run of sections. Real titles in this
        // corpus write all of:
        //   `RFC 9207 §3`            — one section
        //   `RFC 8414 §2`            — one section
        //   `OIDC Core §3.1.3.6, §3.1.3.7` — a LIST after one alias
        //   `emits RFC 8414 required fields`  — the alias with no section
        // The list form is why the run is captured whole and split afterwards:
        // an earlier draft took only the first section and silently dropped
        // every one after the comma, which the gate then reported as an
        // unproven row for a requirement that WAS proven.
        const pattern = new RegExp(
          `${escaped}\\s*((?:(?:§\\s*)?\\d+(?:\\.\\d+)*(?:\\s*(?:,|and)\\s*)?)*)`,
          'gi'
        );
        let match;
        while ((match = pattern.exec(name))) {
          const sections = (match[1] ?? '')
            .split(/\s*(?:,|and)\s*/)
            .map((part) => part.replace(/§/g, '').trim())
            .filter((part) => /^\d+(?:\.\d+)*$/.test(part));

          if (sections.length === 0) {
            citations.push({
              specId: spec.id,
              section: null,
              fullName: name,
              status: assertion.status,
            });
            continue;
          }
          for (const section of sections) {
            citations.push({ specId: spec.id, section, fullName: name, status: assertion.status });
          }
        }
      }
    }
  }
  return citations;
}

/**
 * Hierarchical section match: a test citing §2.4 proves a row declared at §2.4
 * OR at §2.
 *
 * Cited depth in this corpus runs from §2 to §3.1.2.1, so nothing flatter works.
 * A citation with NO section proves nothing — it names a spec, not a
 * requirement, and treating it as proof of every row would make the gate
 * meaningless.
 */
function proves(citedSection, rowSection) {
  if (!citedSection) return false;
  if (citedSection === rowSection) return true;
  return citedSection.startsWith(`${rowSection}.`);
}

function joinRows(rows, citations) {
  return rows.map((row) => {
    const matching = citations.filter(
      (citation) => citation.specId === row.specId && proves(citation.section, row.section)
    );
    const passing = matching.filter((citation) => citation.status === 'passed');
    return {
      ...row,
      citingTests: matching.length,
      passingTests: passing.length,
      proofs: [...new Set(passing.map((citation) => citation.fullName))],
    };
  });
}

/* -------------------------------------------------------------------------- */
/*                                  The gate                                   */
/* -------------------------------------------------------------------------- */

function gate(joined, citations, specs) {
  const failures = [];
  const rowsBySpec = new Map();
  for (const row of joined) {
    if (!rowsBySpec.has(row.specId)) rowsBySpec.set(row.specId, []);
    rowsBySpec.get(row.specId).push(row);
  }

  for (const row of joined) {
    const where = `${row.sourceFile} §${row.section}`;

    if (!VALID_STATUSES.includes(row.status)) {
      failures.push({
        file: row.sourceFile,
        message: `${where}: status "${row.status}" is not one of ${VALID_STATUSES.join(', ')}`,
      });
      continue;
    }

    if (row.status === 'covered') {
      if (row.passingTests === 0) {
        // A row whose only citing tests are SKIPPED counts as unproven, and
        // says so distinctly — "no test" and "a test nobody runs" are different
        // problems with different fixes.
        const reason =
          row.citingTests > 0
            ? `has ${row.citingTests} citing test(s) but none PASSING (skipped tests are not evidence)`
            : 'is marked covered but no passing test cites it';
        failures.push({ file: row.sourceFile, message: `${where}: ${reason}` });
      }
      continue;
    }

    if (row.status === 'manual') {
      if (!row.evidenceRef) {
        failures.push({
          file: row.sourceFile,
          message: `${where}: status "manual" requires an evidenceRef`,
        });
      } else {
        const [path] = row.evidenceRef.split('#');
        if (!existsSync(join(REPO_ROOT, path))) {
          failures.push({
            file: row.sourceFile,
            message: `${where}: evidenceRef "${row.evidenceRef}" does not resolve`,
          });
        }
      }
      continue;
    }

    if (row.status === 'waived') {
      for (const field of ['reason', 'decision', 'revisit']) {
        if (!row[field]) {
          failures.push({
            file: row.sourceFile,
            message: `${where}: status "waived" requires "${field}"`,
          });
        }
      }
      if (row.revisit && row.revisit !== 'never' && !/^\d{4}-\d{2}-\d{2}$/.test(row.revisit)) {
        failures.push({
          file: row.sourceFile,
          message: `${where}: "revisit" must be an ISO date or "never" (got "${row.revisit}")`,
        });
      }
      if (
        row.decision &&
        !row.decision.startsWith('#') &&
        !existsSync(join(REPO_ROOT, row.decision.split('#')[0]))
      ) {
        failures.push({
          file: row.sourceFile,
          message: `${where}: "decision" is neither an issue ref nor a resolvable path`,
        });
      }
      continue;
    }

    if (row.status === 'n/a' && !row.reason) {
      failures.push({
        file: row.sourceFile,
        message: `${where}: status "n/a" requires a "reason"`,
      });
    }
  }

  // Orphan citations: a SEALED spec must have a row for every section its tests
  // cite. This is the ratchet — it is what stops a spec's coverage silently
  // regressing once someone has done the work of enumerating it.
  for (const spec of specs.filter((candidate) => candidate.sealed)) {
    const sections = new Set((rowsBySpec.get(spec.id) ?? []).map((row) => row.section));
    const orphans = new Set(
      citations
        .filter((citation) => citation.specId === spec.id && citation.section)
        .filter((citation) => ![...sections].some((section) => proves(citation.section, section)))
        .map((citation) => citation.section)
    );
    for (const section of orphans) {
      failures.push({
        file: `docs/conformance/requirements/${spec.id}.json`,
        message: `tests cite ${spec.id} §${section}, which has no requirement row — ${spec.id} is SEALED`,
      });
    }
  }

  return failures;
}

/* -------------------------------------------------------------------------- */
/*                                  Render                                     */
/* -------------------------------------------------------------------------- */

function renderMarkdown(joined, specs, stats) {
  const byId = new Map(specs.map((spec) => [spec.id, spec]));
  const lines = [
    '# Spec conformance matrix',
    '',
    '_Generated by `scripts/spec-matrix.mjs`. Do not edit — edit the JSON under `docs/conformance/requirements/` instead._',
    '',
    `Joined ${stats.rows} requirement rows against ${stats.assertions} test assertions ` +
      `(${stats.citations} citations across ${specs.length} registered specs).`,
    '',
  ];

  const satisfied = joined.filter((row) => row.status === 'covered' || row.status === 'manual');
  const knowinglyNot = joined.filter((row) => row.status === 'waived');
  const outOfProfile = joined.filter((row) => row.status === 'n/a');

  lines.push('## Satisfied', '');
  lines.push('| Spec | § | Level | Status | Proven by | Requirement |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  for (const row of satisfied) {
    const proof =
      row.status === 'manual' ? `\`${row.evidenceRef}\`` : `${row.passingTests} test(s)`;
    lines.push(
      `| ${byId.get(row.specId)?.title ?? row.specId} | ${row.section} | ${row.level} | ${row.status} | ${proof} | ${row.quote.slice(0, 120)}… |`
    );
  }

  // `waived` gets its own prominent section. Collapsing it into `n/a` destroys
  // the document for a certification reviewer: `n/a` means the requirement never
  // applied; `waived` means it applied and we chose not to satisfy it.
  lines.push('', '## Knowingly NOT satisfied (waived)', '');
  if (knowinglyNot.length === 0) {
    lines.push('_None._', '');
  } else {
    lines.push('| Spec | § | Level | Reason | Decision | Revisit |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    for (const row of knowinglyNot) {
      lines.push(
        `| ${byId.get(row.specId)?.title ?? row.specId} | ${row.section} | ${row.level} | ${row.reason} | ${row.decision} | ${row.revisit} |`
      );
    }
  }

  lines.push('', "## Outside QAuth's profile (n/a)", '');
  lines.push('| Spec | § | Requirement | Why it does not apply |');
  lines.push('| --- | --- | --- | --- |');
  for (const row of outOfProfile) {
    lines.push(
      `| ${byId.get(row.specId)?.title ?? row.specId} | ${row.section} | ${row.quote.slice(0, 80)}… | ${row.reason} |`
    );
  }

  lines.push('', '## Specs not yet enumerated', '');
  for (const spec of specs) {
    const count = joined.filter((row) => row.specId === spec.id).length;
    if (count === 0)
      lines.push(`- **${spec.title}** — registered, no rows yet (sealed: ${spec.sealed}).`);
  }

  return `${lines.join('\n')}\n`;
}

/* -------------------------------------------------------------------------- */

function main() {
  const args = parseArgs(process.argv.slice(2));
  const specs = loadRegistry();
  const rows = loadRequirements(specs);
  const assertions = loadAssertions(args.report);
  const citations = extractCitations(assertions, specs);
  const joined = joinRows(rows, citations);
  const failures = gate(joined, citations, specs);

  const stats = { rows: rows.length, assertions: assertions.length, citations: citations.length };

  mkdirSync(args.out, { recursive: true });
  writeFileSync(join(args.out, 'matrix.md'), renderMarkdown(joined, specs, stats));
  writeFileSync(
    join(args.out, 'matrix.json'),
    `${JSON.stringify({ stats, rows: joined, failures }, null, 2)}\n`
  );

  process.stdout.write(
    `spec-matrix: ${stats.rows} rows, ${stats.assertions} assertions, ${stats.citations} citations → ${args.out}\n`
  );

  // Job summary, so every PR shows the delta without downloading an artifact.
  if (process.env.GITHUB_STEP_SUMMARY) {
    const counts = VALID_STATUSES.map(
      (status) => `${status}: ${joined.filter((row) => row.status === status).length}`
    ).join(', ');
    writeFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      `### Spec conformance matrix\n\n${counts}\n\nFailures: ${failures.length}\n`,
      { flag: 'a' }
    );
  }

  if (failures.length > 0) {
    for (const failure of failures) {
      process.stdout.write(`::error file=${failure.file}::${failure.message}\n`);
    }
    process.stderr.write(`\nspec-matrix: ${failures.length} gate failure(s).\n`);
    process.exit(1);
  }
}

main();
