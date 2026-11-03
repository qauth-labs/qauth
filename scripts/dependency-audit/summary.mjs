#!/usr/bin/env node
/**
 * dependency-audit summary — print the job summary of a `pnpm audit --json`
 * report (#795). The parsing and the rendering live in `lib.mjs` and are
 * unit-tested there; this file reads the report file and prints.
 *
 * It prints Markdown on stdout, whatever the advisories' severities: the
 * dependency audit workflow appends it to the job summary. Failing the job on
 * a high or critical advisory is the gate step's work
 * (`pnpm audit --audit-level high`), not this script's.
 *
 * Exit codes:
 *   0  the summary is printed
 *   2  the arguments are wrong, or the file cannot be read or is not an audit
 *      report (a registry error, say); a short note saying so is printed on
 *      stdout too, so the job summary does not stay silent
 *
 * Usage:
 *   node scripts/dependency-audit/summary.mjs <report.json>
 */

import { readFileSync } from 'node:fs';

import { parseReport, renderSummary, ReportError } from './lib.mjs';

const EXIT_OK = 0;
const EXIT_INPUT = 2;

const USAGE = 'usage: node scripts/dependency-audit/summary.mjs <report.json>';

function unreadable(path, reason) {
  console.error(`dependency-audit: ${path} ${reason}`);
  process.stdout.write(
    [
      '## Dependency audit',
      '',
      `The report of \`pnpm audit --json\` could not be read: it ${reason}. The audit step's own log says why.`,
      '',
    ].join('\n')
  );
  return EXIT_INPUT;
}

function main(args) {
  if (args.length !== 1 || args[0].startsWith('-')) {
    console.error(`dependency-audit: ${USAGE}`);
    return EXIT_INPUT;
  }
  const path = args[0];

  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    return unreadable(path, `cannot be read (${error.code ?? error.message})`);
  }

  let advisories;
  try {
    advisories = parseReport(text);
  } catch (error) {
    if (error instanceof ReportError) return unreadable(path, error.message);
    throw error;
  }

  process.stdout.write(renderSummary(advisories));
  return EXIT_OK;
}

process.exitCode = main(process.argv.slice(2));
