/**
 * Dependency audit summary (#795): the report `pnpm audit --json` prints,
 * turned into the Markdown that CI writes to the job summary. `summary.mjs`
 * is the CLI that reads the report file and prints; this module holds the
 * parsing and the rendering, so the tests drive them on objects.
 *
 * The gate itself is not here. CI runs `pnpm audit --audit-level high`, whose
 * exit code fails the job on a high or critical advisory; this summary lists
 * every advisory the report holds, whatever its severity, and never decides
 * the job. An advisory accepted in `pnpm-workspace.yaml`
 * (`auditConfig.ignoreGhsas`) is not in the report, so it is not listed.
 *
 * Every advisory is listed by the paths it is reached through, never by a
 * development or production label: the paths say which code pulls it in.
 *
 * A report that does not have the shape below is refused rather than rendered
 * in part, so a change in pnpm's output shows up as a failed summary step and
 * not as a summary that quietly lists nothing.
 *
 * Zero runtime dependencies — no imports at all.
 */

/** Every severity pnpm reports, most severe first. */
export const SEVERITIES = Object.freeze(['critical', 'high', 'moderate', 'low', 'info']);

/** The severities CI's gate fails on (`--audit-level high`). */
export const GATED_SEVERITIES = Object.freeze(['critical', 'high']);

/** A report that cannot be read; its message says why. */
export class ReportError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ReportError';
  }
}

const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isString = (value) => typeof value === 'string' && value.length > 0;

/**
 * Read the text `pnpm audit --json` printed.
 *
 * @param {string} text the report, as printed
 * @returns {Advisory[]} its advisories, most severe first
 * @throws {ReportError} when the text is not an audit report
 *
 * @typedef {{
 *   id: string,
 *   severity: string,
 *   packageName: string,
 *   title: string,
 *   url: string,
 *   vulnerableVersions: string,
 *   patchedVersions: string | null,
 *   installedVersions: string[],
 *   paths: string[],
 * }} Advisory
 */
export function parseReport(text) {
  let report;
  try {
    report = JSON.parse(text);
  } catch {
    throw new ReportError('is not JSON');
  }
  if (!isRecord(report)) throw new ReportError('is not a JSON object');
  if ('error' in report) throw new ReportError('is an error, not an audit report');
  if (!isRecord(report.advisories)) throw new ReportError('has no "advisories" object');

  return Object.entries(report.advisories)
    .map(([key, advisory]) => readAdvisory(key, advisory))
    .sort(compareAdvisories);
}

function readAdvisory(key, advisory) {
  const where = `advisory ${key}`;
  if (!isRecord(advisory)) throw new ReportError(`has an ${where} that is not an object`);

  const fields = ['github_advisory_id', 'module_name', 'title', 'url', 'vulnerable_versions'];
  for (const field of fields) {
    if (!isString(advisory[field])) throw new ReportError(`has an ${where} with no "${field}"`);
  }
  if (!SEVERITIES.includes(advisory.severity)) {
    throw new ReportError(`has an ${where} with an unknown severity`);
  }
  const patched = advisory.patched_versions;
  if (patched !== null && patched !== undefined && !isString(patched)) {
    throw new ReportError(`has an ${where} whose "patched_versions" is not a string`);
  }
  if (!Array.isArray(advisory.findings) || advisory.findings.length === 0) {
    throw new ReportError(`has an ${where} with no findings`);
  }

  const versions = new Set();
  const paths = [];
  for (const finding of advisory.findings) {
    if (!isRecord(finding) || !isString(finding.version) || !Array.isArray(finding.paths)) {
      throw new ReportError(`has an ${where} with a finding that is not a version and its paths`);
    }
    if (!finding.paths.every(isString)) {
      throw new ReportError(`has an ${where} with a path that is not a string`);
    }
    versions.add(finding.version);
    paths.push(...finding.paths);
  }

  return {
    id: advisory.github_advisory_id,
    severity: advisory.severity,
    packageName: advisory.module_name,
    title: advisory.title,
    url: advisory.url,
    vulnerableVersions: advisory.vulnerable_versions,
    patchedVersions: isString(patched) ? patched : null,
    installedVersions: [...versions].sort(),
    paths,
  };
}

function compareAdvisories(a, b) {
  const bySeverity = SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity);
  if (bySeverity !== 0) return bySeverity;
  if (a.packageName !== b.packageName) return a.packageName < b.packageName ? -1 : 1;
  if (a.id !== b.id) return a.id < b.id ? -1 : 1;
  return 0;
}

/** Collapse whitespace, so a value from the registry cannot end a table row. */
const oneLine = (value) => value.replace(/\s+/g, ' ').trim();

/** Plain text in a table cell: every character Markdown or HTML reads escaped. */
const text = (value) => oneLine(value).replace(/[\\`*_[\]()<>|~!#&]/g, '\\$&');

/**
 * A code span in a table cell. A backtick would end the span, so it is
 * replaced; a pipe would end the cell even inside the span, so it is escaped.
 * A backslash is escaped first: the table reads `\\|` as an escaped backslash
 * and then a pipe that ends the cell.
 */
const code = (value) =>
  `\`${oneLine(value).replace(/`/g, "'").replace(/\\/g, '\\\\').replace(/\|/g, '\\|')}\``;

const GHSA_ID = /^GHSA(-[a-z0-9]{4}){3}$/;

/** The advisory's id, linked to its page when the report gives an https URL. */
function advisoryLink(advisory) {
  const label = GHSA_ID.test(advisory.id) ? advisory.id : text(advisory.id);
  let url;
  try {
    url = new URL(advisory.url);
  } catch {
    return label;
  }
  if (url.protocol !== 'https:') return label;
  // A parenthesis would close the link; a pipe, which the URL parser leaves as it is, would end the cell.
  const href = url.href.replace(/\(/g, '%28').replace(/\)/g, '%29').replace(/\|/g, '%7C');
  return `[${label}](${href})`;
}

function pathsCell(paths) {
  const shown = paths.length === 0 ? '' : `, e.g. ${code(paths[0])}`;
  return `${paths.length}${shown}`;
}

function countsLine(advisories) {
  const counts = SEVERITIES.map((severity) => [
    severity,
    advisories.filter((advisory) => advisory.severity === severity).length,
  ]).filter(([, count]) => count > 0);
  const total = advisories.length;
  const noun = total === 1 ? 'advisory' : 'advisories';
  return `\`pnpm audit\` reports ${total} ${noun}: ${counts.map(([s, n]) => `${n} ${s}`).join(', ')}.`;
}

/**
 * The job summary for a report's advisories.
 *
 * @param {Advisory[]} advisories as `parseReport` returns them
 * @returns {string} Markdown, ending in a newline
 */
export function renderSummary(advisories) {
  const lines = ['## Dependency audit', ''];

  if (advisories.length === 0) {
    lines.push('`pnpm audit` reports no advisory.');
  } else {
    const gated = advisories.filter((advisory) => GATED_SEVERITIES.includes(advisory.severity));
    lines.push(countsLine(advisories));
    lines.push('');
    lines.push(
      gated.length === 0
        ? 'None is high or critical, so none fails this job: they are listed here until they are fixed.'
        : `${gated.length} high or critical: this job fails until each is fixed, or accepted with a reason in \`pnpm-workspace.yaml\` under \`auditConfig.ignoreGhsas\`. Moderate and low ones are listed and do not fail it.`
    );
    lines.push('');
    lines.push('| Severity | Package | Installed | Fixed in | Advisory | Paths |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    for (const advisory of advisories) {
      const cells = [
        advisory.severity,
        code(advisory.packageName),
        advisory.installedVersions.map(code).join(', '),
        advisory.patchedVersions === null ? 'no release' : code(advisory.patchedVersions),
        `${advisoryLink(advisory)} ${text(advisory.title)}`,
        pathsCell(advisory.paths),
      ];
      lines.push(`| ${cells.join(' | ')} |`);
    }
  }

  lines.push('');
  lines.push(
    'Advisories accepted in `pnpm-workspace.yaml` (`auditConfig.ignoreGhsas`) are left out; each entry there says why and until when.'
  );
  return `${lines.join('\n')}\n`;
}
