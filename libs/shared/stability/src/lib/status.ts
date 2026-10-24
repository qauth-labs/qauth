import { markdownHeadingAnchors } from './anchor';
import { evidenceKind, evidencePath, evidenceSection } from './evidence';
import { ADR_PATH_PATTERN, type ExperimentalItem, PROMOTION_CONDITIONS } from './item';
import { missingEvidence, registryShapeProblems, validateExperimentalRegistry } from './validate';

/**
 * The promotion status that `scripts/experimental-status.mjs` prints: per
 * item, the four conditions of ADR-018 §5 and their evidence. Pure: the
 * script passes in how to tell that a path exists.
 */

/**
 * Whether a path from the repository root names a file, and, when a section
 * is given, whether the file has that section.
 */
export type PathExists = (path: string, section?: string) => boolean;

/** The file access {@link repositoryPathCheck} needs, passed in so this library does no I/O. */
export interface RepositoryFiles {
  /** Whether a path from the repository root names a regular file; a directory does not. */
  isFile(path: string): boolean;
  /** The text of a file, by its path from the repository root. */
  readText(path: string): string;
}

/**
 * The check evidence paths get: the path names a file, and a `#section` is
 * one of the heading anchors of a Markdown file. A section of any other kind
 * of file cannot be checked, so it is refused.
 */
export function repositoryPathCheck(files: RepositoryFiles): PathExists {
  return (path, section) => {
    if (!files.isFile(path)) return false;
    if (section === undefined) return true;
    return path.endsWith('.md') && markdownHeadingAnchors(files.readText(path)).has(section);
  };
}

/** The `path` evidence of `item` that names no file or no section, as `<condition>: <evidence>`. */
export function missingEvidencePaths(item: ExperimentalItem, pathExists: PathExists): string[] {
  const missing: string[] = [];
  for (const condition of PROMOTION_CONDITIONS) {
    for (const evidence of item.conditions[condition.id]?.evidence ?? []) {
      if (
        evidenceKind(evidence) === 'path' &&
        !pathExists(evidencePath(evidence), evidenceSection(evidence))
      ) {
        missing.push(`${condition.id}: ${evidence}`);
      }
    }
  }
  return missing;
}

/**
 * Built, not yet stable, and every condition has evidence: the maintainer may
 * promote it in the next minor release.
 */
export function mayBecomeStable(item: ExperimentalItem, pathExists: PathExists): boolean {
  return (
    item.built &&
    !item.stable &&
    missingEvidence(item).length === 0 &&
    missingEvidencePaths(item, pathExists).length === 0
  );
}

/**
 * What `--check-stable` fails on: every problem of the registry, among them a
 * stable item with a condition that has no evidence; an ADR link that names
 * no file; and evidence of a stable item that names a path or a section that
 * does not exist. `[]` passes.
 */
export function stableCheckFailures(
  items: readonly ExperimentalItem[],
  pathExists: PathExists
): string[] {
  const shape = registryShapeProblems(items);
  if (shape.length > 0) return shape;
  const failures = validateExperimentalRegistry(items);
  for (const item of items) {
    if (ADR_PATH_PATTERN.test(item.adr ?? '') && !pathExists(item.adr)) {
      failures.push(`${item.id}: the ADR link ${item.adr} names a file that does not exist`);
    }
  }
  for (const item of items.filter((candidate) => candidate.stable)) {
    for (const missing of missingEvidencePaths(item, pathExists)) {
      failures.push(`${item.id}: stable, but the evidence of ${missing} does not exist`);
    }
  }
  return failures;
}

const yesNo = (value: boolean) => (value ? 'yes' : 'no');

/** The switch as a reader sets it: `KEY=value`, an import path, or `none named yet`. */
export function describeSwitch(item: ExperimentalItem): string {
  if (item.switchKey === null) return 'none named yet';
  const setting =
    item.switchValue === null ? item.switchKey : `${item.switchKey}=${item.switchValue}`;
  return item.requires.length === 0 ? setting : `${setting}, with ${item.requires.join(', ')}`;
}

/** The status of every item, as the script prints it. */
export function renderPromotionStatus(
  items: readonly ExperimentalItem[],
  pathExists: PathExists
): string {
  const blocks = items.map((item) => {
    const lines = [
      `${item.id}: ${item.title.replace(/`/g, '')}`,
      `  built: ${yesNo(item.built)} · stable: ${yesNo(item.stable)} · switch: ${describeSwitch(item)}`,
      `  spec: ${item.spec.name} (${item.spec.status}), ${item.spec.url}`,
    ];
    const missingPaths = new Set(missingEvidencePaths(item, pathExists));
    PROMOTION_CONDITIONS.forEach((condition, index) => {
      const entry = item.conditions[condition.id];
      const evidence = entry?.evidence ?? [];
      lines.push(`  [${evidence.length > 0 ? 'x' : ' '}] ${index + 1}. ${condition.text}`);
      for (const piece of evidence) {
        const absent = missingPaths.has(`${condition.id}: ${piece}`) ? ' (does not exist)' : '';
        lines.push(`        ${piece}${absent}`);
      }
      if (entry?.note !== undefined) lines.push(`        ${entry.note}`);
    });
    const lacking = missingEvidence(item).length;
    const reasons = [
      ...(item.built ? [] : ['not built']),
      ...(lacking > 0 ? [`${lacking} of 4 conditions lack evidence`] : []),
      ...(missingPaths.size > 0 ? [`${missingPaths.size} evidence path(s) do not exist`] : []),
    ];
    lines.push(
      item.stable
        ? '  stable'
        : `  may become stable: ${reasons.length === 0 ? 'yes' : `no (${reasons.join('; ')})`}`
    );
    return lines.join('\n');
  });

  const ready = items.filter((item) => mayBecomeStable(item, pathExists)).map((item) => item.id);
  blocks.push(`May become stable: ${ready.length > 0 ? ready.join(', ') : 'none'}.`);
  return `${blocks.join('\n\n')}\n`;
}
