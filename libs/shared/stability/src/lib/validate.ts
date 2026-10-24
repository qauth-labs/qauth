import { evidenceKind } from './evidence';
import {
  ADR_PATH_PATTERN,
  CONFIG_KEY_PATTERN,
  type ExperimentalItem,
  IMPORT_PATH_PATTERN,
  ITEM_ID_PATTERN,
  PROMOTION_CONDITIONS,
  type PromotionConditionId,
  REQUIRED_SETTING_PATTERN,
  SPEC_STATUSES,
} from './item';

/**
 * The conditions of `item` that have no evidence yet, in ADR-018 §5's order.
 * An item may become stable only when this is empty.
 */
export function missingEvidence(item: ExperimentalItem): PromotionConditionId[] {
  return PROMOTION_CONDITIONS.filter(
    (condition) => (item.conditions?.[condition.id]?.evidence ?? []).length === 0
  ).map((condition) => condition.id);
}

const isBlank = (value: unknown) => typeof value !== 'string' || value.trim() === '';

/**
 * Check the registry's entries against its rules. Returns one line per
 * problem, `[]` when there is none.
 *
 * Pure: whether a `path` evidence or the ADR file exists is the caller's
 * check, since only the caller has the file system.
 */
export function validateExperimentalRegistry(items: readonly ExperimentalItem[]): string[] {
  const problems: string[] = [];
  const seen = new Set<string>();

  for (const item of items) {
    const at = isBlank(item.id) ? '(no id)' : item.id;

    if (!ITEM_ID_PATTERN.test(item.id ?? '')) {
      problems.push(`${at}: the id must be lower-case words joined by "-", with "." in a version`);
    }
    if (seen.has(item.id)) problems.push(`${at}: registered twice`);
    seen.add(item.id);

    if (isBlank(item.title)) problems.push(`${at}: the title is missing`);
    if (isBlank(item.description)) problems.push(`${at}: the description is missing`);

    if (isBlank(item.adr)) {
      problems.push(`${at}: the ADR link is missing`);
    } else if (!ADR_PATH_PATTERN.test(item.adr)) {
      problems.push(`${at}: the ADR link must be a docs/adr/NNN-<name>.md path`);
    }

    problems.push(...switchProblems(item, at));

    if (isBlank(item.spec?.name)) problems.push(`${at}: the spec has no name`);
    if (!/^https:\/\/\S+$/.test(item.spec?.url ?? '')) {
      problems.push(`${at}: the spec URL must be an https link`);
    }
    if (!SPEC_STATUSES.includes(item.spec?.status)) {
      problems.push(`${at}: the spec status must be one of ${SPEC_STATUSES.join(', ')}`);
    }

    problems.push(...conditionProblems(item, at));

    if (item.stable && !item.built) {
      problems.push(`${at}: an item that is not built cannot be stable`);
    }
    if (item.stable) {
      for (const condition of missingEvidence(item)) {
        problems.push(`${at}: stable, but condition ${condition} has no evidence`);
      }
    }
  }

  return problems;
}

function switchProblems(item: ExperimentalItem, at: string): string[] {
  const problems: string[] = [];
  if (item.switchKey === null || item.switchKey === undefined || isBlank(item.switchKey)) {
    if (item.built) problems.push(`${at}: a built item needs a switch key`);
    if (item.switchValue !== null && item.switchValue !== undefined) {
      problems.push(`${at}: a switch value needs a switch key`);
    }
  } else if (item.surface === 'server') {
    if (!CONFIG_KEY_PATTERN.test(item.switchKey)) {
      problems.push(`${at}: a server switch must be a configuration key, such as FEATURE_ENABLED`);
    }
    if (isBlank(item.switchValue)) {
      problems.push(`${at}: a server switch needs the value that turns the item on`);
    }
  } else if (item.surface === 'sdk') {
    if (!IMPORT_PATH_PATTERN.test(item.switchKey)) {
      problems.push(`${at}: an SDK switch must be an @qauth-labs/... import path`);
    }
    if (item.switchValue !== null) {
      problems.push(`${at}: an SDK switch is an import path and has no value`);
    }
  } else {
    problems.push(`${at}: the surface must be server or sdk`);
  }

  for (const setting of item.requires ?? []) {
    if (!REQUIRED_SETTING_PATTERN.test(setting)) {
      problems.push(`${at}: a required setting must read KEY=value, not "${setting}"`);
    }
  }
  if ((item.requires ?? []).length > 0 && item.surface !== 'server') {
    problems.push(`${at}: only a server item can require other settings`);
  }
  return problems;
}

function conditionProblems(item: ExperimentalItem, at: string): string[] {
  const problems: string[] = [];
  const known = new Set<string>(PROMOTION_CONDITIONS.map((condition) => condition.id));

  for (const id of Object.keys(item.conditions ?? {})) {
    if (!known.has(id)) problems.push(`${at}: there is no promotion condition ${id}`);
  }
  for (const condition of PROMOTION_CONDITIONS) {
    const entry = item.conditions?.[condition.id];
    if (entry === undefined) {
      problems.push(`${at}: condition ${condition.id} is missing; write it with no evidence`);
      continue;
    }
    for (const evidence of entry.evidence) {
      if (evidenceKind(evidence) === null) {
        problems.push(
          `${at}: condition ${condition.id}: "${evidence}" is not an RFC number, an issue, an https link or a repository path`
        );
      }
    }
    if (entry.note !== undefined && isBlank(entry.note)) {
      problems.push(`${at}: condition ${condition.id} has an empty note`);
    }
  }

  // The first condition is a fact about the spec, so the two must agree.
  const specFinal = (item.conditions?.['spec-final']?.evidence ?? []).length > 0;
  if (item.spec?.status === 'draft' && specFinal) {
    problems.push(`${at}: condition spec-final has evidence, but the spec is a draft`);
  }
  if ((item.spec?.status === 'rfc' || item.spec?.status === 'final') && !specFinal) {
    problems.push(`${at}: the spec is ${item.spec.status}, so condition spec-final needs evidence`);
  }
  return problems;
}
