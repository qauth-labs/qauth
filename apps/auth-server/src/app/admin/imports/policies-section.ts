import {
  diffPolicies,
  mailTransportIssues,
  REALM_POLICY_REGISTRY,
} from '@qauth-labs/fastify-plugin-realm-policy';

import {
  defineSection,
  type ImportChangeDraft,
  type ImportSectionContext,
  type ImportSectionDiff,
  type ImportState,
} from './section';

/**
 * THE `policies` SECTION OF AN IMPORT (ADR-019 Decisions 10 and 11, issue
 * #518): the realm policies, matched field by field by their path.
 *
 * - The changes are the policy diff (`diffPolicies`, CFG-02) from the stored
 *   document to the file's, which the parser filled with every default: a
 *   field the file leaves out takes its default, as the format says (#515).
 *   Each change moves and needs what its annotation says, as a change of
 *   `realms.policies.update` does: `realms.policies.security` for a security
 *   change, `realms.policies.write` for any other.
 * - A file holds no secret value, so no change sets or clears a secret.
 *   `secretsToSet` names the secret fields the file's choices need and the
 *   realm lacks: those the realm policy rules say must be set for the
 *   document the file gives (the smtp transport's password once `smtp` is
 *   selected, or given again once its server changes). A change needs a
 *   secret (`needsSecret`) when the secret would not be needed without it;
 *   a secret no single change accounts for is put on every change of its
 *   group.
 * - An export (#530) writes the stored document, every field set, a secret
 *   field replaced by nothing: no value, no `<name>Set` flag, no marker.
 *   The file says nothing of a secret; an import of it names the secrets
 *   the target realm lacks (`secretsToSet`).
 */

/** A rule over a whole policy document, as the policy store runs it. */
type PolicyRule = typeof mailTransportIssues;

/** The rules that say which secrets a document needs. */
export const SECRET_NEED_RULES: readonly PolicyRule[] = Object.freeze([mailTransportIssues]);

/** The secret fields of the policies, by path, in registration order. */
const SECRET_PATHS: readonly string[] = REALM_POLICY_REGISTRY.fields()
  .filter((entry) => entry.field.secret)
  .map((entry) => entry.path);

const SECRET_PATH_SET: ReadonlySet<string> = new Set(SECRET_PATHS);

/**
 * The secret fields `document` needs and `state` lacks, by path: every
 * secret a rule names, judged twice, once against the stored policies (a
 * secret the change asks to be given again) and once as though nothing were
 * stored (a secret the realm lacked already, which the file's choice still
 * needs).
 */
export function secretsNeeded(
  document: Readonly<Record<string, unknown>>,
  state: Pick<ImportState, 'policies' | 'setSecrets'>,
  rules: readonly PolicyRule[] = SECRET_NEED_RULES
): string[] {
  const set = new Set(state.setSecrets);
  const isSet = (path: string): boolean => set.has(path);
  const written = (): undefined => undefined;
  const contexts = [
    { previous: state.policies, isSet, wasSet: isSet, written },
    { previous: {}, isSet, wasSet: isSet, written },
  ];
  const needed = new Set<string>();
  for (const rule of rules) {
    for (const context of contexts) {
      // A secret the rule names is one to set: one the realm lacks, or one
      // that must be given again although it is set.
      for (const issue of rule(document, context)) {
        if (SECRET_PATH_SET.has(issue.path)) needed.add(issue.path);
      }
    }
  }
  return SECRET_PATHS.filter((path) => needed.has(path));
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** `document` with the field at `path` given `value`: a copy. */
function withField(
  document: Readonly<Record<string, unknown>>,
  path: string,
  value: unknown
): Record<string, unknown> {
  const copy = structuredClone(document) as Record<string, unknown>;
  const segments = path.split('.');
  let node: Record<string, unknown> = copy;
  for (const segment of segments.slice(0, -1)) {
    const next = node[segment];
    if (!isRecord(next)) return copy;
    node = next;
  }
  node[segments[segments.length - 1]] = structuredClone(value);
  return copy;
}

/** The group a field or a secret is in: the first segment of its path. */
const groupOf = (path: string): string => path.split('.')[0];

function diffPolicySection({ state, file }: ImportSectionContext): ImportSectionDiff {
  const after = file.policies as Readonly<Record<string, unknown>> | undefined;
  if (after === undefined) return { changes: [] };
  const diff = diffPolicies(state.policies, after, { setSecrets: state.setSecrets });
  const secretsToSet = secretsNeeded(after, state);
  const needs = new Set<number>();
  const accounted = new Set<string>();
  diff.changes.forEach((change, index) => {
    if (change.secret || secretsToSet.length === 0) return;
    const without = secretsNeeded(withField(after, change.path, change.before), state);
    const caused = secretsToSet.filter((path) => !without.includes(path));
    if (caused.length === 0) return;
    needs.add(index);
    for (const path of caused) accounted.add(path);
  });
  for (const path of secretsToSet) {
    if (accounted.has(path)) continue;
    diff.changes.forEach((change, index) => {
      if (groupOf(change.path) === groupOf(path)) needs.add(index);
    });
  }
  const changes = diff.changes.map((change, index): ImportChangeDraft => ({
    key: null,
    path: change.path,
    op: 'update',
    before: change.before,
    after: change.after,
    direction: change.direction,
    class: change.class,
    effects: change.class === 'security' ? [...change.effects] : [],
    secret: change.secret,
    environmentBound: change.environmentBound,
    needsSecret: needs.has(index),
  }));
  return { changes, secretsToSet };
}

/** The secret fields of the policies, by their segments. */
const SECRET_SEGMENTS: readonly (readonly string[])[] = REALM_POLICY_REGISTRY.fields()
  .filter((entry) => entry.field.secret)
  .map((entry) => entry.segments);

/**
 * The `policies` of a file that describes `state`: the stored document with
 * every secret field left out, whatever it holds, through the format's
 * `document` view, which fills a field the document lacks with its default.
 */
export function exportedPolicies(state: Pick<ImportState, 'policies'>): Record<string, unknown> {
  const document = structuredClone(state.policies) as Record<string, unknown>;
  for (const segments of SECRET_SEGMENTS) {
    let node: unknown = document;
    for (const segment of segments.slice(0, -1)) {
      node = isRecord(node) ? node[segment] : undefined;
    }
    if (isRecord(node)) delete node[segments[segments.length - 1]];
  }
  return REALM_POLICY_REGISTRY.parse(document, 'document');
}

/** The `policies` section. */
export const POLICIES_SECTION = defineSection({
  name: 'policies',
  schema: () => REALM_POLICY_REGISTRY.schema('document'),
  naturalKey: undefined,
  diff: diffPolicySection,
  export: exportedPolicies,
  // As `realms.policies.update` classifies one changed field
  // (`classificationOfPolicyChange`).
  permissionsFor: (change) =>
    change.class === 'security' ? ['realms.policies.security'] : ['realms.policies.write'],
});
