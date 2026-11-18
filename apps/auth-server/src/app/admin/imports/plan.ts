import { createHash } from 'node:crypto';

import { canonicalizeJson } from '@qauth-labs/fastify-plugin-db';
import {
  hasUrlCredentials,
  REALM_FILE_SECTIONS,
  type RealmFile,
  realmNameWarning,
} from '@qauth-labs/realm-file';
import { SECURITY_EFFECTS, type SecurityEffect } from '@qauth-labs/shared-validation';
import { z } from 'zod';

import { PERMISSION_REGISTRY, type PermissionRegistry } from '../../helpers/admin-permissions';
import { ADMIN_SCOPES } from '../../helpers/admin-scopes';
import { CHANGE_DIRECTIONS, scopesOf } from '../change-preview';
import { CLIENTS_SECTION } from './clients-section';
import { POLICIES_SECTION } from './policies-section';
import {
  IMPORT_CHANGE_OPS,
  type ImportChangeDraft,
  ImportPlanError,
  type ImportSection,
  type ImportState,
} from './section';

/**
 * THE IMPORT PLAN OF A REALM FILE (ADR-018 §5, ADR-019 Decisions 7 and 11,
 * ADR-020 fork G, issue #518): before anything is applied, every change an
 * import would make, which way it moves, the single operation it equals and
 * what that needs, and a digest the approval of the import binds to.
 *
 * {@link planImport} is pure: the realm's state and a parsed file in, the
 * plan out. The dry run (`POST /admin/v1-rc.0/realms/{realmId}/imports`,
 * `./routes.ts`) answers it; the apply (#531) recomputes it and refuses when
 * the digest differs.
 *
 * - **Sections.** Each section of {@link IMPORT_SECTIONS} compares its value
 *   in the file with the realm's state; a section the file leaves out says
 *   nothing and changes nothing. A file holding a section no entry plans
 *   yet is refused, naming it: the import never skips part of a file.
 * - **Deletes.** An item the realm has and the file leaves out stays, unless
 *   the import prunes (`prune: true`).
 * - **What it needs.** The plan's class is the strictest of its changes
 *   (`security` when one is), its effects, permissions and scopes those of
 *   every change: the strictest change gates the import (ADR-019 Decision
 *   11), and the diff marks each change so a reviewer sees what loosens. A
 *   plan with no change is a `write` that needs no permission.
 * - **No secret.** A file holds none; a secret field shows only as set or
 *   not set; a URL the realm stores with a user name or password shows them
 *   as `***`. `secretsToSet` names the secrets the file's choices need and
 *   the realm lacks, which are set on the realm itself, never by an import.
 * - **The digest.** The SHA-256 digest, base64url, of the RFC 8785
 *   canonical JSON of the realm id, the base `policies_version`, the prune
 *   flag and the changes. A change holds no display text, so the digest
 *   covers every member of every change and differs when anything the plan
 *   would do differs, the base version included; the warnings and the
 *   rendered text (`./render.ts`) are not in it. It is taken over the changes
 *   as shown, a stored URL's user name and password masked, so it never
 *   depends on a secret.
 */

/** The sections an import plans, in the realm file's order (`REALM_FILE_SECTIONS`). */
export const IMPORT_SECTIONS: readonly ImportSection[] = Object.freeze([
  POLICIES_SECTION,
  CLIENTS_SECTION,
]);

/** The section `name` an import plans, if it plans one. */
export function importSection(name: string): ImportSection | undefined {
  return IMPORT_SECTIONS.find((section) => section.name === name);
}

const classSchema = z.enum(['write', 'security']);
const effectsSchema = z.array(z.enum(SECURITY_EFFECTS));
const scopesSchema = z.array(
  z.enum([ADMIN_SCOPES.read, ADMIN_SCOPES.write, ADMIN_SCOPES.security])
);

/** One change of an import plan. */
export const importChangeSchema = z
  .object({
    section: z
      .string()
      .meta({ description: 'The section of the realm file: policies or clients.' }),
    key: z.string().nullable().meta({
      description:
        "The item's natural key, such as a client's client_id; null for the policies, whose fields are matched by their path.",
    }),
    path: z.string().meta({
      description:
        'The dotted path of the field within the item, such as password.minScore or redirect_uris; empty when the change creates or deletes the whole item.',
    }),
    op: z.enum(IMPORT_CHANGE_OPS).meta({
      description:
        'create for an item the realm lacks, update for a field of one it has, delete for an item it has and the file leaves out, which only a pruning import deletes.',
    }),
    before: z.unknown().meta({
      description:
        'The value the realm holds, as stored; null for an item it lacks. A secret field shows set or not set, never a value.',
    }),
    after: z.unknown().meta({
      description:
        'The value the import would store; null for an item it deletes. A secret field shows set or not set, never a value.',
    }),
    direction: z.enum(CHANGE_DIRECTIONS).meta({
      description:
        'Whether the change tightens, loosens or neither; a change whose direction is unknown counts as loosening.',
    }),
    class: classSchema.meta({
      description:
        'security when the single operation the change equals is a security operation (ADR-019 Decision 11).',
    }),
    effects: effectsSchema.meta({
      description: 'The effects that make the change a security change; empty for a write.',
    }),
    permissions: z.array(z.string()).meta({
      description: 'The admin permissions the change needs.',
    }),
    scopes: scopesSchema.meta({ description: 'The admin scopes the change needs.' }),
    secret: z.boolean().meta({
      description: 'Whether the field is a secret, shown only as set or not set.',
    }),
    environmentBound: z.boolean().meta({
      description:
        'Whether the value describes the environment the realm runs in, which a sandbox promotion leaves out unless it is selected (ADR-019 Decision 11).',
    }),
    needsSecret: z.boolean().meta({
      description:
        'Whether the change leaves the realm needing a secret it does not hold: one secretsToSet names, or the client secret of a client that authenticates with one.',
    }),
  })
  .meta({ id: 'AdminImportChange' });

/** The plan of an import. */
export const importPlanSchema = z
  .object({
    realmId: z.uuid().meta({ description: 'The realm the import targets.' }),
    baseVersion: z.int().min(0).meta({
      description:
        "The realm's policies_version the plan was made against: the realm's ETag, without its quotes.",
    }),
    prune: z.boolean().meta({
      description: 'Whether items the realm has and the file leaves out are deleted.',
    }),
    digest: z.string().meta({
      description:
        'The SHA-256 digest, base64url, of the RFC 8785 form of the realm id, the base version, the prune flag and the changes as the plan shows them, a URL credential masked: the approval of the import binds to it, and the apply refuses a plan whose digest differs.',
    }),
    class: classSchema.meta({
      description:
        'The strictest class of the changes: security when any change is; write when none is, or when there is no change.',
    }),
    effects: effectsSchema.meta({ description: 'Every effect of the security changes.' }),
    permissions: z.array(z.string()).meta({
      description: 'Every admin permission the changes need; empty when there is no change.',
    }),
    scopes: scopesSchema.meta({ description: 'Every admin scope the changes need.' }),
    approvalRequired: z.boolean().meta({
      description: 'Whether applying the plan needs an approval: exactly when it is security.',
    }),
    secretsToSet: z.array(z.string()).meta({
      description:
        "The secret fields the file's choices need and the realm lacks, by path, such as mail.smtp.password: set on the realm itself, never by an import.",
    }),
    warnings: z.array(z.string()).meta({
      description:
        'What the import does not stop on but says, such as a file written for a realm of another name.',
    }),
    changes: z.array(importChangeSchema).meta({
      description:
        'Every change, section by section in the order of the realm file, each section in its own order; empty when the file matches the realm.',
    }),
  })
  .meta({ id: 'AdminImportPlan' });

export type ImportChange = z.infer<typeof importChangeSchema>;
export type ImportPlan = z.infer<typeof importPlanSchema>;

/** What {@link planImport} takes beside the state and the file. */
export interface PlanImportOptions {
  /** Delete an item the realm has and the file leaves out. `false` by default. */
  readonly prune?: boolean;
  /** The permission catalog the scopes are read from; the server's by default. */
  readonly permissions?: Pick<PermissionRegistry, 'get'>;
}

/** What a user name and password in a URL show as. */
const MASK = '***';

/** The usual form of a URL with user information: its scheme and `://`, then up to the `@`. */
const USER_INFO = /^([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^/?#\s]*@/u;

/**
 * `value` with every string that is a URL with a user name or password
 * masked, at any depth: a value the realm stored before the realm file's
 * rule existed (#515) is shown without its secret.
 */
export function maskUrlCredentials(value: unknown): unknown {
  if (typeof value === 'string') {
    if (!hasUrlCredentials(value)) return value;
    // The usual form keeps the rest of the URL, and a URL masked already
    // stays as it is; any other (`https:/user@host`, which only a URL parser
    // reads so) is shown as the mask alone.
    const masked = value.replace(USER_INFO, `$1${MASK}@`);
    return hasUrlCredentials(masked.replace(`${MASK}@`, '')) ? MASK : masked;
  }
  if (Array.isArray(value)) return value.map(maskUrlCredentials);
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([member, entry]) => [member, maskUrlCredentials(entry)])
    );
  }
  return value;
}

/** Strings in UTF-16 code unit order. */
const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The digest of a plan: SHA-256, base64url, of the RFC 8785 canonical JSON
 * of what it would do.
 */
export function planDigest(input: {
  readonly realmId: string;
  readonly baseVersion: number;
  readonly prune: boolean;
  readonly changes: readonly ImportChange[];
}): string {
  const canonical = canonicalizeJson({
    realmId: input.realmId,
    baseVersion: input.baseVersion,
    prune: input.prune,
    changes: input.changes,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

/** A section of the realm file the import does not plan yet, as the issue that refuses it says. */
function unplannedSections(file: RealmFile): string[] {
  return REALM_FILE_SECTIONS.map((section) => section.name).filter(
    (name) =>
      (file as unknown as Record<string, unknown>)[name] !== undefined &&
      importSection(name) === undefined
  );
}

/** One change with what it needs, its values masked. */
function changeOf(
  section: ImportSection,
  draft: ImportChangeDraft,
  permissions: Pick<PermissionRegistry, 'get'>
): ImportChange {
  const needed = [...new Set(section.permissionsFor(draft))].sort(byCodeUnit);
  return {
    section: section.name,
    key: draft.key,
    path: draft.path,
    op: draft.op,
    before: maskUrlCredentials(draft.before),
    after: maskUrlCredentials(draft.after),
    direction: draft.direction,
    class: draft.class,
    effects: SECURITY_EFFECTS.filter((effect) => draft.effects.includes(effect)),
    permissions: needed,
    scopes: scopesOf(needed, permissions),
    secret: draft.secret,
    environmentBound: draft.environmentBound,
    needsSecret: draft.needsSecret,
  };
}

/**
 * The plan of importing `file` into the realm `state` describes.
 *
 * @throws ImportPlanError when the file holds a section the import does not
 *   plan yet, or names a client of the realm no realm file manages
 */
export function planImport(
  state: ImportState,
  file: RealmFile,
  options: PlanImportOptions = {}
): ImportPlan {
  const prune = options.prune ?? false;
  const permissions = options.permissions ?? PERMISSION_REGISTRY;
  const unplanned = unplannedSections(file);
  if (unplanned.length > 0) {
    throw new ImportPlanError(
      unplanned.map((name) => ({
        pointer: `/${name}`,
        message: `this server does not import the ${name} section yet: leave it out of the file, and change it through its own operations`,
      }))
    );
  }

  const changes: ImportChange[] = [];
  const secrets = new Set<string>();
  for (const section of IMPORT_SECTIONS) {
    const diff = section.diff({ state, file, prune });
    for (const draft of diff.changes) changes.push(changeOf(section, draft, permissions));
    for (const path of diff.secretsToSet ?? []) secrets.add(path);
  }

  const security = changes.some((change) => change.class === 'security');
  const effects = new Set<SecurityEffect>(changes.flatMap((change) => change.effects));
  const needed = [...new Set(changes.flatMap((change) => change.permissions))].sort(byCodeUnit);
  const warning = realmNameWarning(file, state.realmName);
  return {
    realmId: state.realmId,
    baseVersion: state.policiesVersion,
    prune,
    digest: planDigest({
      realmId: state.realmId,
      baseVersion: state.policiesVersion,
      prune,
      changes,
    }),
    class: security ? 'security' : 'write',
    effects: SECURITY_EFFECTS.filter((effect) => effects.has(effect)),
    permissions: needed,
    scopes: scopesOf(needed, permissions),
    approvalRequired: security,
    secretsToSet: [...secrets],
    warnings: warning === undefined ? [] : [warning],
    changes,
  };
}
