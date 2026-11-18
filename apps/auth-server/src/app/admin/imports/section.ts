import type { RealmFile, RealmFileClient } from '@qauth-labs/realm-file';
import { realmFileSection } from '@qauth-labs/realm-file';
import type { SecurityEffect } from '@qauth-labs/shared-validation';
import type { z } from 'zod';

import type { ChangeDirection } from '../change-preview';

/**
 * THE SECTIONS AN IMPORT PLANS (ADR-019 Decision 11, issue #518): what a
 * section of the realm file adds to the import plan, besides its schema and
 * natural key, which the format fixes (`@qauth-labs/realm-file`, #515): how
 * its value in a file differs from the realm's state, change by change, and
 * the admin permissions each change needs.
 *
 * A section is added with {@link defineSection} and listed in
 * `IMPORT_SECTIONS` (`./plan.ts`). A file that holds a section the import
 * does not plan yet is refused, naming the section: an import never skips
 * part of a file.
 */

/** What an import's change does to its item. */
export const IMPORT_CHANGE_OPS = Object.freeze(['create', 'update', 'delete'] as const);

export type ImportChangeOp = (typeof IMPORT_CHANGE_OPS)[number];

/**
 * The realm as an import reads it: what each section compares a file with.
 * It holds no secret value: which secret policy fields are set, never what
 * they hold, and no client's secret.
 */
export interface ImportState {
  /** The target realm, the one the import names. */
  readonly realmId: string;
  /** Its name, which a file's `realm` only advises. */
  readonly realmName: string;
  /** The policies' counter (`policies_version`), the base the plan is made against. */
  readonly policiesVersion: number;
  /** The stored policy document: every field, no secret. */
  readonly policies: Readonly<Record<string, unknown>>;
  /** The secret policy fields that hold a value, by path, such as `mail.smtp.password`. */
  readonly setSecrets: readonly string[];
  /** The clients a realm file describes (the operator manages them), each as a file lists it. */
  readonly clients: readonly RealmFileClient[];
  /**
   * The `client_id`s of the realm's other clients, which no realm file's
   * `clients` names, each with why: a client a developer owns, one that
   * registered itself, a CIMD client, the system client, a service account's.
   */
  readonly unmanagedClients: ReadonlyMap<string, string>;
}

/** What a section is asked to compare. */
export interface ImportSectionContext {
  readonly state: ImportState;
  readonly file: RealmFile;
  /** Whether an item the realm has and the file leaves out is deleted. */
  readonly prune: boolean;
}

/** One change a section finds, before its permissions are named. */
export interface ImportChangeDraft {
  /** The item's natural key, `null` in a section without one (`policies`). */
  readonly key: string | null;
  /**
   * The dotted path of the field within the item, such as
   * `password.minScore` or `redirect_uris`; empty for a whole item created
   * or deleted.
   */
  readonly path: string;
  readonly op: ImportChangeOp;
  /** The value the realm holds, `null` for an item it does not have; never a secret's value. */
  readonly before: unknown;
  /** The value the import would store, `null` for an item it deletes; never a secret's value. */
  readonly after: unknown;
  readonly direction: ChangeDirection;
  /** `security` when the single operation the change equals is a security operation. */
  readonly class: 'write' | 'security';
  /** The effects that make it a security change; empty for a write. */
  readonly effects: readonly SecurityEffect[];
  /** Whether the field is a secret, shown only as set or not set. */
  readonly secret: boolean;
  /** Whether the value describes the environment the realm runs in (ADR-019 Decision 11). */
  readonly environmentBound: boolean;
  /** Whether the change leaves the realm needing a secret it does not hold. */
  readonly needsSecret: boolean;
}

/** What a section finds. */
export interface ImportSectionDiff {
  /** Its changes, in the section's order. */
  readonly changes: readonly ImportChangeDraft[];
  /** The secrets its value needs and the realm lacks, by path. */
  readonly secretsToSet?: readonly string[];
}

/** One reason a file cannot be planned against the realm: where in the file, and why. */
export interface ImportPlanIssue {
  /** A JSON Pointer into the file (RFC 6901). */
  readonly pointer: string;
  readonly message: string;
}

/** A file the import cannot plan, with every reason. No message quotes a value. */
export class ImportPlanError extends Error {
  override readonly name = 'ImportPlanError';

  constructor(readonly issues: readonly ImportPlanIssue[]) {
    super(
      `The realm file cannot be imported: ${issues.map((issue) => `${issue.pointer}: ${issue.message}`).join('; ')}`
    );
  }
}

/** A section as {@link defineSection} takes it. */
export interface ImportSectionDefinition {
  /** Its top-level key: a section of the realm file's format. */
  readonly name: string;
  /** The schema of its value, or of one entry of a list: the format's. */
  readonly schema: () => z.ZodType;
  /** The member it matches items by, the format's; `undefined` for `policies`. */
  readonly naturalKey: string | undefined;
  /** How its value in the file differs from the realm's state. */
  readonly diff: (context: ImportSectionContext) => ImportSectionDiff;
  /** The admin permissions one of its changes needs, from the catalog. */
  readonly permissionsFor: (change: ImportChangeDraft) => readonly string[];
}

/** A section of the import plan. */
export type ImportSection = Readonly<ImportSectionDefinition>;

/**
 * Define a section of the import plan.
 *
 * @throws {Error} when the realm file's format has no section of that name,
 *   or matches it by another natural key
 */
export function defineSection(definition: ImportSectionDefinition): ImportSection {
  const format = realmFileSection(definition.name);
  if (format === undefined) {
    throw new Error(`${definition.name} is not a section of the realm file`);
  }
  if (format.naturalKey !== definition.naturalKey) {
    throw new Error(
      `The realm file matches ${definition.name} by ${String(format.naturalKey)}, not ${String(definition.naturalKey)}`
    );
  }
  return Object.freeze({ ...definition });
}
