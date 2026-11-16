import {
  type CimdClientSpec,
  cimdClientSpecSchema,
  type ResourceSpec,
  resourceSpecSchema,
} from '@qauth-labs/infra-db/seed-manifest';
import { type SystemClientSpec, systemClientSpecSchema } from '@qauth-labs/infra-db/system-client';
import { REALM_POLICY_REGISTRY, type RealmPolicies } from '@qauth-labs/server-realm-policy';
import { z } from 'zod';

import { REALM_FILE_FORMAT } from './format';
import { type RealmFileIssue, realmFileIssues } from './issues';
import { REALM_FILE_SECTIONS, realmFileClientSchema } from './sections';

/**
 * THE DECLARATIVE REALM FILE (ADR-018 §5, ADR-019 Decision 11, ADR-020 fork
 * G, issue #515): a realm's configuration as one JSON document, which the
 * admin API and the CLI export and import, and which holds no secret value.
 *
 * Its top-level keys are `format` (optional, {@link REALM_FILE_FORMAT} by
 * default), `realm`, the realm's name, and the sections of
 * {@link REALM_FILE_SECTIONS}. Every object is strict: an unknown member is
 * refused, and named, so a typo fails, a secret fails, and a section of a
 * later release fails instead of being skipped.
 *
 * Never in a file: the realm's host, its endpoint hosts and issuer, its keys
 * and passkey RP ID, users and sessions, secret values, ids the server
 * generates and timestamps, the sandbox pairing, and clients a developer owns
 * or that registered themselves. Items are matched by natural keys: the realm
 * by its name, which only advises (the caller chooses the target realm), a
 * client by its `client_id`, a protected resource by its `resource`.
 */

/** A `clients` entry, as parsed. */
export type RealmFileClient = z.output<typeof realmFileClientSchema>;

/** A parsed realm file: defaults filled, in the shape of {@link realmFileSchema}. */
export interface RealmFile {
  readonly format: typeof REALM_FILE_FORMAT;
  readonly realm: string;
  readonly policies?: RealmPolicies;
  readonly clients?: readonly RealmFileClient[];
  readonly cimd_clients?: readonly CimdClientSpec[];
  readonly resources?: readonly ResourceSpec[];
  readonly system_client?: SystemClientSpec;
}

/** The members before the sections. */
export const REALM_FILE_HEADER_KEYS = Object.freeze(['format', 'realm'] as const);

const formatSchema = z
  .literal(REALM_FILE_FORMAT, {
    error: (issue) =>
      `this server reads realm files of format ${REALM_FILE_FORMAT}, not ${JSON.stringify(issue.input)}: a file of another format needs a release that reads it`,
  })
  .default(REALM_FILE_FORMAT)
  .describe(
    `The file's format. Optional: a file without it is read as ${REALM_FILE_FORMAT}. A breaking change raises its release-candidate number before QAuth 1.0.0, and its major version after.`
  );

const realmSchema = z
  .string()
  .min(1)
  .describe(
    "The name of the realm the file describes. It only advises: the caller of an import chooses the target realm, and a different name is a warning, so a sandbox realm's file can go to its live realm."
  );

/** Where each `client_id` first appears, so the second appearance names the first. */
function uniqueNaturalKeys(file: Record<string, unknown>, ctx: z.core.$RefinementCtx): void {
  const firstSeen = new Map<string, Map<string, string>>();
  for (const section of REALM_FILE_SECTIONS) {
    const key = section.naturalKey;
    const value = file[section.name];
    if (key === undefined || value === undefined) continue;
    const entries: Array<[unknown, Array<string | number>]> =
      section.kind === 'list' && Array.isArray(value)
        ? value.map((entry, index) => [entry, [section.name, index]])
        : [[value, [section.name]]];
    let seen = firstSeen.get(key);
    if (seen === undefined) firstSeen.set(key, (seen = new Map()));
    for (const [entry, path] of entries) {
      const name = (entry as Record<string, unknown>)[key];
      if (typeof name !== 'string') continue;
      const where = path.join('.');
      const first = seen.get(name);
      if (first === undefined) {
        seen.set(name, where);
        continue;
      }
      ctx.addIssue({
        code: 'custom',
        path: [...path, key],
        message: `${key} "${name}" is listed at ${first} already: a ${key} names one item of the realm, so it appears once in a file`,
      });
    }
  }
}

function buildSchema(policies: z.ZodType<RealmPolicies>) {
  return z
    .strictObject({
      format: formatSchema,
      realm: realmSchema,
      policies: policies.optional(),
      clients: z.array(realmFileClientSchema).optional(),
      cimd_clients: z.array(cimdClientSpecSchema).optional(),
      resources: z.array(resourceSpecSchema).optional(),
      system_client: systemClientSpecSchema.optional(),
    })
    .superRefine(uniqueNaturalKeys);
}

let built: { policies: z.ZodType; schema: ReturnType<typeof buildSchema> } | undefined;

/**
 * The Zod schema of the realm file, over the realm policies registered now.
 * An area that registers a policy group adds it to the file, as the policy
 * registry rebuilds its `document` view on every registration.
 */
export function realmFileSchema(): ReturnType<typeof buildSchema> {
  const policies = REALM_POLICY_REGISTRY.schema('document');
  if (built?.policies !== policies) {
    built = { policies, schema: buildSchema(policies as z.ZodType<RealmPolicies>) };
  }
  return built.schema;
}

/** Options of {@link parseRealmFile}. */
export interface ParseRealmFileOptions {
  /**
   * The environment the seed reads `SYSTEM_CLIENT_ID` from: a `system_client`
   * section that names no `client_id` takes it, as a seed manifest's does
   * (`parseManifest`), before the default `system`.
   */
  readonly env?: Readonly<Record<string, string | undefined>>;
}

/** The outcome of {@link safeParseRealmFile}. */
export type RealmFileParseResult =
  | { readonly success: true; readonly file: RealmFile }
  | { readonly success: false; readonly issues: readonly RealmFileIssue[] };

/** A realm file that is not valid, with every issue and its path. */
export class RealmFileError extends Error {
  readonly issues: readonly RealmFileIssue[];

  constructor(issues: readonly RealmFileIssue[]) {
    const [first] = issues;
    const more = issues.length > 1 ? ` (and ${issues.length - 1} more)` : '';
    super(`The realm file is not valid: ${first?.pointer || '/'}: ${first?.message ?? ''}${more}`);
    this.name = 'RealmFileError';
    this.issues = issues;
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** `raw` with a `system_client` that names no `client_id` given the configured one. */
function withSystemClientId(raw: unknown, options: ParseRealmFileOptions): unknown {
  const configured = options.env?.['SYSTEM_CLIENT_ID']?.trim();
  if (
    !configured ||
    !isRecord(raw) ||
    !isRecord(raw['system_client']) ||
    raw['system_client']['client_id'] !== undefined
  ) {
    return raw;
  }
  return { ...raw, system_client: { ...raw['system_client'], client_id: configured } };
}

/** Parse a realm file, already read as JSON, and say every issue it has. */
export function safeParseRealmFile(
  raw: unknown,
  options: ParseRealmFileOptions = {}
): RealmFileParseResult {
  const result = realmFileSchema().safeParse(withSystemClientId(raw, options));
  if (result.success) return { success: true, file: result.data as RealmFile };
  return { success: false, issues: realmFileIssues(result.error) };
}

/**
 * Parse a realm file, already read as JSON: defaults filled, the policies'
 * included.
 *
 * @throws RealmFileError when the file is not valid, with every issue
 */
export function parseRealmFile(raw: unknown, options: ParseRealmFileOptions = {}): RealmFile {
  const result = safeParseRealmFile(raw, options);
  if (!result.success) throw new RealmFileError(result.issues);
  return result.file;
}

/**
 * The warning an import into `targetRealm` gives for `file`, or `undefined`:
 * the file's `realm` only advises, so another name does not stop the import
 * (a sandbox realm's file goes to its live realm), but it is said.
 */
export function realmNameWarning(
  file: Pick<RealmFile, 'realm'>,
  targetRealm: string
): string | undefined {
  if (file.realm === targetRealm) return undefined;
  return `the file describes the realm "${file.realm}" and is imported into "${targetRealm}": the target realm is the one the import names`;
}
