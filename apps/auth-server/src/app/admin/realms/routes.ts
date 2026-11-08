import {
  type PolicyDiff,
  PolicySchemaVersionError,
  PolicySecretStoreUnavailableError,
  PolicyVersionConflictError,
  REALM_POLICY_REGISTRY,
  type RealmPolicyChange,
  RealmPolicyNotFoundError,
} from '@qauth-labs/fastify-plugin-realm-policy';
import {
  NotFoundError,
  PreconditionFailedError,
  TemporarilyUnavailableError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import {
  ifMatchHeadersSchema,
  MERGE_PATCH_MEDIA_TYPE,
  requireMergePatch,
} from '../../api-conventions/conditional-requests';
import { rfc3339 } from '../../api-conventions/time';
import {
  type AdminOperation,
  type Classification,
  mergeClassifications,
  type OperationClassification,
  operationSchemaExtensions,
} from '../../helpers/admin-operations';
import { UnprocessableContentError } from '../../helpers/api-request-errors';
import {
  REALM_POLICIES_REFUSED_MESSAGE,
  unprocessablePolicyField,
  updateRealmPolicies,
} from '../../helpers/realm-policy-update';
import { sandboxPairingOf } from '../../helpers/sandbox-realm';
import { requestClassification } from '../../plugins/admin-operations';
import {
  ADMIN_SECURITY_SCHEME,
  type AdminChange,
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
} from '../pipeline';
import { openRequestSealedValue } from '../secrets/sealed-values';
import { SEALED_VALUE_SCHEMA } from '../secrets/secret-members';
import { readPolicyState, REALM_OPERATION_IDS, REALM_POLICY_SECRET_MEMBERS } from './operations';

/**
 * THE REALM ROUTES OF THE ADMIN API (ADR-019 Decisions 7 and 10, issue #517):
 *
 *   GET   /admin/v1-rc.0/realms/{realmId}           — realms.get, with its ETag
 *   PATCH /admin/v1-rc.0/realms/{realmId}/policies  — realms.policies.update,
 *                                                    a JSON Merge Patch, If-Match required
 *
 * Both answer the realm representation. Its `ETag` is the version of the
 * realm's policies (`policies_version`), which the patch names in `If-Match`;
 * the pipeline answers 428 without one and 412 with another
 * (`plugins/admin-operations.ts`), and the store's write is conditional on it,
 * under the realm row's lock, so a write in between is 412 too.
 *
 * A patch names fields of the policy groups; a member the policies do not
 * have is a malformed request (400 `validation_error`, decided 2026-10-22),
 * and a merged document the policy schema or a rule refuses is 422
 * `unprocessable_content`, naming each field. A secret field takes only a
 * value sealed with `secrets.seal` for this operation and its member (#984),
 * or `null` to clear it; the handler opens it in the operation's
 * transaction, the policy store hands it to the realm's secret store, and no
 * response, log or audit record ever holds it.
 */

/** The path of a realm, as the admin listener routes it. */
const REALM_PATH = '/admin/v1-rc.0/realms/:realmId';

const realmParams = z.object({ realmId: z.uuid() });

const isoTime = z.iso.datetime();

/**
 * The realm representation (#517). `policies` is the `representation` view of
 * the policy registry: every group and field, each secret `<name>` only as
 * `<name>Set`. The view's schema strips what it does not name, so a value
 * that is not in it never reaches a response serialized with it.
 */
export const realmSchema = z
  .object({
    id: z.uuid(),
    name: z.string(),
    enabled: z.boolean(),
    operator: z.boolean().meta({
      description:
        'Whether this is the operator realm, whose admins may hold grants on other realms.',
    }),
    createdAt: isoTime,
    updatedAt: isoTime,
    sandboxOf: z.uuid().nullable().meta({
      description:
        'The live realm this realm is the sandbox of (ADR-019 Decision 11), or null. Read-only.',
    }),
    sandbox: z.uuid().nullable().meta({
      description: "This realm's sandbox, or null. Read-only.",
    }),
    policySchemaVersion: z.string().meta({
      description: 'The version of the realm policy schema `policies` follows (ADR-018 §5).',
    }),
    policies: REALM_POLICY_REGISTRY.schema('representation').meta({
      description:
        'The realm policies, every field set; a secret field shows only whether it is set, as <name>Set.',
    }),
  })
  .meta({ id: 'AdminRealm' });

type RealmResource = z.infer<typeof realmSchema>;

/** A tree of the registry's fields, by segment, for the patch body schema. */
type FieldTree = Map<string, FieldTree | (typeof REALM_POLICY_FIELDS)[number]>;

const REALM_POLICY_FIELDS = REALM_POLICY_REGISTRY.fields();

/**
 * The body of a policy patch: the groups and fields of the registry, each
 * optional, and no other member (400 for one). A field takes any JSON value,
 * `null` included (it then takes its default): its type and bounds are
 * checked on the merged document, which answers 422 naming the field. A
 * group is an object, never `null`: a whole group is changed field by field.
 * A secret field takes a sealed value or `null`; the `<name>Set` flag of the
 * representation is taken back and changes nothing.
 */
export function policyPatchBodySchema(): z.ZodType {
  const root: FieldTree = new Map();
  for (const entry of REALM_POLICY_FIELDS) {
    let node = root;
    for (const segment of entry.segments.slice(0, -1)) {
      let next = node.get(segment);
      if (!(next instanceof Map)) {
        next = new Map();
        node.set(segment, next);
      }
      node = next;
    }
    node.set(entry.segments[entry.segments.length - 1], entry);
  }
  const groupOf = (tree: FieldTree): z.ZodType => {
    const shape: Record<string, z.ZodType> = {};
    for (const [name, member] of tree) {
      if (member instanceof Map) {
        shape[name] = groupOf(member).optional();
      } else if (member.field.secret) {
        shape[name] = SEALED_VALUE_SCHEMA.nullable()
          .optional()
          .meta({
            description: `${member.field.doc.summary} A value sealed with secrets.seal for realms.policies.update and this member sets it, null clears it, leaving it out keeps it.`,
          });
        shape[`${name}Set`] = z
          .boolean()
          .optional()
          .meta({
            description: `Whether ${member.path} is set, as the representation shows it; it sets and clears nothing.`,
          });
      } else {
        shape[name] = z
          .unknown()
          .optional()
          .meta({
            description: `${member.field.doc.summary} null gives it its default; the merged value is checked against the policy schema (422).`,
          });
      }
    }
    return z.strictObject(shape);
  };
  return groupOf(root).meta({ id: 'AdminRealmPolicyPatch' });
}

/** The realm's representation and its `ETag`, read in `tx`. */
export async function realmResource(
  request: FastifyRequest,
  realmId: string
): Promise<{ readonly etag: string; readonly body: RealmResource }> {
  const tx = adminTransaction(request);
  const row = await request.server.repositories.realms.findById(realmId, tx);
  if (row === undefined) throw new NotFoundError('Realm', realmId);
  const state = await readPolicyState(request, realmId, tx);
  const pairing = await sandboxPairingOf(request.server.repositories.realms, row, tx);
  return {
    etag: `"${state.version}"`,
    body: {
      id: row.id,
      name: row.name,
      enabled: row.enabled,
      operator: row.isOperator,
      createdAt: rfc3339(row.createdAt),
      updatedAt: rfc3339(row.updatedAt),
      sandboxOf: pairing.sandboxOf,
      sandbox: pairing.sandbox,
      policySchemaVersion: state.schemaVersion,
      policies: state.policies as RealmResource['policies'],
    },
  };
}

/** The value at `segments` of `root`, or `undefined`. */
function valueAt(root: unknown, segments: readonly string[]): unknown {
  let node: unknown = root;
  for (const segment of segments) {
    if (typeof node !== 'object' || node === null || !Object.hasOwn(node, segment)) {
      return undefined;
    }
    node = (node as Record<string, unknown>)[segment];
  }
  return node;
}

/** Set `value` at `segments` of `root`, making the groups on the way. */
function setAt(root: Record<string, unknown>, segments: readonly string[], value: unknown): void {
  let node = root;
  for (const segment of segments.slice(0, -1)) {
    const next = Object.hasOwn(node, segment) ? node[segment] : undefined;
    if (typeof next === 'object' && next !== null && !Array.isArray(next)) {
      node = next as Record<string, unknown>;
    } else {
      const created: Record<string, unknown> = {};
      node[segment] = created;
      node = created;
    }
  }
  node[segments[segments.length - 1]] = value;
}

/**
 * The patch the policy store applies: the request's body, each sealed secret
 * opened for this operation, its member and the realm (#984), and the
 * representation's `<name>Set` flags left for the store to drop.
 */
async function openedPatch(request: FastifyRequest): Promise<Record<string, unknown>> {
  const patch = structuredClone(request.body) as Record<string, unknown>;
  const secrets = REALM_POLICY_FIELDS.filter((entry) => entry.field.secret);
  for (const [index, entry] of secrets.entries()) {
    const value = valueAt(patch, entry.segments);
    if (value === undefined || value === null) continue;
    // The member the value was sealed for: its JSON Pointer in the body.
    const member = REALM_POLICY_SECRET_MEMBERS[index];
    const { sealed } = value as { sealed: string };
    setAt(patch, entry.segments, await openRequestSealedValue(request, member, sealed, entry.path));
  }
  return patch;
}

/** What `diff` needs, field by field, as `realms.policies.update` classifies a change. */
function classificationOfDiff(diff: PolicyDiff): Classification {
  return mergeClassifications([
    { class: 'write', effects: [], permissions: ['realms.policies.write'] },
    ...diff.changes
      .filter((change) => change.class === 'security')
      .map((change): Classification => ({
        class: 'security',
        effects: [...change.effects],
        permissions: ['realms.policies.security'],
      })),
  ]);
}

/**
 * The guard of the store's write: the change about to be stored needs no
 * more than the request was classified and authorized for. The write is
 * conditional on the version the classification read, so it never does;
 * should it, the state the request was judged against is gone: 412.
 */
function requireWithin(diff: PolicyDiff, classification: OperationClassification): void {
  const needed = classificationOfDiff(diff);
  const security = needed.class === 'security';
  const exceeds =
    (security && classification.class !== 'security') ||
    needed.effects.some((effect) => !classification.effects.includes(effect)) ||
    (security && !classification.permissions.includes('realms.policies.security'));
  if (exceeds) {
    throw new PreconditionFailedError({ operation: REALM_OPERATION_IDS.updatePolicies });
  }
}

/**
 * The audit record of a policy change: the changed fields before and after,
 * under `policies`, and the counter. A secret field appears as whether it is
 * set, annotated `secret`, so the audit log stores its marker only.
 */
export function auditedChange(change: RealmPolicyChange): AdminChange {
  const before: Record<string, unknown> = {};
  const after: Record<string, unknown> = {};
  const annotations: Record<string, 'secret'> = {};
  for (const entry of change.diff.changes) {
    const segments = entry.path.split('.');
    setAt(before, segments, entry.before);
    setAt(after, segments, entry.after);
    if (entry.secret) annotations[`policies.${entry.path}`] = 'secret';
  }
  return {
    change: {
      before: { policiesVersion: change.version, policies: before },
      after: { policiesVersion: change.version + 1, policies: after },
    },
    annotations,
  } as AdminChange;
}

/** A refusal of the policy store as the admin API answers it. Names no other realm. */
function storeRefusal(error: unknown, realmId: string): unknown {
  if (error instanceof PolicyVersionConflictError) {
    return new PreconditionFailedError({ operation: REALM_OPERATION_IDS.updatePolicies });
  }
  if (error instanceof RealmPolicyNotFoundError) return new NotFoundError('Realm', realmId);
  if (error instanceof PolicySecretStoreUnavailableError) {
    return new UnprocessableContentError(
      error.paths.map((path) =>
        unprocessablePolicyField({
          path,
          message: 'is a secret, and this server has no secret store to keep it in',
        })
      ),
      REALM_POLICIES_REFUSED_MESSAGE
    );
  }
  // Written by a later release during a rolling upgrade: a node of that
  // release writes them. The reason goes to the log only.
  if (error instanceof PolicySchemaVersionError && error.reason === 'newer') {
    return new TemporarilyUnavailableError(30, { operation: REALM_OPERATION_IDS.updatePolicies });
  }
  return error;
}

/**
 * The realm operations in the pipeline's registry, or `undefined` when it
 * holds none: a test registry built from fixture operations alone serves no
 * realm route, and the server's own registry (`OPERATION_REGISTRY`) holds both.
 *
 * @throws {Error} when it holds one and not the other
 */
function realmOperations(
  fastify: FastifyInstance
): { get: AdminOperation; updatePolicies: AdminOperation } | undefined {
  const get = fastify.adminApi.registry.get(REALM_OPERATION_IDS.get);
  const updatePolicies = fastify.adminApi.registry.get(REALM_OPERATION_IDS.updatePolicies);
  if (get === undefined && updatePolicies === undefined) return undefined;
  if (get === undefined || updatePolicies === undefined) {
    throw new Error(
      `The admin operation registry holds only some realm operations; it lacks ${get === undefined ? REALM_OPERATION_IDS.get : REALM_OPERATION_IDS.updatePolicies}`
    );
  }
  return { get, updatePolicies };
}

/** Register the realm routes behind the admin pipeline. */
export const realmRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const operations = realmOperations(fastify);
  if (operations === undefined) return;
  const common = {
    'x-qauth-stability': 'experimental' as const,
    // A DPoP-bound admin token (#520).
    security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
  };

  typed.get(
    REALM_PATH,
    {
      config: { operation: operations.get.id },
      schema: {
        ...operationSchemaExtensions(operations.get),
        ...common,
        summary: 'Read a realm and its policies',
        description:
          "The ETag is the version of the realm's policies: a policy patch names it in If-Match.",
        'x-qauth-errors': [400, 401, 403, 404],
        params: realmParams,
        response: { 200: realmSchema },
      },
    },
    async (request, reply) => {
      const { etag, body } = await realmResource(
        request,
        requestAdminCaller(request).targetRealm.id
      );
      reply.header('etag', etag);
      return body;
    }
  );

  typed.patch(
    `${REALM_PATH}/policies`,
    {
      config: { operation: operations.updatePolicies.id },
      // After the pipeline's stages: a route of the admin listener has no
      // early hook of its own.
      preHandler: requireMergePatch,
      schema: {
        ...operationSchemaExtensions(operations.updatePolicies),
        ...common,
        summary: "Change a realm's policies",
        description:
          'A JSON Merge Patch (RFC 7396) of the policies, judged on the merged document: a change a field’s annotation makes a security change needs realms.policies.security and an approval, any other realms.policies.write. If-Match names the ETag of the realm (428 without it, 412 when the policies moved). A secret field takes a value secrets.seal sealed for this operation and its member, or null to clear it.',
        'x-qauth-errors': [400, 401, 403, 404, 412, 415, 422, 428, 503],
        consumes: [MERGE_PATCH_MEDIA_TYPE],
        params: realmParams,
        headers: ifMatchHeadersSchema,
        body: policyPatchBodySchema(),
        response: { 200: realmSchema },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const classification = requestClassification(request);
      const patch = await openedPatch(request);
      let stored: RealmPolicyChange | undefined;
      try {
        await updateRealmPolicies(request.server, realmId, patch, {
          // The version the classification was made against: the write is
          // conditional on it, under the realm row's lock.
          expectedVersion: Number(classification.stateVersion),
          tx: adminTransaction(request),
          guard: (change) => {
            requireWithin(change.diff, classification);
            stored = change;
          },
        });
      } catch (error) {
        throw storeRefusal(error, realmId);
      }
      if (stored === undefined) throw new Error('The policy store wrote without its guard');
      recordAdminChange(request, auditedChange(stored));
      const { etag, body } = await realmResource(request, realmId);
      reply.header('etag', etag);
      return body;
    }
  );
};
