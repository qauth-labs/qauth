import { PolicySchemaVersionError } from '@qauth-labs/fastify-plugin-realm-policy';
import {
  REALM_FILE_FORMAT,
  REALM_FILE_SCHEMA_ID,
  safeParseRealmFile,
} from '@qauth-labs/realm-file';
import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { type AdminOperation, operationSchemaExtensions } from '../../helpers/admin-operations';
import {
  UnprocessableContentError,
  type UnprocessableField,
} from '../../helpers/api-request-errors';
import { ADMIN_SECURITY_SCHEME, requestAdminCaller } from '../pipeline';
import { IMPORT_OPERATION_IDS } from './operations';
import { importPlanSchema, planImport } from './plan';
import { ImportPlanError, type ImportPlanIssue } from './section';
import { MAX_IMPORT_CLIENTS, readImportState, TooManyClientsError } from './state';

/**
 * THE IMPORT ROUTE OF THE ADMIN API (ADR-018 §5, ADR-019 Decisions 7 and 11,
 * ADR-020 fork G, issue #518):
 *
 *   POST /admin/v1-rc.0/realms/{realmId}/imports — realms.imports.plan, the dry run
 *
 * The body carries a realm file (`urn:qauth:realm-file:v1-rc.0`), whether
 * the import prunes, and `mode`, which is only `dry-run` here: applying an
 * import is #531's. The answer is the import plan (`AdminImportPlan`,
 * `./plan.ts`). A file the format refuses, one with a section the import does
 * not plan yet, and one that names a client no realm file manages are
 * answered 422, each issue a JSON Pointer into the body, `/file/...`; no
 * message quotes a value. It reads the realm in the handler's transaction,
 * writes nothing but the audit row every admin call leaves, and shows no
 * secret.
 */

/** The path of the imports of a realm, as the admin listener routes it. */
const IMPORTS_PATH = '/admin/v1-rc.0/realms/:realmId/imports';

const realmParams = z.object({ realmId: z.uuid() });

/** What a refused file is answered with. */
export const REALM_FILE_REFUSED_MESSAGE = 'The realm file cannot be imported into this realm.';

/** The body of an import request. */
const importRequestSchema = z
  .strictObject({
    mode: z.literal('dry-run').meta({
      description:
        'dry-run: answer the plan and apply nothing. The only mode this release takes; applying an import comes later (#531).',
    }),
    prune: z.boolean().optional().meta({
      description:
        'Whether an item the realm has and the file leaves out is deleted. Left out: false, and nothing is deleted.',
    }),
    file: z.record(z.string(), z.unknown()).meta({
      description: `The realm file, as JSON: format ${REALM_FILE_FORMAT}, whose JSON Schema is ${REALM_FILE_SCHEMA_ID}. A file the format refuses is answered 422, naming each member at fault.`,
    }),
  })
  .meta({ id: 'AdminRealmImportRequest' });

type ImportRequest = z.infer<typeof importRequestSchema>;

/** An issue of the file as a field of the body. */
const fieldOf = (issue: ImportPlanIssue): UnprocessableField => ({
  pointer: `/file${issue.pointer}`,
  message: issue.message,
});

/**
 * The import operations in the pipeline's registry, or `undefined` when it
 * holds none: a test registry built from fixture operations alone serves no
 * import route.
 */
function importOperations(fastify: FastifyInstance): { plan: AdminOperation } | undefined {
  const plan = fastify.adminApi.registry.get(IMPORT_OPERATION_IDS.plan);
  return plan === undefined ? undefined : { plan };
}

/** Register the import route behind the admin pipeline. */
export const importRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const operations = importOperations(fastify);
  if (operations === undefined) return;

  typed.post(
    IMPORTS_PATH,
    {
      config: { operation: operations.plan.id },
      schema: {
        ...operationSchemaExtensions(operations.plan),
        'x-qauth-stability': 'experimental',
        // A DPoP-bound admin token (#520).
        security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
        summary: 'Plan the import of a realm file',
        description: `A dry run: answers every change importing the file would make to the realm's policies and to the clients the operator manages, without applying it. Each change names its section, its item (a client's client_id) and its field, the value before and after, whether it tightens, loosens or neither (an unknown direction counts as loosening), and the class, effects, permissions and scopes of the single operation it equals: a policy change as realms.policies.update judges it, a client's field as clients.update does, and creating or deleting a client is a security change, as clients.create and clients.delete are. The plan's class is the strictest of its changes, and its digest, over the realm, the base policies version, the prune flag and the changes, is what the approval of the import binds to. A client the file leaves out stays unless prune is true. secretsToSet names the secrets the file's choices need and the realm lacks, such as mail.smtp.password once the file selects smtp: they are set on the realm, never by an import. A file the format refuses (422, each member at fault under /file), one holding a section this release does not import (cimd_clients, resources, system_client), one naming a client no realm file manages (a developer's, a self-registered or CIMD client, the system client, a service account's), and one that would create a client under the system client's client_id or a CIMD client_id are refused. It needs realms.import.plan, and realms.read and clients.read, since the plan shows the realm's policies and clients as they stand; it applies nothing and shows no secret. A realm with more than ${MAX_IMPORT_CLIENTS} clients is refused (422).`,
        'x-qauth-errors': [400, 401, 403, 404, 415, 422, 503],
        params: realmParams,
        body: importRequestSchema,
        response: { 200: importPlanSchema },
      },
    },
    async (request, reply) => {
      const caller = requestAdminCaller(request);
      const realm = caller.targetRealm;
      const body = request.body as ImportRequest;
      const parsed = safeParseRealmFile(body.file);
      if (!parsed.success) {
        throw new UnprocessableContentError(parsed.issues.map(fieldOf), REALM_FILE_REFUSED_MESSAGE);
      }
      // Imported here, not with the module: they read the environment, and
      // the unit tests import the routes without one.
      const [{ systemClientId }, { isCimdClientId }] = await Promise.all([
        import('../../helpers/oauth-client'),
        import('../../helpers/cimd'),
      ]);
      let state;
      try {
        state = await readImportState(request, realm, {
          systemClientId: systemClientId(),
          isCimdClientId,
        });
      } catch (error) {
        if (error instanceof PolicySchemaVersionError && error.reason === 'newer') {
          // A later release's policies, during a rolling upgrade: a node of
          // that release plans the import.
          throw new TemporarilyUnavailableError(30, { operation: IMPORT_OPERATION_IDS.plan });
        }
        if (error instanceof TooManyClientsError) {
          // The realm's fault, not the file's: the pointer names the whole request.
          throw new UnprocessableContentError(
            [{ pointer: '', message: error.message }],
            'This realm holds more clients than an import plans.'
          );
        }
        throw error;
      }
      try {
        const plan = planImport(state, parsed.file, {
          prune: body.prune ?? false,
          permissions: request.server.adminApi.registry.permissions,
        });
        reply.header('cache-control', 'no-store');
        return plan;
      } catch (error) {
        if (error instanceof ImportPlanError) {
          throw new UnprocessableContentError(
            error.issues.map(fieldOf),
            REALM_FILE_REFUSED_MESSAGE
          );
        }
        throw error;
      }
    }
  );
};
