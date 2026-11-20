import { PolicySchemaVersionError } from '@qauth-labs/fastify-plugin-realm-policy';
import {
  REALM_FILE_FORMAT,
  REALM_FILE_SCHEMA_ID,
  serializeRealmFile,
} from '@qauth-labs/realm-file';
import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { type AdminOperation, operationSchemaExtensions } from '../../helpers/admin-operations';
import { UnprocessableContentError } from '../../helpers/api-request-errors';
import { MAX_IMPORT_CLIENTS, readImportState, TooManyClientsError } from '../imports/state';
import { ADMIN_SECURITY_SCHEME, requestAdminCaller } from '../pipeline';
import { EXPORT_OPERATION_IDS } from './operations';
import { exportRealmFile, realmFileDisposition, RealmFileExportError } from './realm-file';

/**
 * THE EXPORT ROUTE OF THE ADMIN API (ADR-018 §5, ADR-019 Decision 11,
 * ADR-020 fork G, issue #530):
 *
 *   GET /admin/v1-rc.0/realms/{realmId}/realm-file — realms.export
 *
 * The answer is the realm file itself (`urn:qauth:realm-file:v1-rc.0`), its
 * canonical text as the format writes it, so two exports of the same state
 * are the same bytes: the handler sends the text, not an object the
 * serializer would write again. `Content-Disposition` names it
 * `<realm>.realm.json`, so a browser saves it. It reads the realm in the
 * handler's transaction, as an import does (`../imports/state.ts`), writes
 * nothing but the audit row every admin call leaves, and shows no secret.
 *
 * A realm holding a value no realm file can hold is answered 422, naming
 * each client and member at fault, never a value: no file is written in
 * part. So is a realm with more clients than an import reads.
 */

/** The path of a realm's realm file, as the admin listener routes it. */
const REALM_FILE_PATH = '/admin/v1-rc.0/realms/:realmId/realm-file';

const realmParams = z.object({ realmId: z.uuid() });

/** What a realm that cannot be exported is answered with. */
export const REALM_NOT_EXPORTABLE_MESSAGE =
  'This realm holds a value a realm file cannot hold, so it is not exported.';

/**
 * The answer, as the document describes it: a JSON object, the realm file.
 * The handler sends the file's text; this schema serializes nothing.
 */
const realmFileResponseSchema = z.record(z.string(), z.unknown()).meta({
  id: 'AdminRealmFile',
  description: `The realm file, format ${REALM_FILE_FORMAT}, whose JSON Schema is ${REALM_FILE_SCHEMA_ID}: the realm's policies, a secret field left out, and the clients the operator manages, in canonical order.`,
});

/**
 * The export operation in the pipeline's registry, or `undefined` when it
 * holds none: a test registry built from fixture operations alone serves no
 * export route.
 */
function exportOperation(fastify: FastifyInstance): AdminOperation | undefined {
  return fastify.adminApi.registry.get(EXPORT_OPERATION_IDS.export);
}

/** Register the export route behind the admin pipeline. */
export const exportRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const operation = exportOperation(fastify);
  if (operation === undefined) return;

  typed.get(
    REALM_FILE_PATH,
    {
      config: { operation: operation.id },
      schema: {
        ...operationSchemaExtensions(operation),
        'x-qauth-stability': 'experimental',
        // A DPoP-bound admin token (#520).
        security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
        summary: 'Export a realm as a realm file',
        description: `Answers the realm's configuration as a realm file (${REALM_FILE_FORMAT}): format, realm (the realm's name), policies (every field, a secret field such as mail.smtp.password left out with no marker) and clients (the clients the operator manages, sorted by client_id, without a client secret or a private key member). A client a developer owns, a self-registered or CIMD client, the system client and a service account's are left out. Fields that describe the realm's environment, such as a client's environment, stay. The text is canonical (members in a fixed order, every set sorted): two exports of the same state are byte-identical, and importing the file into the realm plans no change. Content-Disposition names the file <realm>.realm.json. It needs realms.export; it writes nothing and shows no secret. A realm holding a value no realm file can hold, such as a stored URL with a user name or password, is refused (422), naming each client and member, never a value; so is a realm with more than ${MAX_IMPORT_CLIENTS} clients.`,
        'x-qauth-errors': [400, 401, 403, 404, 422, 503],
        params: realmParams,
        response: { 200: realmFileResponseSchema },
      },
    },
    async (request, reply) => {
      const realm = requestAdminCaller(request).targetRealm;
      // Imported here, not with the module: they read the environment, and
      // the unit tests import the routes without one.
      const [{ systemClientId }, { isCimdClientId }] = await Promise.all([
        import('../../helpers/oauth-client'),
        import('../../helpers/cimd'),
      ]);
      let text: string;
      try {
        const state = await readImportState(request, realm, {
          systemClientId: systemClientId(),
          isCimdClientId,
        });
        text = serializeRealmFile(exportRealmFile(state));
      } catch (error) {
        if (error instanceof PolicySchemaVersionError && error.reason === 'newer') {
          // A later release's policies, during a rolling upgrade: a node of
          // that release exports them.
          throw new TemporarilyUnavailableError(30, { operation: EXPORT_OPERATION_IDS.export });
        }
        if (error instanceof TooManyClientsError) {
          throw new UnprocessableContentError(
            [{ pointer: '', message: error.message }],
            'This realm holds more clients than an export reads.'
          );
        }
        if (error instanceof RealmFileExportError) {
          throw new UnprocessableContentError(error.issues, REALM_NOT_EXPORTABLE_MESSAGE);
        }
        throw error;
      }
      reply
        .header('cache-control', 'no-store')
        .header('content-disposition', realmFileDisposition(realm.name))
        .type('application/json; charset=utf-8');
      // The canonical text as it is: Fastify sends a string with a JSON type
      // unserialized, so the bytes are the file's. The route's type knows
      // only the object the document describes.
      return reply.send(text as unknown as z.infer<typeof realmFileResponseSchema>);
    }
  );
};
