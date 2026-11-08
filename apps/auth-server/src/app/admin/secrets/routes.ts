import { BadRequestError } from '@qauth-labs/shared-errors';
import type { FastifyPluginAsync } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { OPERATION_ID_PATTERN, operationSchemaExtensions } from '../../helpers/admin-operations';
import { ADMIN_SECURITY_SCHEME, requestAdminCaller } from '../pipeline';
import { SECRET_OPERATION_IDS } from './operations';
import { declaresSecretMember, sealValue } from './sealed-values';
import { MAX_SEALED_SECRET_LENGTH, MAX_SECRET_MEMBER_LENGTH } from './secret-members';

/**
 * THE SEAL ROUTE OF THE ADMIN API (ADR-019 Decision 7, issue #984):
 * `POST /admin/v1-rc.0/realms/{realmId}/secrets/seal` (`secrets.seal`).
 *
 * It takes a secret's value for one secret member of a security operation
 * (`operation`, `member`: a JSON Pointer into that operation's body that its
 * definition declares secret, such as `/secrets/clientSecret` of
 * `plugins.update`), encrypts it with the realm's `data_at_rest` key under a
 * context bound to the operation and the member, and answers the ciphertext,
 * which the operation's request then carries as `{ "sealed": … }`. It stores
 * nothing, changes nothing, and records no value: no response, audit row or
 * log line holds the value.
 */

const SECRETS_PATH = '/admin/v1-rc.0/realms/:realmId/secrets';

/** The body of `secrets.seal`. */
export const sealBodySchema = z
  .strictObject({
    operation: z.string().max(128).regex(OPERATION_ID_PATTERN).meta({
      description:
        'The security operation whose request will carry the value, such as `plugins.update`.',
    }),
    member: z.string().min(2).max(MAX_SECRET_MEMBER_LENGTH).meta({
      description:
        "The secret member of that operation's body the value is for, as a JSON Pointer (RFC 6901), such as `/secrets/clientSecret`: one the operation declares secret.",
    }),
    value: z
      .string()
      .min(1)
      .max(MAX_SEALED_SECRET_LENGTH)
      .meta({ description: 'The secret. Write-only: no response, row or log holds it.' }),
  })
  .meta({ description: "A value to seal for a security operation's secret member." });

/** Register the seal route behind the admin pipeline. */
export const secretRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const seal = fastify.adminApi.registry.get(SECRET_OPERATION_IDS.seal);
  // A test registry built from fixture operations alone serves no seal route;
  // the server's own registry (`OPERATION_REGISTRY`) holds it.
  if (seal === undefined) return;

  typed.post(
    `${SECRETS_PATH}/seal`,
    {
      config: { operation: seal.id },
      schema: {
        ...operationSchemaExtensions(seal),
        'x-qauth-stability': 'experimental',
        // A DPoP-bound admin token (#520).
        security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
        summary: "Seal a value for a security operation's secret member in the realm",
        description:
          "Encrypts the value with the realm's data_at_rest key, bound to the operation and the member, and answers the ciphertext. It changes nothing and records no value; the operation's request carries the sealed value, never the secret, so its approval holds none.",
        'x-qauth-errors': [400, 401, 403, 404],
        params: z.object({ realmId: z.uuid() }),
        body: sealBodySchema,
        response: {
          200: z
            .object({
              operation: z.string(),
              member: z.string(),
              sealed: z.string().meta({
                description:
                  'The value, encrypted for this member of this operation in this realm: what the operation\'s request sends at the member, as { "sealed": … }.',
              }),
            })
            .meta({ description: 'A sealed secret value.' }),
        },
      },
    },
    async (request) => {
      const { operation: operationId, member, value } = request.body;
      const operation = fastify.adminApi.registry.get(operationId);
      if (operation === undefined || !declaresSecretMember(operation, member)) {
        // Neither is echoed: a client that swapped the member and the value
        // would get the value back, and the log would keep it.
        throw new BadRequestError(
          'The request names no secret member of a security operation of this server'
        );
      }
      const sealed = await sealValue(
        fastify,
        requestAdminCaller(request).targetRealm.id,
        operation,
        member,
        value
      );
      return { operation: operation.id, member, sealed };
    }
  );
};
