import { BadRequestError } from '@qauth-labs/shared-errors';
import type { FastifyPluginAsync } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { OPERATION_ID_PATTERN, operationSchemaExtensions } from '../../helpers/admin-operations';
import { ADMIN_SECURITY_SCHEME, requestAdminCaller } from '../pipeline';
import { SECRET_OPERATION_IDS } from './operations';
import { declaresSecretMember, sealBindingOf, sealValue } from './sealed-values';
import { MAX_SEALED_SECRET_LENGTH, MAX_SECRET_MEMBER_LENGTH } from './secret-members';

/**
 * THE SEAL ROUTE OF THE ADMIN API (ADR-019 Decision 7, issue #984):
 * `POST /admin/v1-rc.0/realms/{realmId}/secrets/seal` (`secrets.seal`).
 *
 * It takes a secret's value for one secret member of a security operation
 * (`operation`, `member`: a JSON Pointer into that operation's body that its
 * definition declares secret, such as `/secrets/clientSecret` of
 * `plugins.update`) in one request of it (`params`: the path parameters of
 * that request but the realm's, such as `{ "plugin": "corp-sso" }`, which the
 * operation's own route parses), encrypts it with the realm's `data_at_rest`
 * key under a context bound to the operation, the member, those parameters
 * and what the route binds beside them (`sealScope`, such as the installed
 * plugin's package and type), and answers the ciphertext, which the
 * operation's request then carries as `{ "sealed": … }`. It stores nothing,
 * changes nothing, and records no value: no response, audit row or log line
 * holds the value.
 */

const SECRETS_PATH = '/admin/v1-rc.0/realms/:realmId/secrets';

/**
 * Whether `value` is well-formed UTF-16, with no lone surrogate:
 * `String.prototype.isWellFormed` (ES2024; the workspace's TypeScript lib is
 * ES2022). UTF-8 cannot carry a lone surrogate: the signer would seal U+FFFD
 * in its place, and the secret the operation stores would not be the one sent.
 */
function isWellFormedText(value: string): boolean {
  return (String.prototype as unknown as { isWellFormed(this: string): boolean }).isWellFormed.call(
    value
  );
}

/** A path parameter's name, as a route's URL writes it. */
const PARAMETER_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

/** What the seal route answers a request that names no request of a security operation. */
const NO_SECRET_MEMBER =
  'The request names no secret member of a security operation of this server, in a request of it in this realm';

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
    params: z.record(z.string().regex(PARAMETER_NAME), z.string().max(1024)).optional().meta({
      description:
        'The path parameters of the operation\'s request the value is for, but realmId, such as `{ "plugin": "corp-sso" }`: the value opens only in a request with the same ones. None when the operation\'s path names only the realm.',
    }),
    value: z
      .string()
      .min(1)
      .max(MAX_SEALED_SECRET_LENGTH)
      .refine(isWellFormedText, {
        message:
          'value is not well-formed text: it holds a lone surrogate, which UTF-8 cannot carry',
      })
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
          "Encrypts the value with the realm's data_at_rest key, bound to the operation, the member and the path parameters of the request it is for, and answers the ciphertext. It changes nothing and records no value; the operation's request carries the sealed value, never the secret, so its approval holds none.",
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
      const { operation: operationId, member, params = {}, value } = request.body;
      const operation = fastify.adminApi.registry.get(operationId);
      const route = operation === undefined ? undefined : fastify.adminApi.routeOf(operation.id);
      // Nothing is echoed: a client that swapped the member, a parameter and
      // the value would get the value back, and the log would keep it.
      if (
        operation === undefined ||
        route === undefined ||
        route.params === undefined ||
        !declaresSecretMember(operation, member)
      ) {
        throw new BadRequestError(NO_SECRET_MEMBER);
      }
      // The parameters as the operation's own route parses its request's, in
      // the realm of this path: the binding its handler reads.
      const parsed = route.params.safeParse({ ...params, realmId: request.params.realmId });
      if (!parsed.success || typeof parsed.data !== 'object' || parsed.data === null) {
        throw new BadRequestError(NO_SECRET_MEMBER);
      }
      const binding = await sealBindingOf(route, parsed.data as Record<string, unknown>);
      if (binding === undefined) throw new BadRequestError(NO_SECRET_MEMBER);
      const sealed = await sealValue(
        fastify,
        requestAdminCaller(request).targetRealm.id,
        operation,
        member,
        binding,
        value
      );
      return { operation: operation.id, member, sealed };
    }
  );
};
