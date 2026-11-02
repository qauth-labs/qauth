import type { FastifyDynamicSwaggerOptions } from '@fastify/swagger';

import { openapiOptions } from '../openapi-options';
import { ADMIN_SECURITY_SCHEME } from './pipeline';

/**
 * The OpenAPI options of the admin listener: the server's own (#347), so the
 * admin document carries the same `Problem` schema, error responses and
 * extensions, under the admin API's title, with the one security scheme its
 * operations require, `DPoP` ({@link ADMIN_SECURITY_SCHEME}).
 */
export const adminOpenapiOptions: FastifyDynamicSwaggerOptions = {
  ...openapiOptions,
  openapi: {
    ...openapiOptions.openapi,
    info: {
      title: 'QAuth Admin API',
      description:
        "The admin API of QAuth (ADR-019 Decision 7), served on the internal admin listener only. Every operation needs a DPoP-bound admin token, sent as `Authorization: DPoP <token>` with a proof made with its key for this listener's base URL and the request's path, whose account holds a grant on the realm in the path; a security operation also needs an approval bound to it.",
      version: '1.0.0',
    },
    // The DPoP scheme only: no admin operation takes a Bearer token. The
    // public document's components hold only its `bearerAuth` scheme; the
    // schemas are added when the document is built (`transformObject`).
    components: {
      securitySchemes: {
        [ADMIN_SECURITY_SCHEME]: {
          type: 'http',
          scheme: 'DPoP',
          bearerFormat: 'JWT',
          description:
            "A DPoP-bound admin access token (RFC 9449 §7.1): `Authorization: DPoP <token>`, and a `DPoP` header holding a proof signed with the key the token names in `cnf.jkt`, for the request's method, ADMIN_API_BASE_URL followed by the request's path, an `iat` within 60 seconds, the token's hash as `ath` and a `jti` never used before. A Bearer token is refused.",
        },
      },
    },
  },
};
