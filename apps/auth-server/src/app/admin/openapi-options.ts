import type { FastifyDynamicSwaggerOptions } from '@fastify/swagger';

import {
  ADMIN_DPOP_SCHEME,
  DPOP_SECURITY_SCHEME,
  FAMILY_DOCUMENT_INFO,
  familyContractVersion,
} from '../api-conventions/family-documents';
import { openapiOptions } from '../openapi-options';

/**
 * The OpenAPI options of the admin listener: the server's own (#347), so the
 * admin document carries the same `Problem` schema, error responses and
 * extensions, under the admin API's title and contract version, with the one
 * security scheme its operations require, `DPoP`. The listener serves the
 * admin family's document cut from this one (`familyDocument`, #525).
 */
export const adminOpenapiOptions: FastifyDynamicSwaggerOptions = {
  ...openapiOptions,
  openapi: {
    ...openapiOptions.openapi,
    info: { ...FAMILY_DOCUMENT_INFO.admin, version: familyContractVersion('admin') },
    // The DPoP scheme only: no admin operation takes a Bearer token. The
    // public document's components hold its own schemes; the schemas are
    // added when the document is built (`transformObject`).
    components: {
      securitySchemes: {
        [DPOP_SECURITY_SCHEME]: { ...ADMIN_DPOP_SCHEME, type: 'http' },
      },
    },
  },
};
