import type { FastifyInstance, FastifyReply } from 'fastify';

import { env } from '../../config/env';
import {
  ASSOCIATION_FILES_CACHE_CONTROL,
  buildAppleAppSiteAssociation,
  buildAssetLinks,
} from '../helpers/app-association';
import { defaultRealmIssuerFrom } from '../helpers/default-realm-boot';
import {
  resolveRealmRelyingParty,
  servesAssociationFiles,
} from '../helpers/webauthn-relying-party';

/**
 * The platform association files of the default realm (ADR-017 Decision 14,
 * issue #467):
 *
 * - `GET /.well-known/apple-app-site-association` — the `webcredentials` apps
 *   of `WEBAUTHN_APPLE_APP_IDS`;
 * - `GET /.well-known/assetlinks.json` — the Android apps of
 *   `WEBAUTHN_ANDROID_APPS`, with the `get_login_creds` relation.
 *
 * A route exists only while the RP ID is the realm host and the operator listed
 * apps for its platform; otherwise the path answers the ordinary 404. Under a
 * parent-domain RP ID the platforms read these files from the parent domain,
 * so serving them here would be wrong. They do not depend on
 * `WEBAUTHN_ENABLED`: they only say which apps share the realm host's
 * credentials, and the platforms use the same files for saved passwords.
 *
 * The realm host is the host of `JWT_ISSUER`, as the default realm's boot step
 * takes it (ADR-019 Decision 1: no URL is built from the request).
 */
export default async function (fastify: FastifyInstance) {
  const relyingParty = resolveRealmRelyingParty(defaultRealmIssuerFrom(env.JWT_ISSUER).host, {
    rpId: env.WEBAUTHN_RP_ID,
    allowParentDomainRpId: env.WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN,
  });
  if (!servesAssociationFiles(relyingParty)) return;

  if (env.WEBAUTHN_APPLE_APP_IDS.length > 0) {
    const document = buildAppleAppSiteAssociation(env.WEBAUTHN_APPLE_APP_IDS);
    fastify.get(
      '/.well-known/apple-app-site-association',
      {
        schema: {
          description:
            'Apple associated domains file: the apps that share the passkeys and passwords of the realm host (`webcredentials`). Served only while the passkey RP ID is the realm host.',
          tags: ['Discovery'],
          'x-qauth-stability': 'experimental',
        },
        config: { surface: 'meta' },
      },
      async (_request, reply) => sendAssociationFile(reply, document)
    );
  }

  if (Object.keys(env.WEBAUTHN_ANDROID_APPS).length > 0) {
    const statements = buildAssetLinks(env.WEBAUTHN_ANDROID_APPS);
    fastify.get(
      '/.well-known/assetlinks.json',
      {
        schema: {
          description:
            'Digital Asset Links statement list: the Android apps that share the sign-in credentials of the realm host (`get_login_creds`). Served only while the passkey RP ID is the realm host.',
          tags: ['Discovery'],
          'x-qauth-stability': 'experimental',
        },
        config: { surface: 'meta' },
      },
      async (_request, reply) => sendAssociationFile(reply, statements)
    );
  }
}

/**
 * Send a file with the exact `Content-Type: application/json` the platform
 * guides name. Fastify's JSON path appends `; charset=utf-8`; a serializer of
 * the reply's own keeps the header as set.
 */
function sendAssociationFile(reply: FastifyReply, document: unknown): FastifyReply {
  return reply
    .header('Cache-Control', ASSOCIATION_FILES_CACHE_CONTROL)
    .type('application/json')
    .serializer((payload: unknown) => JSON.stringify(payload))
    .send(document);
}
