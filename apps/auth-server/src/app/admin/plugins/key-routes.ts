import {
  KeyChangeRefusedError,
  KeyCreationRefusedError,
  KeyIdConflictError,
  NextKeyConflictError,
  type UpstreamClientKeyAlgorithm,
  type UpstreamClientKeys,
} from '@qauth-labs/fastify-plugin-signer';
import {
  BadRequestError,
  NotFoundError,
  TemporarilyUnavailableError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { rfc3339 } from '../../api-conventions/time';
import { type AdminOperation, operationSchemaExtensions } from '../../helpers/admin-operations';
import { authMethodPluginStateMismatch } from '../../helpers/auth-method-plugins';
import { PluginKeyConflictError } from '../../helpers/plugin-key-errors';
import {
  ADMIN_SECURITY_SCHEME,
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
} from '../pipeline';
import { openRequestSealedValue } from '../secrets/sealed-values';
import { SEALED_VALUE_SCHEMA } from '../secrets/secret-members';
import { PLUGIN_KEY_OPERATION_IDS } from './key-operations';
import { installedPluginParams, pluginSealScope } from './routes';

/**
 * THE CLIENT-ASSERTION KEY ROUTES OF A PROVIDER PLUGIN (ADR-019 Decisions 9
 * and 12, issue #1073):
 *
 *   POST /admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/keys           — plugins.keys.import, an approval required
 *   POST /admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/keys/activate  — plugins.keys.activate, an approval required
 *
 * The key is the realm's `upstream_client_assertion` key scoped to the
 * plugin's AuthMethod type, the provider id the signer signs a plugin's
 * client assertions under. The signer's wiring seals it under the KEK
 * (`fastify.upstreamClientKeys`), in the call's transaction, so the key and
 * the call's audit row commit together. A process that holds no KEK answers
 * 503: the key goes only to the signer.
 *
 * See `./key-operations.ts` for what each operation is and why it is a
 * security operation.
 */

/** The path of a plugin's client-assertion keys, as the admin listener routes it. */
const KEYS_PATH = '/admin/v1-rc.0/realms/:realmId/plugins/:plugin/keys';

/** The member the import's sealed key sits at. */
const PRIVATE_KEY_MEMBER = '/privateKey';

/**
 * A key id as a provider names it: printable ASCII without spaces, at most
 * 255 characters (`MAX_IMPORTED_KEY_ID_LENGTH` of the key library, which
 * checks it again).
 */
const keyIdSchema = z
  .string()
  .min(1)
  .max(255)
  .regex(/^[\x21-\x7e]+$/)
  .meta({
    description:
      "The provider's id of the key, kept as its kid, such as the Key ID Apple shows for a Sign in with Apple key.",
  });

const importBody = z
  .strictObject({
    kid: keyIdSchema,
    privateKey: SEALED_VALUE_SCHEMA.meta({
      description:
        'The private key, unencrypted PKCS#8 or SEC 1 PEM (the contents of the .p8 file Apple issues), sealed by secrets.seal for plugins.keys.import, the member /privateKey and the params { plugin }.',
    }),
  })
  .meta({ id: 'AdminPluginKeyImportRequest' });

const activateBody = z
  .strictObject({
    kid: keyIdSchema.meta({
      description: "The plugin's next key, which signs its client assertions from now on.",
    }),
  })
  .meta({ id: 'AdminPluginKeyActivationRequest' });

/** An imported key, as the admin API answers it: never the key itself. */
const importedKeySchema = z
  .object({
    kid: z.string(),
    algorithm: z.enum(['RS256', 'ES256', 'EdDSA']).meta({
      description: "The key's JWS algorithm: the one the plugin's configuration asks for.",
    }),
    status: z.enum(['active', 'next']).meta({
      description:
        "active: it signs the plugin's client assertions now. next: it waits for plugins.keys.activate, and the active key signs until then.",
    }),
  })
  .meta({ id: 'AdminPluginKey' });

/** A switch, as the admin API answers it. */
const activationSchema = z
  .object({
    activatedKid: z.string().meta({ description: 'The key that signs from now on.' }),
    retiredKid: z.string().nullable().meta({
      description: 'The key that stopped signing, or null when the plugin had no active key.',
    }),
    activatedAt: z.iso.datetime(),
  })
  .meta({ id: 'AdminPluginKeyActivation' });

type PluginKeyOperations = Record<keyof typeof PLUGIN_KEY_OPERATION_IDS, AdminOperation>;

/**
 * The key operations in the pipeline's registry, or `undefined` when it holds
 * none of them: a test registry built from fixture operations alone serves no
 * key route, and the server's own registry (`OPERATION_REGISTRY`) holds both.
 *
 * @throws {Error} when it holds one and not the other
 */
function pluginKeyOperations(fastify: FastifyInstance): PluginKeyOperations | undefined {
  const { registry } = fastify.adminApi;
  const imported = registry.get(PLUGIN_KEY_OPERATION_IDS.import);
  const activate = registry.get(PLUGIN_KEY_OPERATION_IDS.activate);
  if (imported === undefined && activate === undefined) return undefined;
  if (imported === undefined || activate === undefined) {
    throw new Error('The operation registry defines some plugin key operations and not others');
  }
  return { import: imported, activate };
}

/** The signer's key custody on this process, or 503 when it holds no KEK. */
function keyCustody(request: FastifyRequest, operationId: string): UpstreamClientKeys {
  const keys = request.server.upstreamClientKeys;
  if (keys === null || keys === undefined) {
    throw new TemporarilyUnavailableError(60, {
      reason: 'signer_service_not_reachable',
      operation: operationId,
    });
  }
  return keys;
}

/** The installed plugin of the path, or 404. */
function installedPlugin(fastify: FastifyInstance, name: string) {
  const plugin = fastify.authMethodPlugins.find(name);
  if (plugin === undefined) throw new NotFoundError('Plugin', name);
  return plugin;
}

/**
 * A key library refusal as the admin API answers it: 400 for a key, kid or
 * request it refuses, 409 for the keys as they stand. Each message names the
 * algorithm, the key type or the kid, never key material (the key library
 * keeps it so). Anything else is thrown on.
 */
function keyRefusal(error: unknown): never {
  if (error instanceof KeyCreationRefusedError) {
    throw new BadRequestError(error.message);
  }
  if (error instanceof KeyChangeRefusedError) {
    throw error.statusCode === 409
      ? new PluginKeyConflictError(error.message)
      : new BadRequestError(error.message);
  }
  if (error instanceof KeyIdConflictError) {
    throw new PluginKeyConflictError(
      'The realm already holds a key with this kid: a provider names each key it issues apart'
    );
  }
  if (error instanceof NextKeyConflictError) {
    throw new PluginKeyConflictError(
      'The plugin already has a next key waiting: switch to it with plugins.keys.activate first'
    );
  }
  throw error;
}

/** Register the client-assertion key routes behind the admin pipeline. */
export const pluginKeyRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const operations = pluginKeyOperations(fastify);
  if (operations === undefined) return;
  const params = installedPluginParams(fastify.authMethodPlugins.installed);
  const common = {
    'x-qauth-stability': 'experimental' as const,
    // A DPoP-bound admin token (#520).
    security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
  };

  typed.post(
    KEYS_PATH,
    {
      config: {
        operation: operations.import.id,
        // A sealed key opens only for the plugin's installed package and type.
        sealScope: (values) => pluginSealScope(fastify.authMethodPlugins, values),
      },
      schema: {
        ...operationSchemaExtensions(operations.import),
        ...common,
        summary:
          "Import a provider-issued private key as an AuthMethod plugin's client-assertion key",
        description:
          "Imports a private key the provider issued, such as Sign in with Apple's .p8 key, with the provider's key id as its kid, as the key the signer signs the plugin's client assertions with in the realm. The key is sent sealed under privateKey, with a value secrets.seal sealed for plugins.keys.import, the member /privateKey and the params { plugin }; it is stored sealed under the KEK and never returned. Its algorithm must be the one the realm's configuration of the plugin asks for, so the plugin is configured first: 409 when its configuration names no client assertion. The plugin's first key of the algorithm signs at once; a second waits as next until plugins.keys.activate, and 409 while one is already waiting or the kid is taken. 400 for a key that is not an unencrypted private key of the algorithm.",
        'x-qauth-errors': [400, 401, 403, 404, 409],
        params,
        body: importBody,
        response: { 200: importedKeySchema },
      },
    },
    async (request) => {
      const plugin = installedPlugin(fastify, request.params.plugin);
      const realmId = requestAdminCaller(request).targetRealm.id;
      const tx = adminTransaction(request);
      const keys = keyCustody(request, operations.import.id);

      // The algorithm the realm's configuration of the plugin asks for, as
      // the last configure or enable stored it for the signer.
      const row = await request.server.repositories.realmAuthMethodPlugins.find(
        realmId,
        plugin.id,
        tx
      );
      if (row === undefined || authMethodPluginStateMismatch(plugin, row) !== null) {
        throw new PluginKeyConflictError(
          'The realm has no configuration of the installed plugin: configure it, then import the key its configuration asks for'
        );
      }
      const algorithm = row.assertionAlgorithm;
      if (algorithm !== 'RS256' && algorithm !== 'ES256' && algorithm !== 'EdDSA') {
        throw new PluginKeyConflictError(
          "The realm's configuration of the plugin names no client assertion: its provider config authenticates with a client secret, so it signs with no key"
        );
      }

      const privateKeyPem = await openRequestSealedValue(
        request,
        PRIVATE_KEY_MEMBER,
        request.body.privateKey.sealed,
        'the private key'
      );
      let imported;
      try {
        imported = await keys.importKey({
          realmId,
          providerId: plugin.type,
          algorithm: algorithm satisfies UpstreamClientKeyAlgorithm,
          kid: request.body.kid,
          privateKeyPem,
          tx,
        });
      } catch (error) {
        keyRefusal(error);
      }

      recordAdminChange(request, {
        change: {
          before: null,
          after: {
            plugin: plugin.id,
            kid: imported.kid,
            algorithm: imported.algorithm,
            status: imported.status,
          },
        },
        annotations: {},
      });
      return {
        kid: imported.kid,
        algorithm: imported.algorithm,
        status: imported.status,
      };
    }
  );

  typed.post(
    `${KEYS_PATH}/activate`,
    {
      config: { operation: operations.activate.id },
      schema: {
        ...operationSchemaExtensions(operations.activate),
        ...common,
        summary: "Switch an AuthMethod plugin's client assertions to its next key",
        description:
          "Makes the plugin's next key the one the signer signs its client assertions with in the realm, and retires the key that signed until then. Refused with 409 while the next key has been published for less than the rotation overlap (seven days by default), or when the kid names no next key of the plugin.",
        'x-qauth-errors': [400, 401, 403, 404, 409],
        params,
        body: activateBody,
        response: { 200: activationSchema },
      },
    },
    async (request) => {
      const plugin = installedPlugin(fastify, request.params.plugin);
      const realmId = requestAdminCaller(request).targetRealm.id;
      const keys = keyCustody(request, operations.activate.id);
      let activated;
      try {
        activated = await keys.activate({
          realmId,
          providerId: plugin.type,
          kid: request.body.kid,
          tx: adminTransaction(request),
        });
      } catch (error) {
        keyRefusal(error);
      }

      recordAdminChange(request, {
        change: {
          before: {
            plugin: plugin.id,
            activeKid: activated.retiredKid,
            nextKid: activated.activatedKid,
          },
          after: { plugin: plugin.id, activeKid: activated.activatedKid, nextKid: null },
        },
        annotations: {},
      });
      return {
        activatedKid: activated.activatedKid,
        retiredKid: activated.retiredKid,
        activatedAt: rfc3339(activated.activateAt),
      };
    }
  );
};
