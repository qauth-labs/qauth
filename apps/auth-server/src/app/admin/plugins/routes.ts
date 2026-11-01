import type { RealmAuthMethodPlugin } from '@qauth-labs/fastify-plugin-db';
import {
  configMemberAt,
  type InstalledAuthMethodPlugin,
  MAX_AUTH_METHOD_SECRET_LENGTH,
  withConfigMembers,
} from '@qauth-labs/fastify-plugin-federation';
import { BadRequestError, NotFoundError, PreconditionFailedError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { ifMatchAllows } from '../../api-conventions/conditional-requests';
import { pageQuerySchema, pageSchema } from '../../api-conventions/paging';
import { type AdminOperation, operationSchemaExtensions } from '../../helpers/admin-operations';
import { InvalidCursorError } from '../../helpers/api-request-errors';
import {
  AUTH_METHOD_PLUGIN_SIGNER_CALLER,
  authMethodPluginSecretContext,
} from '../../helpers/auth-method-plugins';
import {
  type AdminChange,
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
} from '../pipeline';
import { PLUGIN_OPERATION_IDS } from './operations';

/**
 * THE PLUGIN ROUTES OF THE ADMIN API (ADR-019 Decisions 7, 10 and 12, issue
 * #600), under `/admin/v1-rc.0/realms/{realmId}/plugins`:
 *
 * - `GET  …/plugins` lists the installed plugins with the realm's state of
 *   each (`plugins.list`), one page at a time;
 * - `GET  …/plugins/{plugin}` reads one (`plugins.get`), with its `ETag`;
 * - `POST …/plugins/{plugin}/config` replaces its config and sets or clears
 *   its secret members (`plugins.update`);
 * - `POST …/plugins/{plugin}/enable` and `…/disable` turn it on and off
 *   (`plugins.enable`, `plugins.disable`).
 *
 * `{plugin}` is the plugin's name, its AuthMethod id.
 *
 * The three writes are security operations: each runs only with an approval
 * filed for exactly that request. Each may carry `If-Match` with the `ETag`
 * of the state it was written against, and is refused with 412 when the
 * plugin's state moved; the write itself is conditional on the version it
 * read in its transaction, so two admins never overwrite each other unseen.
 *
 * SECRETS. A plugin's config schema marks its secret members
 * (`writeOnly`). A request sends them apart from the plain members, under
 * `secrets`, by path: a string sets one, `null` clears it, and one it does
 * not name keeps its value. The body schema refuses any installed plugin's
 * secret member under `config`, so an approval, which stores the request
 * until it is used, never holds a secret where it would be shown. The server
 * encrypts each value with the realm's `data_at_rest` key before it stores
 * it; no response, no audit row and no log line holds one: the
 * representation says only which secret members hold a value.
 *
 * The admin API never uploads, replaces or edits plugin code.
 */

const PLUGINS_PATH = '/admin/v1-rc.0/realms/:realmId/plugins';

/** The name the cursors of the plugin list carry. */
const PLUGIN_LIST = 'admin.plugins';

/** The most plain members a config may set at its top level. */
const MAX_CONFIG_MEMBERS = 64;

/** The largest config a request may set, as JSON. */
const MAX_CONFIG_BYTES = 16 * 1024;

/**
 * A plugin's name in this API: its AuthMethod id, as the contract defines it
 * (`AUTH_METHOD_ID_PATTERN`). A stable name, not a UUID, so the API calls it
 * `name` and never `id`.
 */
const pluginNameSchema = z
  .string()
  .regex(/^[a-z][a-z0-9_-]{0,62}$/)
  .meta({ description: "The plugin's name: its AuthMethod id, such as `corp-sso`." });

const realmParams = z.object({ realmId: z.uuid() });
const pluginParams = z.object({ realmId: z.uuid(), plugin: pluginNameSchema });

/** A plugin as the admin API shows it in a realm. */
const pluginSchema = z
  .object({
    name: z.string().meta({
      description: "The plugin's AuthMethod id: the name this API and its path give it.",
    }),
    type: z.string().meta({
      description:
        "The method's type: its sign-in routes answer under `/upstream/{type}` on the realm host.",
    }),
    package: z.string().meta({ description: 'The npm package the deployment loaded it from.' }),
    firstParty: z.boolean().meta({
      description:
        "One of QAuth's first-party plugins. Any other runs on the experimental plugin API (`plugin-api`).",
    }),
    contract: z
      .string()
      .meta({ description: 'The AuthMethod contract version it is written against.' }),
    displayName: z.string().meta({ description: "The plugin's default display name." }),
    enabled: z.boolean().meta({ description: 'The realm offers it.' }),
    config: z.record(z.string(), z.unknown()).meta({
      description: "The realm's config of the plugin: its plain members, never a secret one.",
    }),
    secrets: z.array(z.object({ path: z.string(), set: z.boolean() })).meta({
      description:
        "Each secret member of the plugin's config, by path, and whether it holds a value. Its value is never shown.",
    }),
    version: z.int().min(0).meta({
      description:
        "The version of the realm's state of the plugin; `0` before it was first configured. Its ETag.",
    }),
  })
  .meta({ description: "An installed AuthMethod plugin and the realm's state of it." });

type PluginResource = z.infer<typeof pluginSchema>;

/** The state of a plugin a realm never configured. */
function stateOf(row: RealmAuthMethodPlugin | undefined) {
  return {
    enabled: row?.enabled ?? false,
    config: row?.config ?? {},
    secrets: row?.secrets ?? {},
    version: row?.version ?? 0,
  };
}

/** The representation of `plugin` in a realm whose row is `row`. */
export function pluginResource(
  plugin: InstalledAuthMethodPlugin,
  row: RealmAuthMethodPlugin | undefined
): PluginResource {
  const state = stateOf(row);
  return {
    name: plugin.id,
    type: plugin.type,
    package: plugin.package,
    firstParty: plugin.firstParty,
    contract: plugin.method.contract,
    displayName: plugin.method.display.name,
    enabled: state.enabled,
    config: structuredClone(state.config),
    secrets: plugin.secretPaths.map((path) => ({ path, set: Object.hasOwn(state.secrets, path) })),
    version: state.version,
  };
}

/** The entity tag of a plugin's state in a realm. */
function entityTag(row: RealmAuthMethodPlugin | undefined): string {
  return `"${stateOf(row).version}"`;
}

/** What the audit row records of a change: the representation, which holds no secret value. */
function auditSide(resource: PluginResource): NonNullable<AdminChange['change']['after']> {
  return JSON.parse(JSON.stringify(resource)) as NonNullable<AdminChange['change']['after']>;
}

/**
 * The body of `plugins.update`, for the plugins `installed` (#600): the
 * plain members under `config`, the secret members under `secrets`. A
 * `config` that holds a secret member of any installed plugin is refused,
 * so a secret is never sent where an approval or a renderer would read it as
 * a plain value.
 */
export function pluginConfigBodySchema(installed: readonly InstalledAuthMethodPlugin[]) {
  const secretPaths = [...new Set(installed.flatMap((plugin) => plugin.secretPaths))];
  return z
    .strictObject({
      config: z
        .record(z.string().min(1).max(64), z.unknown())
        .refine((config) => Object.keys(config).length <= MAX_CONFIG_MEMBERS, {
          message: `config sets at most ${MAX_CONFIG_MEMBERS} members`,
        })
        .refine(
          (config) => Buffer.byteLength(JSON.stringify(config) ?? '', 'utf8') <= MAX_CONFIG_BYTES,
          { message: `config is at most ${MAX_CONFIG_BYTES} bytes as JSON` }
        )
        .refine(
          (config) => secretPaths.every((path) => configMemberAt(config, path) === undefined),
          {
            message: 'config holds a secret member: send it under secrets',
          }
        )
        .meta({ description: "The plugin's plain config members: the whole config, replaced." }),
      secrets: z
        .record(
          z.string().min(1).max(260),
          z.string().min(1).max(MAX_AUTH_METHOD_SECRET_LENGTH).nullable()
        )
        .optional()
        .meta({
          description:
            'Secret members to set (a string) or clear (`null`), by path. One not named keeps its value. Write-only: no response shows a value.',
        }),
    })
    .meta({ description: "An AuthMethod plugin's configuration in the realm." });
}

/** The installed plugin of the path, or 404. */
function installedPlugin(fastify: FastifyInstance, name: string): InstalledAuthMethodPlugin {
  const plugin = fastify.authMethodPlugins.find(name);
  if (plugin === undefined) throw new NotFoundError('Plugin', name);
  return plugin;
}

/** Refuse a write named against another version of the state than `row`'s. */
function requireCurrent(
  request: FastifyRequest,
  operationId: string,
  row: RealmAuthMethodPlugin | undefined
): void {
  if (!ifMatchAllows(request.headers['if-match'], String(stateOf(row).version))) {
    throw new PreconditionFailedError({ operation: operationId });
  }
}

/** The plaintext of each secret the row holds, for a schema check only. */
async function storedSecrets(
  fastify: FastifyInstance,
  plugin: InstalledAuthMethodPlugin,
  realmId: string,
  ciphertexts: Readonly<Record<string, string>>
): Promise<Map<string, string>> {
  const plaintexts = new Map<string, string>();
  for (const path of plugin.secretPaths) {
    if (!Object.hasOwn(ciphertexts, path)) continue;
    const plaintext = await fastify.signer.decrypt(AUTH_METHOD_PLUGIN_SIGNER_CALLER, {
      realmId,
      ciphertext: ciphertexts[path],
      context: authMethodPluginSecretContext(plugin.id, path),
    });
    plaintexts.set(path, plaintext.toString('utf8'));
  }
  return plaintexts;
}

/**
 * Refuse a config the plugin's schema refuses, with 400, naming each failing
 * member and the schema's code, never a value.
 */
function requireValidConfig(
  plugin: InstalledAuthMethodPlugin,
  config: Readonly<Record<string, unknown>>,
  secrets: ReadonlyMap<string, string>
): void {
  const parsed = plugin.method.configSchema.safeParse(withConfigMembers(config, secrets));
  if (parsed.success) return;
  const members = parsed.error.issues
    .map((issue) => `${issue.path.map(String).join('.') || '(root)'}: ${issue.code}`)
    .slice(0, 16);
  throw new BadRequestError(
    `The configuration does not pass the plugin's config schema (${members.join('; ')})`
  );
}

/** The plugin's row in the request's realm, in the handler's transaction. */
async function rowOf(
  request: FastifyRequest,
  plugin: InstalledAuthMethodPlugin
): Promise<RealmAuthMethodPlugin | undefined> {
  return request.server.repositories.realmAuthMethodPlugins.find(
    requestAdminCaller(request).targetRealm.id,
    plugin.id,
    adminTransaction(request)
  );
}

/** Write a new state over `row`, conditional on its version; 412 when it moved. */
async function writeState(
  request: FastifyRequest,
  operationId: string,
  plugin: InstalledAuthMethodPlugin,
  row: RealmAuthMethodPlugin | undefined,
  state: {
    readonly enabled: boolean;
    readonly config: Readonly<Record<string, unknown>>;
    readonly secrets: Readonly<Record<string, string>>;
  }
): Promise<RealmAuthMethodPlugin> {
  const written = await request.server.repositories.realmAuthMethodPlugins.save(
    requestAdminCaller(request).targetRealm.id,
    plugin.id,
    state,
    row?.version ?? null,
    adminTransaction(request)
  );
  if (written === undefined) throw new PreconditionFailedError({ operation: operationId });
  return written;
}

/** Answer a plugin's representation with its `ETag`, and record the change. */
function answer(
  request: FastifyRequest,
  reply: FastifyReply,
  plugin: InstalledAuthMethodPlugin,
  before: RealmAuthMethodPlugin | undefined,
  after: RealmAuthMethodPlugin | undefined
): PluginResource {
  const resource = pluginResource(plugin, after);
  if (before !== after) {
    recordAdminChange(request, {
      change: {
        before: before === undefined ? null : auditSide(pluginResource(plugin, before)),
        after: auditSide(resource),
      },
      annotations: {},
    });
  }
  reply.header('etag', entityTag(after));
  return resource;
}

type PluginOperations = Record<keyof typeof PLUGIN_OPERATION_IDS, AdminOperation>;

/**
 * The plugin operations in the pipeline's registry, or `undefined` when it
 * defines none of them: a test registry built from fixture operations alone,
 * on which the listener serves no plugin route. The server's own registry
 * (`OPERATION_REGISTRY`) defines all of them.
 *
 * @throws {Error} when it defines some and not others
 */
function pluginOperations(fastify: FastifyInstance): PluginOperations | undefined {
  const { registry } = fastify.adminApi;
  const entries = Object.entries(PLUGIN_OPERATION_IDS).map(
    ([key, id]) => [key, registry.get(id)] as const
  );
  const missing = entries.filter(([, operation]) => operation === undefined);
  if (missing.length === entries.length) return undefined;
  if (missing.length > 0) {
    throw new Error(
      `The admin operation registry holds only some plugin operations; it lacks ${missing.map(([key]) => PLUGIN_OPERATION_IDS[key as keyof typeof PLUGIN_OPERATION_IDS]).join(', ')}`
    );
  }
  return Object.fromEntries(entries) as PluginOperations;
}

/** The position after which a page of the installed list starts, from its cursor. */
function pageStart(installed: readonly InstalledAuthMethodPlugin[], cursor: string | undefined) {
  if (cursor === undefined) return 0;
  let after: unknown;
  try {
    if (!/^[A-Za-z0-9_-]+$/.test(cursor)) throw new Error('not base64url');
    after = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
  } catch {
    throw new InvalidCursorError();
  }
  const { l, i } = (after ?? {}) as { l?: unknown; i?: unknown };
  const index = installed.findIndex((plugin) => plugin.id === i);
  if (l !== PLUGIN_LIST || index < 0) throw new InvalidCursorError();
  return index + 1;
}

/** Register the plugin routes behind the admin pipeline. */
export const pluginRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const operations = pluginOperations(fastify);
  if (operations === undefined) return;
  const configBody = pluginConfigBodySchema(fastify.authMethodPlugins.installed);
  const common = {
    'x-qauth-stability': 'experimental' as const,
    security: [{ bearerAuth: [] }],
  };

  typed.get(
    PLUGINS_PATH,
    {
      config: { operation: operations.list.id },
      schema: {
        ...operationSchemaExtensions(operations.list),
        ...common,
        summary: "List the installed AuthMethod plugins and the realm's state of each",
        'x-qauth-errors': [400, 401, 403, 404],
        params: realmParams,
        querystring: pageQuerySchema,
        response: { 200: pageSchema(pluginSchema) },
      },
    },
    async (request) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const { installed } = fastify.authMethodPlugins;
      const start = pageStart(installed, request.query.cursor);
      const page = installed.slice(start, start + request.query.limit);
      const rows = new Map(
        (
          await request.server.repositories.realmAuthMethodPlugins.listByRealm(
            realmId,
            adminTransaction(request)
          )
        ).map((row) => [row.pluginId, row])
      );
      const last = page.at(-1);
      return {
        items: page.map((plugin) => pluginResource(plugin, rows.get(plugin.id))),
        nextCursor:
          last !== undefined && start + page.length < installed.length
            ? Buffer.from(JSON.stringify({ l: PLUGIN_LIST, i: last.id }), 'utf8').toString(
                'base64url'
              )
            : null,
      };
    }
  );

  typed.get(
    `${PLUGINS_PATH}/:plugin`,
    {
      config: { operation: operations.get.id },
      schema: {
        ...operationSchemaExtensions(operations.get),
        ...common,
        summary: "Read an installed AuthMethod plugin and the realm's state of it",
        'x-qauth-errors': [400, 401, 403, 404],
        params: pluginParams,
        response: { 200: pluginSchema },
      },
    },
    async (request, reply) => {
      const plugin = installedPlugin(fastify, request.params.plugin);
      const row = await rowOf(request, plugin);
      reply.header('etag', entityTag(row));
      return pluginResource(plugin, row);
    }
  );

  typed.post(
    `${PLUGINS_PATH}/:plugin/config`,
    {
      config: { operation: operations.update.id },
      schema: {
        ...operationSchemaExtensions(operations.update),
        ...common,
        summary: "Replace an AuthMethod plugin's configuration in the realm",
        'x-qauth-errors': [400, 401, 403, 404, 412],
        params: pluginParams,
        body: configBody,
        response: { 200: pluginSchema },
      },
    },
    async (request, reply) => {
      const plugin = installedPlugin(fastify, request.params.plugin);
      const realmId = requestAdminCaller(request).targetRealm.id;
      const row = await rowOf(request, plugin);
      requireCurrent(request, operations.update.id, row);
      const { config, secrets: changes = {} } = request.body;

      const unknown = Object.keys(changes).filter((path) => !plugin.secretPaths.includes(path));
      if (unknown.length > 0) {
        throw new BadRequestError(
          `The plugin has no secret member ${unknown.map((path) => JSON.stringify(path)).join(', ')}`
        );
      }
      const misplaced = plugin.secretPaths.filter(
        (path) => configMemberAt(config, path) !== undefined
      );
      if (misplaced.length > 0) {
        throw new BadRequestError('config holds a secret member: send it under secrets');
      }

      // The secrets the realm will hold: those kept, and those set.
      const stored = stateOf(row).secrets;
      const plaintexts = await storedSecrets(fastify, plugin, realmId, stored);
      for (const [path, value] of Object.entries(changes)) {
        if (value === null) plaintexts.delete(path);
        else plaintexts.set(path, value);
      }
      requireValidConfig(plugin, config, plaintexts);

      const ciphertexts: Record<string, string> = {};
      for (const path of plugin.secretPaths) {
        if (!plaintexts.has(path)) continue;
        const change = Object.hasOwn(changes, path) ? changes[path] : undefined;
        ciphertexts[path] =
          change === undefined || change === null
            ? stored[path]
            : await fastify.signer.encrypt(AUTH_METHOD_PLUGIN_SIGNER_CALLER, {
                realmId,
                plaintext: Buffer.from(change, 'utf8'),
                context: authMethodPluginSecretContext(plugin.id, path),
              });
      }
      const written = await writeState(request, operations.update.id, plugin, row, {
        enabled: stateOf(row).enabled,
        config,
        secrets: ciphertexts,
      });
      return answer(request, reply, plugin, row, written);
    }
  );

  typed.post(
    `${PLUGINS_PATH}/:plugin/enable`,
    {
      config: { operation: operations.enable.id },
      schema: {
        ...operationSchemaExtensions(operations.enable),
        ...common,
        summary: 'Enable an AuthMethod plugin in the realm',
        'x-qauth-errors': [400, 401, 403, 404, 412],
        params: pluginParams,
        body: z.null().optional(),
        response: { 200: pluginSchema },
      },
    },
    async (request, reply) => {
      const plugin = installedPlugin(fastify, request.params.plugin);
      const realmId = requestAdminCaller(request).targetRealm.id;
      const row = await rowOf(request, plugin);
      requireCurrent(request, operations.enable.id, row);
      if (row?.enabled === true) return answer(request, reply, plugin, row, row);
      const state = stateOf(row);
      // A plugin is enabled only with a config its own schema accepts.
      requireValidConfig(
        plugin,
        state.config,
        await storedSecrets(fastify, plugin, realmId, state.secrets)
      );
      const written = await writeState(request, operations.enable.id, plugin, row, {
        enabled: true,
        config: state.config,
        secrets: state.secrets,
      });
      return answer(request, reply, plugin, row, written);
    }
  );

  typed.post(
    `${PLUGINS_PATH}/:plugin/disable`,
    {
      config: { operation: operations.disable.id },
      schema: {
        ...operationSchemaExtensions(operations.disable),
        ...common,
        summary: 'Disable an AuthMethod plugin in the realm',
        'x-qauth-errors': [400, 401, 403, 404, 412],
        params: pluginParams,
        body: z.null().optional(),
        response: { 200: pluginSchema },
      },
    },
    async (request, reply) => {
      const plugin = installedPlugin(fastify, request.params.plugin);
      const row = await rowOf(request, plugin);
      requireCurrent(request, operations.disable.id, row);
      if (row === undefined || !row.enabled) return answer(request, reply, plugin, row, row);
      const written = await writeState(request, operations.disable.id, plugin, row, {
        enabled: false,
        config: row.config,
        secrets: row.secrets,
      });
      return answer(request, reply, plugin, row, written);
    }
  );
};
