import type { RealmAuthMethodPlugin } from '@qauth-labs/fastify-plugin-db';
import {
  configSpellsMemberOf,
  type InstalledAuthMethodPlugin,
  MAX_AUTH_METHOD_SECRET_LENGTH,
  withConfigMembers,
  withoutConfigMembers,
} from '@qauth-labs/fastify-plugin-federation';
import { BadRequestError, NotFoundError, PreconditionFailedError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { ifMatchAllows } from '../../api-conventions/conditional-requests';
import { pageQuerySchema, pageSchema } from '../../api-conventions/paging';
import { type AdminOperation, operationSchemaExtensions } from '../../helpers/admin-operations';
import { InvalidCursorError } from '../../helpers/api-request-errors';
import { authMethodPluginSecretCipher } from '../../helpers/auth-method-plugins';
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
 * - `POST …/plugins/{plugin}/secrets/seal` seals one secret member's value
 *   for the realm (`plugins.secrets.seal`): it changes nothing, and answers
 *   the value encrypted;
 * - `POST …/plugins/{plugin}/config` replaces its config and sets or clears
 *   its secret members (`plugins.update`), naming the version it replaces;
 * - `POST …/plugins/{plugin}/enable` and `…/disable` turn it on and off
 *   (`plugins.enable`, `plugins.disable`).
 *
 * `{plugin}` is the plugin's name, its AuthMethod id.
 *
 * The three writes are security operations: each runs only with an approval
 * filed for exactly that request. A configure names the version of the state
 * it replaces in its body (`version`), so the approval binds it and the
 * approver sees it, and a configure over a state that moved since is refused
 * with 412: two approved configures never overwrite each other unseen. An
 * enable or a disable may carry `If-Match`. Every write is conditional on
 * the version it read in its transaction.
 *
 * SECRETS. A plugin's config schema marks its secret members
 * (`writeOnly`). A secret's value reaches the server in one place only: the
 * body of `plugins.secrets.seal`, which encrypts it with the realm's
 * `data_at_rest` key, under a context bound to the plugin and the member,
 * and answers the ciphertext; it stores nothing and records no value. A
 * configure request then names each secret member apart from the plain
 * ones, under `secrets`, by path: `{ sealed }` sets one to a sealed value,
 * `null` clears it, and one it does not name keeps its value. So the request
 * an approval stores, and the digests it is bound by, hold a ciphertext,
 * never the value (a value in an approval would sit in the clear until the
 * approval closes, and a digest over it could be guessed offline). The
 * handler checks that each sealed value opens for its member of this plugin
 * in this realm, and stores the ciphertext as it is. The body schema refuses
 * any installed plugin's secret member under `config`, however it is
 * spelled. A configure that keeps a stored secret while a member that holds
 * a URL is added or changes origin is refused: the secret must be sealed
 * again, so it never follows a destination it was not set for. No response,
 * audit row or log line holds a value: the representation says only which
 * secret members hold one.
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

/** A data-at-rest ciphertext, `v1.<kid>.<iv>.<ciphertext>`, as the signer writes one. */
const SEALED_PATTERN = /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * The longest sealed value: a secret of the longest length (8192 UTF-16
 * units, at most 24 KiB as UTF-8), encrypted and base64url-encoded, with room
 * for its key id and IV.
 */
const MAX_SEALED_LENGTH = 48 * 1024;

/** A secret member's path, as a request names it. */
const secretPathSchema = z.string().min(1).max(260);

/** A sealed value, as `plugins.secrets.seal` answered it. */
const sealedSchema = z.string().max(MAX_SEALED_LENGTH).regex(SEALED_PATTERN).meta({
  description: 'A secret value sealed for this member, as plugins.secrets.seal answered it.',
});

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

/**
 * The path parameters of a configure: a plugin this process loaded, so an
 * approval is never filed, with a body checked against no plugin's secret
 * members, for a plugin this node does not have (a rolling upgrade).
 */
function installedPluginParams(installed: readonly InstalledAuthMethodPlugin[]) {
  const names = new Set(installed.map((plugin) => plugin.id));
  return z.object({
    realmId: z.uuid(),
    plugin: pluginNameSchema.refine((name) => names.has(name), {
      message: 'names no plugin this server loaded',
    }),
  });
}

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
    // A member the plugin marks secret is never shown, even one an earlier
    // version of the plugin stored as plain.
    config: withoutConfigMembers(state.config, plugin.secretPaths),
    secrets: plugin.secretPaths.map((path) => ({ path, set: Object.hasOwn(state.secrets, path) })),
    version: state.version,
  };
}

/** The entity tag of a plugin's state in a realm. */
function entityTag(row: RealmAuthMethodPlugin | undefined): string {
  return `"${stateOf(row).version}"`;
}

/**
 * What the audit row records of a change: the representation, which holds
 * no secret value, and on the side after a configure, which secret members
 * the request set or cleared, so a rotation shows in the diff.
 */
function auditSide(
  resource: PluginResource,
  secretsChanged?: readonly string[]
): NonNullable<AdminChange['change']['after']> {
  return JSON.parse(
    JSON.stringify(
      secretsChanged === undefined ? resource : { ...resource, secretsChanged: [...secretsChanged] }
    )
  ) as NonNullable<AdminChange['change']['after']>;
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
      version: z.int().min(0).max(2_147_483_647).meta({
        description:
          "The version of the realm's state of the plugin this configure replaces, as its read gave it (`0` before it was first configured). The approval binds it; a state that moved since answers 412.",
      }),
      config: z
        .record(z.string().min(1).max(64), z.unknown())
        .refine((config) => Object.keys(config).length <= MAX_CONFIG_MEMBERS, {
          message: `config sets at most ${MAX_CONFIG_MEMBERS} members`,
        })
        .refine(
          (config) => Buffer.byteLength(JSON.stringify(config) ?? '', 'utf8') <= MAX_CONFIG_BYTES,
          { message: `config is at most ${MAX_CONFIG_BYTES} bytes as JSON` }
        )
        .refine((config) => !configSpellsMemberOf(config, secretPaths), {
          message:
            'config holds a secret member: seal it with plugins.secrets.seal and send it under secrets',
        })
        .meta({ description: "The plugin's plain config members: the whole config, replaced." }),
      secrets: z
        .record(secretPathSchema, z.strictObject({ sealed: sealedSchema }).nullable())
        .optional()
        .meta({
          description:
            'Secret members to set to a sealed value (`{ sealed }`) or clear (`null`), by path. One not named keeps its value.',
        }),
    })
    .meta({ description: "An AuthMethod plugin's configuration in the realm." });
}

/** The origin of an absolute http(s) URL, or `undefined`. */
function urlOriginOf(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  return url.protocol === 'https:' || url.protocol === 'http:' ? url.origin : undefined;
}

/** The origin of each http(s) URL among a plain config's members, by member path. */
function urlMemberOrigins(config: unknown): Map<string, string> {
  const origins = new Map<string, string>();
  const walk = (value: unknown, path: string, depth: number): void => {
    const origin = urlOriginOf(value);
    if (origin !== undefined) {
      origins.set(path, origin);
      return;
    }
    if (typeof value !== 'object' || value === null || depth > 32) return;
    for (const [key, item] of Object.entries(value)) {
      walk(item, Array.isArray(value) ? `${path}[${key}]` : `${path}.${key}`, depth + 1);
    }
  };
  walk(config, '', 0);
  return origins;
}

/**
 * The plain members of `after` that send somewhere `before` did not: each
 * member whose value is an http(s) URL and that is new, or whose origin is
 * not the one `before` holds at the same path (review of #939). A secret
 * kept across such a configure would go to the new destination, as
 * `UpstreamClientSecretDestinationChangedError` refuses for the upstream
 * OpenID Connect client (#938).
 */
export function newUrlDestinations(
  before: Readonly<Record<string, unknown>>,
  after: Readonly<Record<string, unknown>>
): string[] {
  const old = urlMemberOrigins(before);
  return [...urlMemberOrigins(after)]
    .filter(([path, origin]) => old.get(path) !== origin)
    .map(([path]) => path.slice(1));
}

/**
 * Refuse, with 400, a configure that keeps a stored secret (one it neither
 * sets nor clears) while it sends the plugin to a new destination: a member
 * whose value is an http(s) URL is added or changes origin. So an admin who
 * cannot read a write-only secret cannot send it elsewhere by changing, say,
 * `tokenEndpoint`. The error names the secrets to seal again; it echoes no
 * member value.
 */
function requireKeptSecretsStay(
  plugin: InstalledAuthMethodPlugin,
  row: RealmAuthMethodPlugin | undefined,
  config: Readonly<Record<string, unknown>>,
  changes: Readonly<Record<string, unknown>>
): void {
  const stored = stateOf(row).secrets;
  const kept = plugin.secretPaths.filter(
    (path) => Object.hasOwn(stored, path) && !Object.hasOwn(changes, path)
  );
  if (kept.length === 0) return;
  const before = withoutConfigMembers(stateOf(row).config, plugin.secretPaths);
  if (newUrlDestinations(before, config).length === 0) return;
  const names = kept.map((path) => JSON.stringify(path)).join(', ');
  throw new BadRequestError(
    `The configuration sends the plugin to a new destination (a member that holds a URL is new or names another origin), and the stored secret ${names} was set for the old one: seal ${kept.length === 1 ? 'it' : 'each'} again with plugins.secrets.seal and send ${kept.length === 1 ? 'it' : 'them'} under secrets`
  );
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

/**
 * The plaintext of each secret the row holds, but those in `skip`, opened as
 * `api` (`authMethodPluginSecretCipher`), for a schema check only: a request
 * that replaces or clears a secret needs no look at the value it replaces,
 * so a stored value that no longer opens never blocks the update that would
 * replace it.
 */
async function storedSecrets(
  fastify: FastifyInstance,
  plugin: InstalledAuthMethodPlugin,
  realmId: string,
  ciphertexts: Readonly<Record<string, string>>,
  skip: ReadonlySet<string> = new Set()
): Promise<Map<string, string>> {
  const cipher = authMethodPluginSecretCipher(fastify);
  const plaintexts = new Map<string, string>();
  for (const path of plugin.secretPaths) {
    if (!Object.hasOwn(ciphertexts, path) || skip.has(path)) continue;
    plaintexts.set(path, await cipher.open(realmId, plugin.id, path, ciphertexts[path]));
  }
  return plaintexts;
}

/** Signer error codes that say a ciphertext was not made for this slot of this realm. */
const NOT_SEALED_HERE: ReadonlySet<unknown> = new Set([
  'DATA_DECRYPTION_FAILED',
  'SIGNER_KEY_NOT_FOUND',
]);

/**
 * The plaintext of a sealed value, which must open for `path` of `plugin` in
 * the realm: one sealed for another member, plugin or realm, or changed, is
 * refused with 400. Any other failure (the signer unreachable) is thrown on,
 * and the request fails.
 */
async function openSealed(
  fastify: FastifyInstance,
  plugin: InstalledAuthMethodPlugin,
  realmId: string,
  path: string,
  sealed: string
): Promise<string> {
  try {
    return await authMethodPluginSecretCipher(fastify).open(realmId, plugin.id, path, sealed);
  } catch (error) {
    if (NOT_SEALED_HERE.has((error as { code?: unknown } | null)?.code)) {
      throw new BadRequestError(
        `The value for the secret member ${JSON.stringify(path)} was not sealed for it, for this plugin, in this realm`
      );
    }
    throw error;
  }
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
  const parsed = plugin.method.configSchema.safeParse(
    withConfigMembers(withoutConfigMembers(config, plugin.secretPaths), secrets)
  );
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
  after: RealmAuthMethodPlugin | undefined,
  secretsChanged?: readonly string[]
): PluginResource {
  const resource = pluginResource(plugin, after);
  if (before !== after) {
    recordAdminChange(request, {
      change: {
        before: before === undefined ? null : auditSide(pluginResource(plugin, before)),
        after: auditSide(resource, secretsChanged),
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
  const configParams = installedPluginParams(fastify.authMethodPlugins.installed);
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
    `${PLUGINS_PATH}/:plugin/secrets/seal`,
    {
      config: { operation: operations.seal.id },
      schema: {
        ...operationSchemaExtensions(operations.seal),
        ...common,
        summary: "Seal a value for one of an AuthMethod plugin's secret members in the realm",
        description:
          'Encrypts the value with the realm data_at_rest key, bound to this plugin and member, and answers the ciphertext. It changes nothing and records no value; a configure request sets the member to the sealed value.',
        'x-qauth-errors': [400, 401, 403, 404],
        params: pluginParams,
        body: z
          .strictObject({
            path: secretPathSchema.meta({ description: 'The secret member, by path.' }),
            value: z
              .string()
              .min(1)
              .max(MAX_AUTH_METHOD_SECRET_LENGTH)
              .meta({ description: 'Its value. Write-only: no response, row or log holds it.' }),
          })
          .meta({ description: 'A value to seal for a secret member.' }),
        response: {
          200: z
            .object({
              path: z.string(),
              sealed: z.string().meta({
                description:
                  'The value, encrypted for this member of this plugin in this realm: what a configure request sends under secrets.',
              }),
            })
            .meta({ description: 'A sealed secret value.' }),
        },
      },
    },
    async (request) => {
      const plugin = installedPlugin(fastify, request.params.plugin);
      const { path, value } = request.body;
      if (!plugin.secretPaths.includes(path)) {
        // The path is not echoed: a client that swapped the path and the value
        // would get the value back, and the log would keep it.
        throw new BadRequestError('path names no secret member of the plugin');
      }
      const sealed = await authMethodPluginSecretCipher(fastify).seal(
        requestAdminCaller(request).targetRealm.id,
        plugin.id,
        path,
        value
      );
      return { path, sealed };
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
        description:
          'Names the version of the state it replaces in its body (412 when the state moved). Secret members are named under secrets with values plugins.secrets.seal sealed, never in the clear.',
        'x-qauth-errors': [400, 401, 403, 404, 412],
        params: configParams,
        body: configBody,
        response: { 200: pluginSchema },
      },
    },
    async (request, reply) => {
      const plugin = installedPlugin(fastify, request.params.plugin);
      const realmId = requestAdminCaller(request).targetRealm.id;
      const row = await rowOf(request, plugin);
      // A configure replaces the whole config: it names, in the body the
      // approval binds, the version it replaces, so an approved change never
      // overwrites another unseen.
      if (request.body.version !== stateOf(row).version) {
        throw new PreconditionFailedError({ operation: operations.update.id });
      }
      requireCurrent(request, operations.update.id, row);
      const { config, secrets: changes = {} } = request.body;

      const named = Object.keys(changes);
      const unknown = named.filter((path) => !plugin.secretPaths.includes(path));
      if (unknown.length > 0) {
        // The name is not echoed: a client that swapped a path and its value
        // would get the value back, and the log would keep it.
        throw new BadRequestError('secrets names a member that is no secret member of the plugin');
      }
      if (configSpellsMemberOf(config, plugin.secretPaths)) {
        throw new BadRequestError(
          'config holds a secret member: seal it with plugins.secrets.seal and send it under secrets'
        );
      }
      // A kept secret never follows a changed destination.
      requireKeptSecretsStay(plugin, row, config, changes);

      // The secrets the realm will hold: those kept, and those set; a value
      // this request replaces or clears is never opened.
      const stored = stateOf(row).secrets;
      const plaintexts = await storedSecrets(fastify, plugin, realmId, stored, new Set(named));
      const ciphertexts: Record<string, string> = {};
      for (const path of plugin.secretPaths) {
        if (plaintexts.has(path)) ciphertexts[path] = stored[path];
      }
      for (const [path, change] of Object.entries(changes)) {
        if (change === null) continue;
        plaintexts.set(path, await openSealed(fastify, plugin, realmId, path, change.sealed));
        ciphertexts[path] = change.sealed;
      }
      requireValidConfig(plugin, config, plaintexts);

      const written = await writeState(request, operations.update.id, plugin, row, {
        enabled: stateOf(row).enabled,
        config,
        secrets: ciphertexts,
      });
      return answer(request, reply, plugin, row, written, named);
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
        // A member the plugin now marks secret leaves the plain config.
        config: withoutConfigMembers(state.config, plugin.secretPaths),
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
        // A member the plugin now marks secret leaves the plain config.
        config: withoutConfigMembers(row.config, plugin.secretPaths),
        secrets: row.secrets,
      });
      return answer(request, reply, plugin, row, written);
    }
  );
};
