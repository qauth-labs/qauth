import type {
  RealmAuthMethodPlugin,
  RealmAuthMethodPluginState,
} from '@qauth-labs/fastify-plugin-db';
import {
  AuthMethodConfigError,
  configSpellsMemberOf,
  type InstalledAuthMethodPlugin,
  parseAuthMethodConfig,
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
import {
  AUTH_METHOD_PLUGIN_STATE_MISMATCHES,
  authMethodPluginSecretCipher,
  authMethodPluginStateBinding,
  type AuthMethodPluginStateMismatch,
  authMethodPluginStateMismatch,
} from '../../helpers/auth-method-plugins';
import {
  ADMIN_SECURITY_SCHEME,
  type AdminChange,
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
} from '../pipeline';
import { openRequestSealedValue } from '../secrets/sealed-values';
import { memberPointer, SEALED_VALUE_SCHEMA } from '../secrets/secret-members';
import { PLUGIN_OPERATION_IDS } from './operations';

/**
 * THE PLUGIN ROUTES OF THE ADMIN API (ADR-019 Decisions 7, 10 and 12, issue
 * #600), under `/admin/v1-rc.0/realms/{realmId}/plugins`:
 *
 * - `GET  …/plugins` lists the installed plugins with the realm's state of
 *   each (`plugins.list`), one page at a time;
 * - `GET  …/plugins/{plugin}` reads one (`plugins.get`), with its `ETag`;
 * - `POST …/plugins/{plugin}/config` replaces its config and sets or clears
 *   its secret members (`plugins.update`), naming the version it replaces;
 * - `POST …/plugins/{plugin}/enable` and `…/disable` turn it on and off
 *   (`plugins.enable`, `plugins.disable`).
 *
 * `{plugin}` is the plugin's name, its AuthMethod id.
 *
 * The three writes are security operations: each runs only with an approval
 * filed for exactly that request. Each names the version of the state it
 * acts on in its body (`version`), so the approval binds it and the approver
 * sees it, and a write over a state that moved since is refused with 412:
 * two approved configures never overwrite each other unseen, and an approved
 * enable never runs against a config its approver never saw. Each may carry
 * `If-Match` too. Every write is conditional on the version it read in its
 * transaction.
 *
 * SECRETS. A plugin's config schema marks its secret members
 * (`writeOnly`). A secret's value reaches the server in one place only: the
 * body of `secrets.seal` (#984), which encrypts it with the realm's
 * `data_at_rest` key, under a context bound to `plugins.update` and the
 * member `/secrets/<path>`, and answers the ciphertext; it stores nothing and
 * records no value. A configure request then names each secret member apart
 * from the plain ones, under `secrets`, by path: `{ sealed }` sets one to a
 * sealed value, `null` clears it, and one it does not name keeps its value.
 * `plugins.update` declares `/secrets/*` its secret members, so the admin
 * listener boots its route only with the sealed-value schema there. So the
 * request an approval stores, and the digest it is bound by, hold a
 * ciphertext, never the value (a value in an approval would sit in the clear
 * until the approval closes, and a digest over it could be guessed offline).
 * The handler opens each sealed value for its own operation, that member and
 * this realm, and seals it again for the store under the plugin's own context
 * (bound to the plugin, its package and type, and the member): what the
 * approval bound is never what is stored. The body schema refuses any
 * installed plugin's secret member under `config`, however it is spelled. A configure that keeps a stored secret while a member that holds
 * a URL is added or changes origin is refused: the secret must be sealed
 * again, so it never follows a destination it was not set for. A plugin that
 * names where its secrets go (`secretDestination`, #1031) is held to that
 * too: a configure that keeps a stored secret while the plugin names
 * another destination for the new config than for the stored one is
 * refused. No response, audit row or log line holds a value: the
 * representation says only which secret members hold one.
 *
 * THE PLUGIN THAT WROTE THE STATE (#949). Every write records the package and
 * the type of the installed plugin it writes for, and a sealed value is bound
 * to both. A realm's state that another package wrote, or this package under
 * another type, is not this plugin's: it reads as off and as holding no
 * secret, `mismatch` says why, an enable is refused with 400, and its stored
 * secrets are never opened. A configure writes it again under the installed
 * plugin, off, with the secrets it seals again; an approved enable then turns
 * it on. A disable only turns the stored switch off and keeps the rest. A new
 * version of the same package, under the same type, keeps the state.
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

/** A secret member's path, as a request names it. */
const secretPathSchema = z.string().min(1).max(260);

/** The member of a configure's body a plugin secret's sealed value sits at: `/secrets/<path>`. */
export function pluginSecretMember(path: string): string {
  return memberPointer(['secrets', path]);
}

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
    enabled: z.boolean().meta({
      description:
        'The realm offers it. Always `false` while `mismatch` is set, whatever the stored state says.',
    }),
    config: z.record(z.string(), z.unknown()).meta({
      description:
        "The realm's config of the plugin: its plain members, never a secret one. While `mismatch` is set, the members the state another plugin wrote holds; a configure replaces them.",
    }),
    secrets: z.array(z.object({ path: z.string(), set: z.boolean() })).meta({
      description:
        "Each secret member of the plugin's config, by path, and whether it holds a value. Its value is never shown. While `mismatch` is set, none holds one: a secret sealed for another package or type never opens for this plugin.",
    }),
    configuredBy: z
      .object({
        package: z.string().meta({ description: 'The npm package of the plugin that wrote it.' }),
        type: z.string().meta({ description: 'The AuthMethod type it was written under.' }),
      })
      .nullable()
      .meta({
        description:
          "The plugin the realm's state was written for. `null` before it was first written, or for a state written before QAuth recorded it.",
      }),
    mismatch: z.enum(AUTH_METHOD_PLUGIN_STATE_MISMATCHES).nullable().meta({
      description:
        "Why the realm's state is not this plugin's, or `null` when it is: `package_unrecorded` (written before QAuth recorded which package wrote it), `package_changed` (another package wrote it under this name), `type_changed` (this package wrote it under another type). Such a state is off and holds none of this plugin's secrets until a configure writes it again for this plugin, sealing its secrets again, and an enable is approved.",
    }),
    version: z.int().min(0).meta({
      description:
        "The version of the realm's state of the plugin; `0` before it was first configured. Its ETag.",
    }),
  })
  .meta({ description: "An installed AuthMethod plugin and the realm's state of it." });

type PluginResource = z.infer<typeof pluginSchema>;

/** The version of the realm's state of a plugin: `0` before it was first written. */
function versionOf(row: RealmAuthMethodPlugin | undefined): number {
  return row?.version ?? 0;
}

/**
 * The realm's state of `plugin` as the admin API acts on it: that of a
 * plugin the realm never configured when it has no row, and, for a state
 * another package or type wrote (#949), off and holding no secret of the
 * plugin, with why.
 */
function stateOf(plugin: InstalledAuthMethodPlugin, row: RealmAuthMethodPlugin | undefined) {
  const mismatch = row === undefined ? null : authMethodPluginStateMismatch(plugin, row);
  return {
    mismatch,
    enabled: mismatch === null && row?.enabled === true,
    config: row?.config ?? {},
    secrets: mismatch === null ? (row?.secrets ?? {}) : {},
    version: versionOf(row),
  };
}

/** How the refusal of an enable names a mismatch (#949). */
const MISMATCH_TEXT: Readonly<Record<AuthMethodPluginStateMismatch, string>> = Object.freeze({
  package_unrecorded: 'before QAuth recorded which package wrote it',
  package_changed: 'by another package than the one installed under this name',
  type_changed: 'by this package under another type',
});

/** The representation of `plugin` in a realm whose row is `row`. */
export function pluginResource(
  plugin: InstalledAuthMethodPlugin,
  row: RealmAuthMethodPlugin | undefined
): PluginResource {
  const state = stateOf(plugin, row);
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
    configuredBy: row === undefined ? null : authMethodPluginStateBinding(row),
    mismatch: state.mismatch,
    version: state.version,
  };
}

/** The entity tag of a plugin's state in a realm. */
function entityTag(row: RealmAuthMethodPlugin | undefined): string {
  return `"${versionOf(row)}"`;
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

/** The version of the realm's state of a plugin that a write names: what the approval binds. */
function stateVersionSchema(what: string) {
  return z
    .int()
    .min(0)
    .max(2_147_483_647)
    .meta({
      description: `The version of the realm's state of the plugin ${what}, as its read gave it (\`0\` before it was first configured). The approval binds it; a state that moved since answers 412.`,
    });
}

/**
 * The body of `plugins.enable` or `plugins.disable` (#600): the version of
 * the state it acts on, so an approved enable never runs against a config
 * its approver never saw, nor a disable against a state that moved.
 */
export function pluginStateBodySchema(action: 'enable' | 'disable') {
  return z.strictObject({ version: stateVersionSchema(`this ${action} acts on`) }).meta({
    description: `The state of the plugin ${action === 'enable' ? 'an enable' : 'a disable'} acts on.`,
  });
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
      version: stateVersionSchema('this configure replaces'),
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
            'config holds a secret member: seal it with secrets.seal and send it under secrets',
        })
        .meta({ description: "The plugin's plain config members: the whole config, replaced." }),
      secrets: z.record(secretPathSchema, SEALED_VALUE_SCHEMA.nullable()).optional().meta({
        description:
          'Secret members to set to a sealed value (`{ sealed }`, from secrets.seal for plugins.update and the member `/secrets/<path>`) or clear (`null`), by path. One not named keeps its value.',
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
 * The stored secrets a configure keeps: those the realm's state of the
 * plugin holds that the request neither sets nor clears. A state another
 * package or type wrote holds none of this plugin's (#949).
 */
function keptSecretPaths(
  plugin: InstalledAuthMethodPlugin,
  row: RealmAuthMethodPlugin | undefined,
  changes: Readonly<Record<string, unknown>>
): string[] {
  const { secrets } = stateOf(plugin, row);
  return plugin.secretPaths.filter(
    (path) => Object.hasOwn(secrets, path) && !Object.hasOwn(changes, path)
  );
}

/**
 * The 400 of a configure that would carry the kept secrets to a new
 * destination, `why` saying how it is new. It names the secrets to seal
 * again; it echoes no member value.
 */
function keptSecretsMoved(kept: readonly string[], why: string): BadRequestError {
  const names = kept.map((path) => JSON.stringify(path)).join(', ');
  return new BadRequestError(
    `The configuration sends the plugin to a new destination (${why}), and the stored secret ${names} was set for the old one: seal ${kept.length === 1 ? 'it' : 'each'} again with secrets.seal and send ${kept.length === 1 ? 'it' : 'them'} under secrets`
  );
}

/**
 * Refuse, with 400, a configure that keeps a stored secret (one it neither
 * sets nor clears) while it sends the plugin to a new destination: a member
 * whose value is an http(s) URL is added or changes origin. So an admin who
 * cannot read a write-only secret cannot send it elsewhere by changing, say,
 * `tokenEndpoint`.
 *
 * Every plugin is held to it. This rule reads no member that is not a URL,
 * and no URL's path, so a plugin that names its own destination
 * (`secretDestination`, #1031) is held to that too, once its config parses
 * ({@link requireKeptSecretsAtDestination}): the hook adds a refusal, and
 * never lifts this one.
 */
export function requireKeptSecretsStay(
  plugin: InstalledAuthMethodPlugin,
  row: RealmAuthMethodPlugin | undefined,
  config: Readonly<Record<string, unknown>>,
  changes: Readonly<Record<string, unknown>>
): void {
  const kept = keptSecretPaths(plugin, row, changes);
  if (kept.length === 0) return;
  const before = withoutConfigMembers(stateOf(plugin, row).config, plugin.secretPaths);
  if (newUrlDestinations(before, config).length === 0) return;
  throw keptSecretsMoved(kept, 'a member that holds a URL is new or names another origin');
}

/**
 * Where the plugin says its secrets go under the plain members `config`
 * and the secret values `secrets` (`secretDestination`, #1031), or
 * `undefined` when that cannot be told: the plugin has no hook, the config
 * does not parse, or the hook throws or answers anything but a string. The
 * result is compared, never logged, stored or answered.
 */
function secretDestinationOf(
  plugin: InstalledAuthMethodPlugin,
  config: Readonly<Record<string, unknown>>,
  secrets: ReadonlyMap<string, string>
): string | undefined {
  if (plugin.method.secretDestination === undefined) return undefined;
  try {
    const parsed = parseAuthMethodConfig(
      plugin.method,
      withConfigMembers(withoutConfigMembers(config, plugin.secretPaths), secrets)
    );
    const destination: unknown = plugin.method.secretDestination(parsed);
    return typeof destination === 'string' ? destination : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Refuse, with 400, a configure that keeps a stored secret while the
 * plugin's own `secretDestination` (#1031) names another destination for the
 * new config than for the stored one: a member that shapes an issuer's path,
 * such as a tenant, or a token endpoint's path, moves the secret as surely
 * as another host does.
 *
 * Both sides are read with the same secret values, those the realm will hold
 * (a value the request replaces is never opened), so only the plain members
 * tell them apart. A side whose destination cannot be told (a stored config
 * the plugin's schema no longer takes, a hook that throws) counts as a new
 * destination: the secret is sealed again, never kept on a guess.
 */
export function requireKeptSecretsAtDestination(
  plugin: InstalledAuthMethodPlugin,
  row: RealmAuthMethodPlugin | undefined,
  config: Readonly<Record<string, unknown>>,
  changes: Readonly<Record<string, unknown>>,
  secrets: ReadonlyMap<string, string>
): void {
  if (plugin.method.secretDestination === undefined) return;
  const kept = keptSecretPaths(plugin, row, changes);
  if (kept.length === 0) return;
  const before = secretDestinationOf(plugin, stateOf(plugin, row).config, secrets);
  const after = secretDestinationOf(plugin, config, secrets);
  if (before !== undefined && before === after) return;
  throw keptSecretsMoved(kept, 'the plugin names another destination for its secrets');
}

/**
 * What a value sealed for a configure is bound to beside the plugin the path
 * names (#984): the npm package and the type of the plugin installed under
 * that name, as its stored secrets are (#949). A value sealed while one
 * package is installed never opens once another is, so the secret is never
 * handed to code it was not set for; `undefined` for a name no plugin is
 * installed under.
 */
export function pluginSealScope(
  plugins: {
    find(name: string): Pick<InstalledAuthMethodPlugin, 'package' | 'type'> | undefined;
  },
  params: Readonly<Record<string, unknown>>
): string | undefined {
  const plugin = typeof params['plugin'] === 'string' ? plugins.find(params['plugin']) : undefined;
  return plugin === undefined ? undefined : JSON.stringify([plugin.package, plugin.type]);
}

/** The installed plugin of the path, or 404. */
function installedPlugin(fastify: FastifyInstance, name: string): InstalledAuthMethodPlugin {
  const plugin = fastify.authMethodPlugins.find(name);
  if (plugin === undefined) throw new NotFoundError('Plugin', name);
  return plugin;
}

/**
 * Refuse, with 412, a write whose body names another version of the state
 * than `row`'s: the body is what the approval binds, so an approved write
 * runs only over the state its approver saw.
 */
function requireNamedVersion(
  version: number,
  operationId: string,
  row: RealmAuthMethodPlugin | undefined
): void {
  if (version !== versionOf(row)) throw new PreconditionFailedError({ operation: operationId });
}

/** Refuse a write named against another version of the state than `row`'s. */
function requireCurrent(
  request: FastifyRequest,
  operationId: string,
  row: RealmAuthMethodPlugin | undefined
): void {
  if (!ifMatchAllows(request.headers['if-match'], String(versionOf(row)))) {
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
    plaintexts.set(path, await cipher.open(realmId, plugin, path, ciphertexts[path]));
  }
  return plaintexts;
}

/**
 * The plaintext of the sealed value a configure sets `path` to, opened for
 * `plugins.update`, the member `/secrets/<path>`, the plugin of the path and
 * its installed package and type, and the request's realm (#984): one sealed
 * for another operation, member, plugin, package, type or realm, or changed,
 * is refused with 400. Any other failure (the signer unreachable) is thrown
 * on, and the request fails.
 */
function openSealed(request: FastifyRequest, path: string, sealed: string): Promise<string> {
  return openRequestSealedValue(
    request,
    pluginSecretMember(path),
    sealed,
    `the secret member ${JSON.stringify(path)}`
  );
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
  // The context's own check (#639, from the review of #939): the schema, and
  // a parsed form of plain data, which the context copies and freezes. A
  // config it would refuse is refused here, before the state is written, so
  // a configure never makes every sign-in through the plugin fail.
  try {
    parseAuthMethodConfig(
      plugin.method,
      withConfigMembers(withoutConfigMembers(config, plugin.secretPaths), secrets)
    );
  } catch (error) {
    if (!(error instanceof AuthMethodConfigError)) throw error;
    const members = error.issues.slice(0, 16);
    throw new BadRequestError(
      `The configuration does not pass the plugin's config schema (${members.join('; ')})`
    );
  }
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

/**
 * Write a new state over `row`, conditional on its version; 412 when it
 * moved. `state.binding` names the plugin it is written for (#949): the
 * installed plugin's package and type, or the row's own for a write that
 * keeps them.
 */
async function writeState(
  request: FastifyRequest,
  operationId: string,
  plugin: InstalledAuthMethodPlugin,
  row: RealmAuthMethodPlugin | undefined,
  state: RealmAuthMethodPluginState
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
    // A DPoP-bound admin token (#520).
    security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
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
      config: {
        operation: operations.update.id,
        sealScope: (params) => pluginSealScope(fastify.authMethodPlugins, params),
      },
      schema: {
        ...operationSchemaExtensions(operations.update),
        ...common,
        summary: "Replace an AuthMethod plugin's configuration in the realm",
        description:
          'Names the version of the state it replaces in its body (412 when the state moved). Secret members are named under secrets with values secrets.seal sealed for plugins.update, the member /secrets/<path> (the path escaped as a JSON Pointer token) and the params { plugin }, never in the clear.',
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
      requireNamedVersion(request.body.version, operations.update.id, row);
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
          'config holds a secret member: seal it with secrets.seal and send it under secrets'
        );
      }
      // A kept secret never follows a changed destination: here by the URL
      // rule, for every plugin, and below, once the config parses, by the
      // plugin's own secretDestination too when it has one (#1031).
      requireKeptSecretsStay(plugin, row, config, changes);

      // The secrets the realm will hold: those kept, and those set; a value
      // this request replaces or clears is never opened. A state another
      // package or type wrote keeps none (#949): its secrets were sealed for
      // that plugin, and are never opened for this one.
      const state = stateOf(plugin, row);
      const stored = state.secrets;
      const plaintexts = await storedSecrets(fastify, plugin, realmId, stored, new Set(named));
      const ciphertexts: Record<string, string> = {};
      for (const path of plugin.secretPaths) {
        if (plaintexts.has(path)) ciphertexts[path] = stored[path];
      }
      const opened = new Map<string, string>();
      for (const [path, change] of Object.entries(changes)) {
        if (change === null) continue;
        opened.set(path, await openSealed(request, path, change.sealed));
      }
      for (const [path, plaintext] of opened) plaintexts.set(path, plaintext);
      requireValidConfig(plugin, config, plaintexts);
      requireKeptSecretsAtDestination(plugin, row, config, changes, plaintexts);
      // Each secret set is stored sealed again, under the plugin's own
      // context: the value sealed for the approval never opens as a stored
      // secret, nor a stored secret as a sealed value.
      const cipher = authMethodPluginSecretCipher(fastify);
      for (const [path, plaintext] of opened) {
        ciphertexts[path] = await cipher.seal(realmId, plugin, path, plaintext);
      }

      const written = await writeState(request, operations.update.id, plugin, row, {
        // A state another package or type wrote stays off until an approved
        // enable turns it on for this plugin (#949).
        enabled: state.enabled,
        config,
        secrets: ciphertexts,
        binding: { package: plugin.package, type: plugin.type },
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
        description:
          'Names the version of the state it enables in its body (412 when the state moved), so an approved enable never runs against a config its approver never saw.',
        'x-qauth-errors': [400, 401, 403, 404, 412],
        params: pluginParams,
        body: pluginStateBodySchema('enable'),
        response: { 200: pluginSchema },
      },
    },
    async (request, reply) => {
      const plugin = installedPlugin(fastify, request.params.plugin);
      const realmId = requestAdminCaller(request).targetRealm.id;
      const row = await rowOf(request, plugin);
      requireNamedVersion(request.body.version, operations.enable.id, row);
      requireCurrent(request, operations.enable.id, row);
      const state = stateOf(plugin, row);
      // A state another package or type wrote is never turned on for this
      // plugin: a configure writes it again for this one first (#949).
      if (state.mismatch !== null) {
        throw new BadRequestError(
          `The realm's state of the plugin was written ${MISMATCH_TEXT[state.mismatch]} (${state.mismatch}): configure it again for the installed plugin, sealing its secrets again, before enabling it`
        );
      }
      if (state.enabled) return answer(request, reply, plugin, row, row);
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
        binding: { package: plugin.package, type: plugin.type },
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
        description:
          'Names the version of the state it disables in its body (412 when the state moved).',
        'x-qauth-errors': [400, 401, 403, 404, 412],
        params: pluginParams,
        body: pluginStateBodySchema('disable'),
        response: { 200: pluginSchema },
      },
    },
    async (request, reply) => {
      const plugin = installedPlugin(fastify, request.params.plugin);
      const row = await rowOf(request, plugin);
      requireNamedVersion(request.body.version, operations.disable.id, row);
      requireCurrent(request, operations.disable.id, row);
      // The stored switch, which a state another package or type wrote may
      // hold on: disabling it turns it off, so the state stays off should
      // that plugin return (#949).
      if (row === undefined || !row.enabled) return answer(request, reply, plugin, row, row);
      const own = authMethodPluginStateMismatch(plugin, row) === null;
      const written = await writeState(request, operations.disable.id, plugin, row, {
        enabled: false,
        // A member the plugin now marks secret leaves the plain config; the
        // config of a state another plugin wrote is kept as it is.
        config: own ? withoutConfigMembers(row.config, plugin.secretPaths) : row.config,
        secrets: row.secrets,
        binding: authMethodPluginStateBinding(row),
      });
      return answer(request, reply, plugin, row, written);
    }
  );
};
