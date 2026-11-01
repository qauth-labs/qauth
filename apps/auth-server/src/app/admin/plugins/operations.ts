import type {
  AdminOperationDefinition,
  RenderedField,
  RenderInput,
} from '../../helpers/admin-operations';

/**
 * THE PLUGIN OPERATIONS OF THE ADMIN API (ADR-019 Decisions 7 and 12, issue
 * #600): list the AuthMethod plugins installed in the deployment with a
 * realm's state of each, read one, and enable, configure and disable one in
 * the realm.
 *
 * Enabling, configuring and disabling a plugin change which upstream
 * credentials can sign users in to the realm: each is a security operation
 * with the effect `credential-path`, so each needs `qauth:admin:security`
 * (the permission `plugins.security`) and an approval, and
 * `qauth:admin:write` reaches none of them. `plugins.enable` and
 * `plugins.update` are reserved as such in `admin-operations-reserved.ts`;
 * disabling is one by the same effect, as `upstreamProviders.disable` is.
 *
 * `plugins.secrets.seal` encrypts a secret member's value for the realm and
 * answers the ciphertext: it changes nothing, so it is a write with no
 * effect, under `plugins.write`. A configure request carries only sealed
 * values, so the request an approval stores never holds a secret in the
 * clear.
 *
 * No operation uploads, replaces or edits plugin code: the code is what the
 * operator installed with the deployment, and the operations set only data
 * the plugin's own config schema accepts.
 */

/** The ids of the plugin operations. */
export const PLUGIN_OPERATION_IDS = Object.freeze({
  list: 'plugins.list',
  get: 'plugins.get',
  seal: 'plugins.secrets.seal',
  update: 'plugins.update',
  enable: 'plugins.enable',
  disable: 'plugins.disable',
} as const);

/** The longest config value an approver is shown, before the display caps it. */
const MAX_RENDERED_VALUE = 500;

/** The plugin a stored request's path names. */
function pluginOf(request: RenderInput): string {
  const { plugin } = (request.params ?? {}) as { plugin?: unknown };
  return typeof plugin === 'string' ? plugin : '(unknown)';
}

/** A config value as an approver reads it: JSON, capped. */
function shownValue(value: unknown): string {
  const text = JSON.stringify(value) ?? 'null';
  return text.length > MAX_RENDERED_VALUE ? `${text.slice(0, MAX_RENDERED_VALUE)}…` : text;
}

/**
 * What an approver is shown of a configure request: each plain member it
 * sets, with its value, and each secret member it sets or clears, by name
 * only. Its body holds secrets apart from the plain config (the route
 * refuses a secret member under `config`), so no secret value is shown.
 */
function renderUpdate(request: RenderInput) {
  const body = (request.body ?? {}) as { version?: unknown; config?: unknown; secrets?: unknown };
  const fields: RenderedField[] = [
    { label: 'replaces the state of version', value: shownValue(body.version) },
  ];
  if (typeof body.config === 'object' && body.config !== null && !Array.isArray(body.config)) {
    for (const [member, value] of Object.entries(body.config)) {
      fields.push({ label: `config.${member}`, value: shownValue(value) });
    }
  }
  if (typeof body.secrets === 'object' && body.secrets !== null && !Array.isArray(body.secrets)) {
    for (const [path, value] of Object.entries(body.secrets)) {
      fields.push({
        label: `secret ${path}`,
        value: value === null ? 'cleared' : 'set to a new sealed value (not shown)',
      });
    }
  }
  return {
    title: `Replace the configuration of the sign-in plugin ${pluginOf(request)} in the realm`,
    fields,
  };
}

/** The definitions, for `ADMIN_OPERATIONS` (`helpers/admin-operations.ts`). */
export const PLUGIN_OPERATION_DEFINITIONS: readonly AdminOperationDefinition[] = Object.freeze([
  {
    id: PLUGIN_OPERATION_IDS.list,
    class: 'read',
    effects: [],
    permissions: ['plugins.read'],
    description:
      "List the AuthMethod plugins installed in the deployment, with the realm's state of each: on or off, its config, and which secret members hold a value.",
  },
  {
    id: PLUGIN_OPERATION_IDS.get,
    class: 'read',
    effects: [],
    permissions: ['plugins.read'],
    description:
      "Read one installed AuthMethod plugin with the realm's state of it; secret members show only whether they hold a value.",
  },
  {
    id: PLUGIN_OPERATION_IDS.seal,
    class: 'write',
    effects: [],
    permissions: ['plugins.write'],
    description:
      "Seal a value for one of an AuthMethod plugin's secret members in a realm: it changes nothing, and answers the value encrypted for that member, which plugins.update then sets.",
  },
  {
    id: PLUGIN_OPERATION_IDS.update,
    class: 'security',
    effects: ['credential-path'],
    permissions: ['plugins.security'],
    description:
      "Replace an AuthMethod plugin's configuration in a realm, set or clear its secret members, checked against the plugin's config schema; it never changes plugin code.",
    render: renderUpdate,
  },
  {
    id: PLUGIN_OPERATION_IDS.enable,
    class: 'security',
    effects: ['credential-path'],
    permissions: ['plugins.security'],
    description:
      "Enable an AuthMethod plugin in a realm, so its sign-in routes answer there; its configuration must pass the plugin's config schema.",
    render: (request: RenderInput) => ({
      title: `Enable the sign-in plugin ${pluginOf(request)} in the realm`,
    }),
  },
  {
    id: PLUGIN_OPERATION_IDS.disable,
    class: 'security',
    effects: ['credential-path'],
    permissions: ['plugins.security'],
    description:
      'Disable an AuthMethod plugin in a realm: its sign-in routes answer 404 there, and its configuration is kept.',
    render: (request: RenderInput) => ({
      title: `Disable the sign-in plugin ${pluginOf(request)} in the realm`,
    }),
  },
]);
