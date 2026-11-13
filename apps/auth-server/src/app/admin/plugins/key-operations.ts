import type {
  AdminOperationDefinition,
  RenderedField,
  RenderInput,
} from '../../helpers/admin-operations';

/**
 * THE CLIENT-ASSERTION KEY OPERATIONS OF A PROVIDER PLUGIN (ADR-019
 * Decisions 9 and 12, issue #1073): import a private key the provider issued
 * as the realm's `upstream_client_assertion` key for the plugin, and switch
 * the plugin's client assertions to the key waiting as `next`.
 *
 * A provider such as Sign in with Apple issues the key itself: the developer
 * downloads it with its key id, and the provider accepts a signed client
 * secret only under that key. QAuth generates every other key, so this is
 * the one way a provider's key comes in. The signer keeps it sealed under
 * the KEK like a generated key and signs with it for the plugin; the plugin
 * never holds it (ADR-019 Decision 12).
 *
 * Both are security operations: an import puts a key in custody that signs
 * the realm's client at the provider (`key-custody`, `credential-path`), and
 * a switch changes which key signs (`key-custody`). Each needs
 * `qauth:admin:security` (the permission `plugins.security`, which already
 * configures and enables the plugin) and an approval, and
 * `qauth:admin:write` reaches neither.
 *
 * An import takes the key only sealed, under `privateKey` (#984): a value
 * `secrets.seal` sealed for `plugins.keys.import`, the member `/privateKey`
 * and the plugin, so neither the request an approval binds nor the approval
 * record holds it in the clear. What the approver is shown and the call's
 * audit row name the plugin, the key id, its algorithm and its status, never
 * the key.
 *
 * The import's algorithm is the one the realm's configuration of the plugin
 * asks for (its provider config's signing algorithm, stored beside it at
 * the last configure or enable): a key of any other is refused, so the
 * plugin is configured before its key is imported. The first key of the
 * algorithm signs at once; a second waits as `next` and signs only after an
 * approved switch, and the old key signs until then. The switch waits for no
 * pre-publication window: the provider holds the key's public half from the
 * moment it issued it (see `createUpstreamClientKeys` of the signer plugin).
 */

/** The ids of the client-assertion key operations. */
export const PLUGIN_KEY_OPERATION_IDS = Object.freeze({
  import: 'plugins.keys.import',
  activate: 'plugins.keys.activate',
} as const);

/** The longest value an approver is shown, before the display caps it. */
const MAX_RENDERED_VALUE = 300;

/** The plugin a stored request's path names. */
function pluginOf(request: RenderInput): string {
  const { plugin } = (request.params ?? {}) as { plugin?: unknown };
  return typeof plugin === 'string' ? plugin : '(unknown)';
}

/** A value as an approver reads it: JSON, capped. */
function shownValue(value: unknown): string {
  const text = JSON.stringify(value) ?? 'null';
  return text.length > MAX_RENDERED_VALUE ? `${text.slice(0, MAX_RENDERED_VALUE)}…` : text;
}

/**
 * What an approver is shown of an import: the plugin and the key id; the key
 * itself only as a sealed value that is set, never its text.
 */
function renderImport(request: RenderInput) {
  const body = (request.body ?? {}) as { kid?: unknown };
  const fields: RenderedField[] = [
    { label: 'key id (kid)', value: shownValue(body.kid) },
    { label: 'private key', value: 'a sealed value (not shown)' },
  ];
  return {
    title: `Import a provider-issued client-assertion key for the sign-in plugin ${pluginOf(request)} in the realm`,
    fields,
  };
}

/** What an approver is shown of a switch: the plugin and the key that will sign. */
function renderActivate(request: RenderInput) {
  const body = (request.body ?? {}) as { kid?: unknown };
  return {
    title: `Switch the client assertions of the sign-in plugin ${pluginOf(request)} to its next key in the realm`,
    fields: [{ label: 'key id (kid) that signs from now on', value: shownValue(body.kid) }],
  };
}

/** The definitions, for `ADMIN_OPERATIONS` (`helpers/admin-operations.ts`). */
export const PLUGIN_KEY_OPERATION_DEFINITIONS: readonly AdminOperationDefinition[] = Object.freeze([
  {
    id: PLUGIN_KEY_OPERATION_IDS.import,
    class: 'security',
    effects: ['key-custody', 'credential-path'],
    permissions: ['plugins.security'],
    description:
      "Import a private key the provider issued, with the provider's key id, as the realm's client-assertion key for an AuthMethod plugin: checked against the algorithm the plugin's configuration asks for, sealed under the KEK and never returned; a second key waits as next until a switch.",
    render: renderImport,
    // The key, as `{ sealed }`.
    secretMembers: ['/privateKey'],
  },
  {
    id: PLUGIN_KEY_OPERATION_IDS.activate,
    class: 'security',
    effects: ['key-custody'],
    permissions: ['plugins.security'],
    description:
      "Switch an AuthMethod plugin's client assertions in a realm to its next key, at once, since the provider already holds the key; the key that signed until then is retired.",
    render: renderActivate,
  },
]);
