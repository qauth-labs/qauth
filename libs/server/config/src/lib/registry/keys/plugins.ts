import { defineKeys } from '../types';

/**
 * AuthMethod plugins (ADR-019 Decision 12, ADR-018 §4, issue #600): the keys
 * of `pluginsEnvSchema`.
 *
 * `AUTH_METHOD_PLUGINS` is `advanced`: the plugin runtime is new and its
 * surface may still change in a minor release. `PLUGIN_API_ENABLED` is
 * `experimental`: it is the switch of the experimental item `plugin-api`,
 * which warns at boot while it is on.
 */
export const PLUGIN_KEYS = defineKeys([
  {
    name: 'AUTH_METHOD_PLUGINS',
    tier: 'advanced',
    role: 'deployment',
    owner: 'plugins',
    default: '',
    since: '0.2.0',
    docs: 'The AuthMethod plugin packages to load at boot, by npm package name, comma-separated; the operator installs them with the deployment, and a package that is not a valid plugin stops the boot.',
  },
  {
    name: 'PLUGIN_API_ENABLED',
    tier: 'experimental',
    role: 'deployment',
    owner: 'plugins',
    default: 'false',
    since: '0.2.0',
    docs: "Turn on the experimental plugin API, so a plugin outside QAuth's first-party list loads; with it off, such a plugin is skipped and the boot says why.",
  },
]);
