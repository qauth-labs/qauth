import { defineKeys } from '../types';

/**
 * The node list and its configuration digest (ADR-019 Decision 8, issue
 * #499): the keys of `deploymentNodesEnvSchema`.
 */
export const DEPLOYMENT_NODE_KEYS = defineKeys([
  {
    name: 'CONFIG_DIGEST_ROLLOUT',
    tier: 'advanced',
    role: 'deployment',
    digest: 'node',
    owner: 'server',
    default: 'false',
    since: '0.3.0',
    docs: "Let this node boot, with a warning in place of the refusal, when its configuration digest differs from a running node's of the same release, for the window of a planned change of a setting every node shares; turn it off once every node runs the new value.",
  },
]);
