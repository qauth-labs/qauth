/**
 * The types of the node list (#499), for the auth server's boot check and
 * readiness, which may not import the database library itself.
 */
export type {
  DeploymentNode,
  DeploymentNodeHeartbeat,
  DeploymentNodesRepository,
  NewDeploymentNode,
} from '@qauth-labs/infra-db';
