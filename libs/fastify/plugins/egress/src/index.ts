export * from './lib/fastify-plugin-egress';
// What the auth-server works with, from the egress library it may not import.
export {
  createTestEgressClient,
  EGRESS_SOURCES,
  type EgressClient,
  type EgressClientOptions,
  EgressError,
  type EgressErrorReason,
  type EgressRequest,
  type EgressResponse,
  type EgressSource,
  isEgressError,
} from '@qauth-labs/server-egress';
