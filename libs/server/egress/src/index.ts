// SSRF-safe egress client for every outbound call (ADR-019 Decisions 8 and 12)
export {
  type AddressKind,
  addressKind,
  isCloudMetadataAddress,
  isPublicUnicastAddress,
} from './lib/address';
export {
  type EgressAllowlist,
  type EgressAllowlistEntry,
  EgressAllowlistError,
  EMPTY_EGRESS_ALLOWLIST,
  loadEgressAllowlist,
  parseEgressAllowlist,
} from './lib/allowlist';
export {
  createEgressClient,
  createTestEgressClient,
  EGRESS_METHODS,
  type EgressClient,
  type EgressClientOptions,
  type EgressCounter,
  type EgressCounterLabels,
  type EgressCounts,
  type EgressDestinationOptions,
  type EgressLogger,
  type EgressMethod,
  type EgressRequest,
  type EgressResponse,
  type ValidatedDestination,
} from './lib/egress-client';
export {
  EgressError,
  type EgressErrorReason,
  type EgressOutcome,
  isEgressError,
} from './lib/errors';
export { DEFAULT_EGRESS_LIMITS, type EgressLimits } from './lib/limits';
export { type EgressPoolStats, egressPoolStats } from './lib/process-pool';
export { EGRESS_SOURCES, type EgressSource } from './lib/source';
