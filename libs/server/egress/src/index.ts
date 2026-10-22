// SSRF-safe egress client for every outbound call (ADR-019 Decisions 8 and 12)
export { type AddressKind, addressKind, isPublicUnicastAddress } from './lib/address';
export {
  createEgressClient,
  EGRESS_METHODS,
  type EgressClient,
  type EgressClientOptions,
  type EgressCounter,
  type EgressCounterLabels,
  type EgressCounts,
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
