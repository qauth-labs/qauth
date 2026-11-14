export * from './lib/fastify-plugin-signer';
export * from './lib/key-custody-check';
export * from './lib/realm-keys';
export * from './lib/repository-key-stores';
export * from './lib/scheduled-key-rotation';
export * from './lib/upstream-client-keys';
export type * from './types';
// The context prefix the auth server builds an AuthMethod plugin secret's
// context from (#600), so the app, which may not import server-keys, and the
// signer's policy name the same one.
export { AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX } from '@qauth-labs/server-keys';
// The same for a value sealed for an admin operation's secret member (#984).
export { ADMIN_SEALED_VALUE_CONTEXT_PREFIX } from '@qauth-labs/server-keys';
// The same for an OID4VP request state's ephemeral response key (#546), and
// the request-object typ the signer stamps, which the auth server pins equal to
// the federation library's.
export {
  OID4VP_RESPONSE_KEY_CONTEXT_PREFIX,
  OID4VP_REQUEST_OBJECT_TYP as SIGNER_REQUEST_OBJECT_TYP,
  TOTP_SECRET_CONTEXT_PREFIX,
} from '@qauth-labs/server-keys';
// The refusals of a provider's client-assertion key import and switch
// (#1073), which the admin API answers as 400 or 409: the app may not import
// server-keys.
export {
  KeyChangeRefusedError,
  KeyCreationRefusedError,
  KeyIdConflictError,
  NextKeyConflictError,
} from '@qauth-labs/server-keys';
// The scheduled key rotation's facts (#542), which the auth server's job and
// its settings use: the rotating purposes, the default windows the config
// registry's defaults are held to, the step a job writes an audit row for,
// and how long a data-at-rest ciphertext lives.
export {
  AUTOMATIC_ROTATION_PURPOSES,
  dataAtRestLifetimeMs,
  DEFAULT_KEY_PREPUBLISH_DAYS,
  DEFAULT_KEY_RETIRED_RETENTION_DAYS,
  DEFAULT_KEY_ROTATION_PERIOD_DAYS,
  KEY_ACTIVATION_DELAY_MS,
  type KeyPurpose,
  type KeyRotationDays,
  type KeyRotationStep,
  type KeysRotatedStep,
  type NextKeyCreatedStep,
  type ResolvedKeyRotationSettings,
  type RotatedKey,
} from '@qauth-labs/server-keys';
export type { KeyRotationFailure, KeyRotationReport } from '@qauth-labs/server-keys/custody';
// The manual rotation (#544): the approval it runs under, the canonical
// record that approval is bound to, and what it returns, for the admin API's
// route and the break-glass CLI, which may not import server-keys.
export {
  type ApprovedOperation,
  canonicalOperationBytes,
  isOperationNonce,
  isSecurityOperationActor,
  KEY_ROTATE_OPERATION,
  type KeyRotateOperation,
  keyRotationOperation,
  type KeyRotationOperationInput,
  type KeyRotationOperationRecord,
  newOperationNonce,
  OPERATION_NONCE_BYTES,
  OperationApprovalError,
  type OperationApprovalRefusal,
  operationDigest,
  type SecurityOperationActor,
} from '@qauth-labs/server-keys';
export type {
  KeyRotationNowRecord,
  RotatedNowKeys,
  RotateNowInput,
} from '@qauth-labs/server-keys/custody';
