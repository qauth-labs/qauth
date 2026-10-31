/**
 * The versioned names of the Interaction API v1 contract (ADR-019 Decision 6,
 * ADR-018 §5, ADR-017 Decision 3).
 *
 * Until QAuth 1.0.0 every QAuth-defined version is a release candidate: the API
 * is served at `/interaction/v1-rc.<M>` and every step is named
 * `urn:qauth:ia:<name>:v1-rc.<M>`. A breaking change before 1.0.0 raises `<M>`
 * for the path and every step name together, so one label never names two
 * contracts. The release that ships 1.0.0 drops the suffix: `/interaction/v1`
 * and `urn:qauth:ia:<name>:v1`.
 */

/** The major version and its release-candidate number. */
export const INTERACTION_API_MAJOR = 1;
export const INTERACTION_API_RC = 0;

/**
 * `v1-rc.0`: the version label of the path, the step names and the published
 * files. Its type is the literal, so a step name's type can carry it (#591).
 */
export const INTERACTION_API_VERSION =
  `v${INTERACTION_API_MAJOR}-rc.${INTERACTION_API_RC}` as const;

/** The path prefix every operation of this version is served under. */
export const INTERACTION_API_PREFIX = `/interaction/${INTERACTION_API_VERSION}`;

/**
 * Reserved for the wallet return leg (ADR-013): the same-device redirect a
 * wallet follows after its presentation. No operation of this document sits
 * under it; the federation area defines the operations there.
 */
export const WALLET_RETURN_PREFIX = `${INTERACTION_API_PREFIX}/wallet/`;

/** The fixed path the auth server serves this document at. */
export const INTERACTION_OPENAPI_PATH = `${INTERACTION_API_PREFIX}/openapi.json`;

/** The flow cookie that binds an interaction to the browser that started it (#592). */
export const FLOW_COOKIE_NAME = '__Host-qauth_flow';

/** The `urn:qauth:ia:` namespace of step names. */
export const STEP_URN_PREFIX = 'urn:qauth:ia:';

/** A step's short name: lower-case ASCII, digits and `_`, starting with a letter. */
export const STEP_NAME_PATTERN = /^[a-z][a-z0-9_]{0,62}$/;

/** The step name `urn:qauth:ia:<name>:v1-rc.0` for a short name. */
export function stepUrn(name: string): string {
  if (!STEP_NAME_PATTERN.test(name)) throw new Error(`not a step name: ${name}`);
  return `${STEP_URN_PREFIX}${name}:${INTERACTION_API_VERSION}`;
}

/**
 * The pattern every step name of this version matches, as a JSON Schema
 * `pattern`: the namespace, a short name and this version's label.
 */
export const STEP_URN_SCHEMA_PATTERN = `^urn:qauth:ia:[a-z][a-z0-9_]{0,62}:${INTERACTION_API_VERSION.replace('.', '\\.')}$`;
