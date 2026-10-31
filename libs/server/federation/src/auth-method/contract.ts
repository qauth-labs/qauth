import {
  DISPLAY_TEXT_PATTERN,
  INTERACTION_API_VERSION,
  STEP_URN_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import type { ExperimentalItemId } from '@qauth-labs/shared-stability';

import { PASSWORD_PROVIDER_TYPE, SELF_REPORTED_SOURCE } from '../providers/password.provider';
import { WALLET_PROVIDER_TYPE } from '../providers/wallet.provider';
import { WEBAUTHN_PROVIDER_TYPE } from '../providers/webauthn.provider';

/**
 * The fixed values of the AuthMethod contract (#599, ADR-003 as amended,
 * ADR-018 §4, ADR-019 Decision 12).
 *
 * EXPERIMENTAL. The AuthMethod contract is the plugin API of ADR-018 §4: it is
 * public and documented, so others can write methods against it, but it stays
 * outside the 1.0 stability promise and may change in a minor release. It
 * becomes stable in 1.x. The experimental-feature registry lists it as
 * `plugin-api`.
 *
 * @packageDocumentation
 */

/**
 * The contract's name, as it appears in {@link AUTH_METHOD_CONTRACT}.
 *
 * @experimental
 */
export const AUTH_METHOD_CONTRACT_NAME = 'qauth-auth-method';

/**
 * The contract's version: a release candidate until QAuth 1.0.0
 * (ADR-018 §5). A breaking change raises the release-candidate number, so one
 * identifier never names two contracts.
 *
 * @experimental
 */
export const AUTH_METHOD_CONTRACT_VERSION = '1-rc.0';

/**
 * The contract a method declares it is written against, as a format id:
 * `qauth-auth-method/1-rc.0`. The registry refuses a method that declares
 * another one, so a method built for another version fails the boot instead of
 * running against a contract it does not know.
 *
 * @experimental
 */
export const AUTH_METHOD_CONTRACT =
  `${AUTH_METHOD_CONTRACT_NAME}/${AUTH_METHOD_CONTRACT_VERSION}` as const;

/**
 * Where the contract stands: experimental, under the experimental-feature
 * registry's item `plugin-api` (ADR-018 §4 and §5). The item id is typed
 * against the registry, so renaming the item there fails the typecheck here.
 *
 * @experimental
 */
export const AUTH_METHOD_STABILITY = Object.freeze({
  stability: 'experimental',
  experimentalItem: 'plugin-api' satisfies ExperimentalItemId,
} as const);

/**
 * The upstream step: the Interaction API step through which a person signs in
 * at an upstream identity provider. The method starts an upstream transaction
 * ({@link AuthMethod.start}), the browser goes to the provider, and the
 * method's callback route hands the provider's answer back to the engine.
 *
 * Step names are QAuth identifiers that carry the Interaction API's version
 * (ADR-018 §5): `urn:qauth:ia:upstream:v1-rc.0` until 1.0.0. The step's params
 * and its place in ADR-017's step table come with the upstream sign-in flow
 * (#639).
 *
 * @experimental
 */
export const UPSTREAM_STEP_URN = `${STEP_URN_PREFIX}upstream:${INTERACTION_API_VERSION}` as const;

if (UPSTREAM_STEP_URN !== stepUrn('upstream')) {
  // The template above keeps the literal type; this keeps it equal to the
  // contract's own spelling of a step name.
  throw new Error('UPSTREAM_STEP_URN does not match the Interaction API step name rule');
}

/**
 * Every step a method may contribute in this version of the contract, by URN.
 * Only the upstream step today; a later version may add others (an LDAP form,
 * for instance).
 *
 * @experimental
 */
export const AUTH_METHOD_STEP_URNS = Object.freeze([UPSTREAM_STEP_URN] as const);

/**
 * A step a method may contribute: one of {@link AUTH_METHOD_STEP_URNS}.
 *
 * @experimental
 */
export type AuthMethodStepUrn = (typeof AUTH_METHOD_STEP_URNS)[number];

/**
 * The root every method's routes are mounted under, on the realm host. A
 * method's own prefix is `/upstream/<type>` ({@link authMethodRoutePrefix}),
 * so each provider has its own callback URL, and a response meant for one
 * provider cannot be replayed at another.
 *
 * No version in the path: the callback URL is registered at the upstream
 * provider, and a path that changed at 1.0 would break every registration.
 *
 * @experimental
 */
export const AUTH_METHOD_ROUTE_ROOT = '/upstream';

/**
 * The prefix a method's routes are mounted under: `/upstream/<type>`.
 *
 * @experimental
 */
export function authMethodRoutePrefix(type: string): string {
  if (!AUTH_METHOD_TYPE_PATTERN.test(type)) {
    throw new TypeError('not an AuthMethod type');
  }
  return `${AUTH_METHOD_ROUTE_ROOT}/${type}`;
}

/**
 * An AuthMethod's `type`: lower-case ASCII letters, digits and `_`, starting
 * with a letter, at most 63 characters. It is the registry key, the value
 * written to `user_credentials.provider_type`, the `source` of the attributes
 * the method extracts and a segment of its route prefix, so it must be safe in
 * all four. A type with `:` or `/` (an ID-JAG issuer type, `oidc_<issuer URL>`)
 * can never match.
 *
 * @experimental
 */
export const AUTH_METHOD_TYPE_PATTERN = /^[a-z][a-z0-9_]{0,62}$/;

/**
 * An AuthMethod's `id`: the stable name of the method's implementation, such
 * as `oidc` or `corp-sso`. Lower-case ASCII letters, digits, `_` and `-`,
 * starting with a letter, at most 63 characters.
 *
 * @experimental
 */
export const AUTH_METHOD_ID_PATTERN = /^[a-z][a-z0-9_-]{0,62}$/;

/**
 * Types an AuthMethod may not take: the credential types and the attribute
 * source QAuth writes itself, built or planned. A method under one of them
 * would read as that built-in credential, and `wallet` would outrank every
 * other attribute source in claim resolution (`rankAttributeSource`).
 *
 * @experimental
 */
export const RESERVED_AUTH_METHOD_TYPES: readonly string[] = Object.freeze([
  PASSWORD_PROVIDER_TYPE,
  WALLET_PROVIDER_TYPE,
  WEBAUTHN_PROVIDER_TYPE,
  SELF_REPORTED_SOURCE,
  'totp',
  'recovery_code',
  'email_code',
]);

/**
 * A route path below a method's prefix: one to four segments of lower-case
 * ASCII letters, digits, `_` and `-`, such as `/callback`. No dot segment, no
 * encoded character, no route parameter and no wildcard can match, so a path
 * cannot leave the prefix it is mounted under.
 *
 * @experimental
 */
export const AUTH_METHOD_ROUTE_PATH_PATTERN = /^(?:\/[a-z0-9][a-z0-9_-]{0,62}){1,4}$/;

/**
 * The display rule of the Interaction API (ADR-019 Decision 6), which a
 * method's default name follows: no markup bracket, no control, format,
 * private-use or unassigned character, no line separator and no space at
 * either end.
 *
 * @experimental
 */
export const AUTH_METHOD_DISPLAY_NAME_PATTERN = new RegExp(DISPLAY_TEXT_PATTERN, 'u');

/**
 * The longest default display name, in UTF-16 code units.
 *
 * @experimental
 */
export const MAX_AUTH_METHOD_DISPLAY_NAME_LENGTH = 64;

/**
 * The largest default icon, in bytes.
 *
 * @experimental
 */
export const MAX_AUTH_METHOD_ICON_BYTES = 16 * 1024;

/**
 * The media types a default icon may have: raster PNG only. An SVG can carry
 * script, and the icon is served from the realm origin.
 *
 * @experimental
 */
export const AUTH_METHOD_ICON_MEDIA_TYPES = Object.freeze(['image/png'] as const);

/**
 * The largest upstream transaction a method may ask the engine to keep, in
 * bytes of its JSON form. The engine stores it server-side, bound to the
 * interaction and its flow cookie, for the lifetime of the interaction.
 *
 * @experimental
 */
export const MAX_UPSTREAM_TRANSACTION_BYTES = 4096;

/**
 * The longest URL a method may send the browser to when it starts.
 *
 * @experimental
 */
export const MAX_UPSTREAM_REDIRECT_LENGTH = 8192;

/**
 * The longest `externalSub` a method may resolve: 255 characters, the limit
 * OpenID Connect Core 1.0 §2 sets on `sub`.
 *
 * @experimental
 */
export const MAX_AUTH_METHOD_EXTERNAL_SUB_LENGTH = 255;

/**
 * The largest `rawClaims` a method's `verify()` may resolve, in bytes of its
 * JSON form. The engine keeps a frozen copy.
 *
 * @experimental
 */
export const MAX_AUTH_METHOD_RAW_CLAIMS_BYTES = 64 * 1024;

/**
 * An attribute key a method may extract: lower-case ASCII letters, digits
 * and `_`, starting with a letter, at most 64 characters (`email`,
 * `given_name`).
 *
 * @experimental
 */
export const AUTH_METHOD_ATTRIBUTE_KEY_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * The longest attribute value a method may extract, in UTF-16 code units.
 *
 * @experimental
 */
export const MAX_AUTH_METHOD_ATTRIBUTE_VALUE_LENGTH = 8192;

/**
 * Why a method's callback did not produce a result, other than the person
 * declining at the provider:
 *
 * - `transaction_mismatch`: no transaction is pending for this browser, or the
 *   callback does not belong to it (`state` differs). A callback replayed in
 *   another browser, or forged, ends here.
 * - `provider_error`: the provider answered with an error, other than the
 *   person declining (`access_denied`).
 * - `invalid_response`: the provider's answer failed a check, such as the ID
 *   token's signature, `iss`, `aud` or `nonce`.
 * - `upstream_unavailable`: the provider could not be reached in time.
 *
 * @experimental
 */
export const UPSTREAM_FAILURE_REASONS = Object.freeze([
  'transaction_mismatch',
  'provider_error',
  'invalid_response',
  'upstream_unavailable',
] as const);

/**
 * One of {@link UPSTREAM_FAILURE_REASONS}.
 *
 * @experimental
 */
export type UpstreamFailureReason = (typeof UPSTREAM_FAILURE_REASONS)[number];
