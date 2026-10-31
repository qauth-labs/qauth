import type {
  AssuranceLevel,
  UserAttribute,
  VerifiedIdentity,
} from '../providers/credential-provider.interface';
import type {
  AuthMethod,
  AuthMethodContext,
  UpstreamStart,
  UpstreamStartRequest,
} from './auth-method.interface';
import {
  AUTH_METHOD_ATTRIBUTE_KEY_PATTERN,
  MAX_AUTH_METHOD_ATTRIBUTE_VALUE_LENGTH,
  MAX_AUTH_METHOD_EXTERNAL_SUB_LENGTH,
  MAX_AUTH_METHOD_RAW_CLAIMS_BYTES,
  MAX_UPSTREAM_REDIRECT_LENGTH,
  MAX_UPSTREAM_TRANSACTION_BYTES,
  UPSTREAM_FAILURE_REASONS,
  type UpstreamFailureReason,
} from './contract';
import { AuthMethodFaultError } from './errors';

/**
 * The engine's half of the upstream step (#599): what it checks around the
 * two calls it makes into a method. The engine never acts on an answer that
 * fails a check; it throws {@link AuthMethodFaultError}, which the sign-in
 * flow answers with the generic error page and its trace id.
 *
 * Pure: the transaction store, the flow cookie and the account decisions
 * belong to the sign-in flow that calls these (#639).
 *
 * @experimental
 */

const ASSURANCE_LEVELS: readonly AssuranceLevel[] = ['low', 'substantial', 'high'];

/**
 * A control character an attribute value may not hold: NUL (which Postgres
 * `text` refuses) and the other C0 controls and DEL, but tab, line feed and
 * carriage return, which a postal address may hold.
 */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const VALUE_CONTROL_CHARACTER = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

/** A C0 or C1 control character, or DEL. */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * Why the upstream step ended without an identity: a callback's reason, or
 * `verification_refused` when `verify()` rejected the callback's result.
 *
 * @experimental
 */
export type UpstreamStepFailureReason = UpstreamFailureReason | 'verification_refused';

/**
 * How the upstream step ended, as the sign-in flow acts on it:
 *
 * - `identity`: a checked `VerifiedIdentity` and its attributes, each with
 *   `source` equal to the method's `type`. The flow looks the credential up by
 *   `(realm, type, externalSub)`; it never matches an account by an attribute.
 * - `declined`: the person cancelled or declined at the provider.
 * - `failed`: anything else. `cause` is `verify()`'s rejection, for the log.
 *
 * @experimental
 */
export type UpstreamStepCompletion =
  | {
      readonly kind: 'identity';
      readonly identity: VerifiedIdentity;
      readonly attributes: readonly UserAttribute[];
    }
  | { readonly kind: 'declined' }
  | {
      readonly kind: 'failed';
      readonly reason: UpstreamStepFailureReason;
      readonly cause?: unknown;
    };

/**
 * Start an upstream transaction: call `method.start()` and check its answer.
 * The redirect must be an absolute `https` URL with no credentials and no
 * fragment, and the transaction JSON data within its cap. The returned
 * transaction is a frozen copy, what the engine stores.
 *
 * A rejection of `start()` (the provider's discovery document cannot be read,
 * for instance) propagates unchanged.
 *
 * @throws AuthMethodFaultError when the answer fails a check
 * @experimental
 */
export async function startUpstreamStep<TConfig, TTransaction>(
  method: AuthMethod<TConfig, TTransaction>,
  context: AuthMethodContext<TConfig>,
  request: UpstreamStartRequest
): Promise<UpstreamStart<TTransaction>> {
  const answer: unknown = await method.start(context, request);
  if (typeof answer !== 'object' || answer === null) {
    throw new AuthMethodFaultError(method.type, 'start() did not answer an object');
  }
  const { redirectTo, transaction } = answer as Record<string, unknown>;
  const redirectProblem = upstreamRedirectProblem(redirectTo);
  if (redirectProblem !== undefined) {
    throw new AuthMethodFaultError(method.type, `start() answered ${redirectProblem}`);
  }
  const stored = storableTransaction(transaction);
  if (stored === undefined) {
    throw new AuthMethodFaultError(
      method.type,
      `start() answered a transaction that is not JSON data of at most ${MAX_UPSTREAM_TRANSACTION_BYTES} bytes`
    );
  }
  return Object.freeze({
    // The URL as parsed, so what the engine sends is what it checked.
    redirectTo: new URL(redirectTo as string).href,
    transaction: stored as TTransaction,
  });
}

/**
 * Turn what a method's callback handed back into the end of the upstream
 * step. A `result` goes to `method.verify()`; the identity it resolves is
 * checked, then `method.extractAttributes()` gives its attributes, which are
 * checked too.
 *
 * @param outcome - what the callback route's handler returned, unchecked
 * @throws AuthMethodFaultError when the outcome is outside the closed set, or
 *   the identity or an attribute fails a check
 * @experimental
 */
export async function completeUpstreamStep(
  method: AuthMethod,
  outcome: unknown
): Promise<UpstreamStepCompletion> {
  if (typeof outcome !== 'object' || outcome === null) {
    throw new AuthMethodFaultError(method.type, 'the callback did not answer an outcome');
  }
  const { kind } = outcome as Record<string, unknown>;
  if (kind === 'declined') return Object.freeze({ kind: 'declined' });
  if (kind === 'failed') {
    const { reason } = outcome as Record<string, unknown>;
    if (!(UPSTREAM_FAILURE_REASONS as readonly unknown[]).includes(reason)) {
      throw new AuthMethodFaultError(
        method.type,
        `the callback failed with a reason outside ${UPSTREAM_FAILURE_REASONS.join(', ')}`
      );
    }
    return Object.freeze({ kind: 'failed', reason: reason as UpstreamFailureReason });
  }
  if (kind !== 'result' || !('result' in outcome)) {
    throw new AuthMethodFaultError(
      method.type,
      'the callback answered an outcome outside result, declined and failed'
    );
  }

  let identity: unknown;
  try {
    identity = await method.verify((outcome as { result: unknown }).result);
  } catch (cause) {
    return Object.freeze({ kind: 'failed', reason: 'verification_refused', cause } as const);
  }
  const checked = checkedIdentity(method.type, identity);

  let attributes: unknown;
  try {
    attributes = method.extractAttributes(checked);
  } catch (cause) {
    throw new AuthMethodFaultError(method.type, 'extractAttributes() threw', { cause });
  }
  return Object.freeze({
    kind: 'identity',
    identity: checked,
    attributes: checkedAttributes(method.type, attributes),
  });
}

/**
 * Why `value` cannot be where an upstream step sends the browser, or
 * `undefined` when it can.
 *
 * @experimental
 */
export function upstreamRedirectProblem(value: unknown): string | undefined {
  if (typeof value !== 'string') return 'a redirect that is not a string';
  if (value.length > MAX_UPSTREAM_REDIRECT_LENGTH) {
    return `a redirect longer than ${MAX_UPSTREAM_REDIRECT_LENGTH} characters`;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'a redirect that is not an absolute URL';
  }
  if (url.protocol !== 'https:') return 'a redirect that is not https';
  if (url.username !== '' || url.password !== '') return 'a redirect with credentials';
  if (value.includes('#')) return 'a redirect with a fragment';
  return undefined;
}

/**
 * A frozen copy of `value` when it is JSON data within the transaction cap:
 * plain objects, arrays, strings, finite numbers, booleans and `null`, nested
 * at most 16 deep. `undefined` otherwise.
 *
 * @experimental
 */
export function storableTransaction(value: unknown): unknown {
  return frozenJsonCopy(value, MAX_UPSTREAM_TRANSACTION_BYTES);
}

/** A frozen copy of `value` when it is JSON data of at most `maxBytes`; `undefined` otherwise. */
function frozenJsonCopy(value: unknown, maxBytes: number): unknown {
  if (!isJsonData(value, 0)) return undefined;
  const json = JSON.stringify(value);
  if (Buffer.byteLength(json, 'utf8') > maxBytes) return undefined;
  return deepFreeze(JSON.parse(json) as unknown);
}

function isJsonData(value: unknown, depth: number): boolean {
  if (depth > 16) return false;
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every((item) => isJsonData(item, depth + 1));
  if (typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  if (Object.getOwnPropertySymbols(value).length > 0) return false;
  return Object.values(value).every((item) => isJsonData(item, depth + 1));
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function checkedIdentity(type: string, identity: unknown): VerifiedIdentity {
  const fault = (problem: string) => new AuthMethodFaultError(type, `verify() resolved ${problem}`);
  if (typeof identity !== 'object' || identity === null) throw fault('something not an object');
  const { externalSub, assuranceLevel, rawClaims } = identity as Record<string, unknown>;
  if (
    typeof externalSub !== 'string' ||
    externalSub.length === 0 ||
    externalSub.length > MAX_AUTH_METHOD_EXTERNAL_SUB_LENGTH ||
    CONTROL_CHARACTER.test(externalSub)
  ) {
    throw fault(
      `an externalSub that is not 1 to ${MAX_AUTH_METHOD_EXTERNAL_SUB_LENGTH} characters with no control character`
    );
  }
  if (!(ASSURANCE_LEVELS as readonly unknown[]).includes(assuranceLevel)) {
    throw fault(`an assuranceLevel outside ${ASSURANCE_LEVELS.join(', ')}`);
  }
  const claims =
    typeof rawClaims === 'object' && rawClaims !== null && !Array.isArray(rawClaims)
      ? frozenJsonCopy(rawClaims, MAX_AUTH_METHOD_RAW_CLAIMS_BYTES)
      : undefined;
  if (claims === undefined) {
    throw fault(
      `rawClaims that are not an object of JSON data of at most ${MAX_AUTH_METHOD_RAW_CLAIMS_BYTES} bytes`
    );
  }
  return Object.freeze({
    externalSub,
    assuranceLevel: assuranceLevel as AssuranceLevel,
    rawClaims: claims as Record<string, unknown>,
  });
}

function checkedAttributes(type: string, attributes: unknown): readonly UserAttribute[] {
  const fault = (problem: string) =>
    new AuthMethodFaultError(type, `extractAttributes() returned ${problem}`);
  if (!Array.isArray(attributes)) throw fault('something not a list');
  return Object.freeze(
    attributes.map((attribute: unknown, index): UserAttribute => {
      if (typeof attribute !== 'object' || attribute === null) {
        throw fault(`an attribute [${index}] that is not an object`);
      }
      const { source, attrKey, attrValue, verified, expiresAt } = attribute as Record<
        string,
        unknown
      >;
      // The source must be the method's own type: a method cannot write
      // attributes under another source, such as `wallet`, which outranks
      // every other in claim resolution.
      if (source !== type) throw fault(`an attribute [${index}] whose source is not ${type}`);
      if (typeof attrKey !== 'string' || !AUTH_METHOD_ATTRIBUTE_KEY_PATTERN.test(attrKey)) {
        throw fault(
          `an attribute [${index}] whose key does not match ${AUTH_METHOD_ATTRIBUTE_KEY_PATTERN.source}`
        );
      }
      if (
        typeof attrValue !== 'string' ||
        attrValue.length > MAX_AUTH_METHOD_ATTRIBUTE_VALUE_LENGTH ||
        VALUE_CONTROL_CHARACTER.test(attrValue)
      ) {
        throw fault(
          `an attribute [${index}] whose value is not a string of at most ${MAX_AUTH_METHOD_ATTRIBUTE_VALUE_LENGTH} characters without control characters other than tab and line breaks`
        );
      }
      if (typeof verified !== 'boolean') {
        throw fault(`an attribute [${index}] whose verified flag is not a boolean`);
      }
      if (
        expiresAt !== undefined &&
        (!(expiresAt instanceof Date) || Number.isNaN(expiresAt.getTime()))
      ) {
        throw fault(`an attribute [${index}] whose expiresAt is not a valid Date`);
      }
      return Object.freeze({
        source,
        attrKey,
        attrValue,
        verified,
        ...(expiresAt === undefined ? {} : { expiresAt }),
      });
    })
  );
}
