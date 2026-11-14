import type { HybridSignedToken } from '@qauth-labs/core-crypto';
import type { JWK } from 'jose';

import { isKeyCustodyError } from './errors';
import { isKeyPurpose } from './key-purposes';
import { PRIVATE_JWK_MEMBERS } from './published-keys';
import { isRealmId } from './realm-id';
import {
  type CookieDerivedKey,
  type CookieSecret,
  type CookieSecrets,
  type RealmJwks,
  type Signer,
  SIGNER_OPERATIONS,
  type SignerOperation,
  type VerificationKey,
} from './signer';
import {
  DataDecryptionError,
  isSignerError,
  isSignerRefusalReason,
  RealmIssuerNotFoundError,
  SignerAccessDeniedError,
  type SignerErrorCode,
  SignerKeyNotFoundError,
  type SignerRefusalReason,
  SignerRequestRefusedError,
  UpstreamClientNotFoundError,
} from './signer-errors';
import { isSignerCaller } from './signer-policy';

/**
 * THE SIGNER SERVICE'S WIRE FORMAT (ADR-019 Decision 9, issue #497).
 *
 * In a distributed deployment the roles without the KEK reach the signer
 * over mutual TLS: the signer role serves one route per {@link Signer}
 * operation on its internal listener, and the remote signer of the other
 * roles calls them with the same interface. Both sides build and read the
 * messages with this module, so the two never drift apart.
 *
 * - Every route is a `POST` below {@link SIGNER_SERVICE_PATH}, with a JSON
 *   body: no claim, plaintext or secret ever sits in a URL, where an access
 *   log would keep it.
 * - The body is the operation's own request object (`signJws`, `encrypt` …),
 *   or its positional arguments by name (`getCookieSecrets` takes `realmId`
 *   and `options`). It carries no caller: the signer takes the role from the
 *   peer's client certificate.
 * - Bytes travel as `{ "bytes": "<base64url>" }`: a webhook body given as
 *   bytes, a plaintext, a decrypted value and the cookie secrets.
 * - A success is `200` with `{ "result": … }`.
 * - A refusal or a failure is `{ "error": { "code": … } }` with public
 *   fields only: a code, a refusal reason, an operation, a role, a key
 *   purpose, an algorithm. Never a message, a claim value, a
 *   plaintext, a ciphertext or key material (see {@link encodeSignerError}).
 *
 * The version in the path is a release candidate until QAuth 1.0
 * (ADR-018 §5): a breaking change raises it.
 */

/** The path every route of the signer service sits under, on the signer's internal listener. */
export const SIGNER_SERVICE_PATH = '/internal/signer/v1-rc.0';

/** Each operation's route, below {@link SIGNER_SERVICE_PATH}. Every route is a `POST`. */
export const SIGNER_SERVICE_ROUTES: Readonly<Record<SignerOperation, string>> = Object.freeze({
  signJws: '/sign-jws',
  signHybrid: '/sign-hybrid',
  signWebhook: '/sign-webhook',
  signClientAssertion: '/sign-client-assertion',
  signRequestObject: '/sign-request-object',
  getCookieSecrets: '/cookie-secrets',
  getCookieDerivedKey: '/cookie-derived-key',
  verifyCookieMac: '/verify-cookie-mac',
  encrypt: '/encrypt',
  decrypt: '/decrypt',
  getVerificationKeys: '/verification-keys',
  getJwks: '/jwks',
  getUpstreamJwks: '/upstream-jwks',
});

/** The largest request body of a call that names a realm and a few ids. */
const SMALL_REQUEST_BYTES = 64 * 1024;

/**
 * The largest request body of a call that carries claims, a body or data:
 * twice the public listener's largest request body (1 MiB), so a value a
 * caller could send there still fits once its bytes travel as base64url
 * (4/3 of their size) inside the JSON of the call.
 */
const LARGE_REQUEST_BYTES = 2 * 1024 * 1024;

/**
 * The largest request body, in bytes of its JSON, the signer service takes
 * for each operation. A remote signer refuses a larger request before it is
 * sent (`REQUEST_TOO_LARGE`), and the service answers `413` to one that
 * arrives.
 */
export const SIGNER_REQUEST_BODY_LIMITS: Readonly<Record<SignerOperation, number>> = Object.freeze({
  signJws: LARGE_REQUEST_BYTES,
  signHybrid: LARGE_REQUEST_BYTES,
  signWebhook: LARGE_REQUEST_BYTES,
  signClientAssertion: SMALL_REQUEST_BYTES,
  signRequestObject: LARGE_REQUEST_BYTES,
  getCookieSecrets: SMALL_REQUEST_BYTES,
  getCookieDerivedKey: SMALL_REQUEST_BYTES,
  verifyCookieMac: SMALL_REQUEST_BYTES,
  encrypt: LARGE_REQUEST_BYTES,
  decrypt: LARGE_REQUEST_BYTES,
  getVerificationKeys: SMALL_REQUEST_BYTES,
  getJwks: SMALL_REQUEST_BYTES,
  getUpstreamJwks: SMALL_REQUEST_BYTES,
});

/**
 * The largest answer a signer service gives, in bytes: an encryption of the
 * largest plaintext, in base64url, with room to spare. A remote signer's
 * transport reads no larger answer.
 */
export const SIGNER_MAX_ANSWER_BYTES = 4 * 1024 * 1024;

/** Whether `value` names a {@link SignerOperation}. */
export function isSignerOperation(value: unknown): value is SignerOperation {
  return typeof value === 'string' && (SIGNER_OPERATIONS as readonly string[]).includes(value);
}

/** The codes a signer service's error carries: the signer's own, and two of the service's. */
export type SignerWireErrorCode =
  | SignerErrorCode
  /** The signer cannot do its work now, such as a KEK provider that does not answer. */
  | 'SIGNER_UNAVAILABLE'
  /** Something failed inside the signer that it does not name. */
  | 'SIGNER_FAULT';

/** The `error` member of a signer service's answer. Every field is public. */
export interface SignerWireError {
  readonly code: SignerWireErrorCode;
  /** With `SIGNER_REQUEST_REFUSED`. */
  readonly reason?: SignerRefusalReason;
  /** With `SIGNER_ACCESS_DENIED`: the role the call was refused for. */
  readonly caller?: string;
  /** With `SIGNER_ACCESS_DENIED`: the operation. */
  readonly operation?: SignerOperation;
  /** With `SIGNER_ACCESS_DENIED` and `SIGNER_KEY_NOT_FOUND`: the key purpose. */
  readonly purpose?: string;
  /**
   * With `SIGNER_KEY_NOT_FOUND`: the algorithm asked for. No `kid` travels:
   * the one a lookup names may come from the caller's ciphertext.
   */
  readonly algorithm?: string;
}

/** A body of the signer service, success or error, ready for `JSON.stringify`. */
export type SignerWireBody = { readonly result: unknown } | { readonly error: SignerWireError };

/** The HTTP status of each error code. A refusal is 4xx; the signer's own trouble is 5xx. */
export const SIGNER_WIRE_ERROR_STATUS: Readonly<Record<SignerWireErrorCode, number>> =
  Object.freeze({
    SIGNER_ACCESS_DENIED: 403,
    SIGNER_REQUEST_REFUSED: 400,
    // The signer answered, and the request cannot succeed as asked: neither
    // the caller's fault (400) nor the signer's trouble (5xx), so a remote
    // signer never counts it as an outage.
    SIGNER_ISSUER_NOT_FOUND: 422,
    SIGNER_UPSTREAM_CLIENT_NOT_FOUND: 422,
    SIGNER_KEY_NOT_FOUND: 422,
    DATA_DECRYPTION_FAILED: 422,
    SIGNER_UNAVAILABLE: 503,
    SIGNER_FAULT: 500,
  });

// ---------------------------------------------------------------------------
// Bytes
// ---------------------------------------------------------------------------

/** Bytes on the wire. */
export interface WireBytes {
  readonly bytes: string;
}

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** `bytes` as {@link WireBytes}. */
export function encodeWireBytes(bytes: Uint8Array): WireBytes {
  return {
    bytes: Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url'),
  };
}

/**
 * The bytes `value` carries when it is {@link WireBytes} with a well-formed
 * base64url value and nothing else, or `undefined`. Never echoes the value.
 */
export function decodeWireBytes(value: unknown): Buffer | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const keys = Object.keys(value);
  if (keys.length !== 1 || keys[0] !== 'bytes') return undefined;
  const text = (value as { bytes: unknown }).bytes;
  // A length of 4n + 1 is no base64url text: no byte string encodes to it.
  if (typeof text !== 'string' || !BASE64URL.test(text) || text.length % 4 === 1) {
    return undefined;
  }
  return Buffer.from(text, 'base64url');
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/** The arguments of each operation after the caller: what a remote call carries. */
export type SignerOperationArgs<O extends SignerOperation> =
  Parameters<Signer[O]> extends [unknown, ...infer Rest] ? Rest : never;

/** The answer of each operation. */
export type SignerOperationResult<O extends SignerOperation> = Awaited<ReturnType<Signer[O]>>;

/** The field names of an operation whose arguments travel by name, not as one request object. */
const NAMED_ARGUMENTS = {
  getCookieSecrets: ['realmId', 'options'],
  getVerificationKeys: ['realmId', 'purpose'],
  getJwks: ['realmId', 'purpose'],
  getUpstreamJwks: ['realmId', 'providerId'],
} as const satisfies Partial<Record<SignerOperation, readonly string[]>>;

type NamedOperation = keyof typeof NAMED_ARGUMENTS;

function isNamedOperation(operation: SignerOperation): operation is NamedOperation {
  return Object.hasOwn(NAMED_ARGUMENTS, operation);
}

/** A webhook body or a plaintext as it travels: bytes as {@link WireBytes}, anything else as is. */
function bytesField(value: unknown): unknown {
  return value instanceof Uint8Array ? encodeWireBytes(value) : value;
}

/**
 * The body a remote call of `operation` sends, as text: the request object,
 * its bytes as {@link WireBytes}, or the named arguments. A request the
 * in-process signer would refuse travels as it is, so the signer refuses it
 * with the same reason; one that is not JSON at all is refused here.
 *
 * @throws SignerRequestRefusedError (`INVALID_CLAIMS`) when the request does
 *   not serialize, such as claims that hold a `BigInt` or a cycle. The
 *   serializer's message is dropped: it may quote a claim.
 */
export function encodeSignerRequest<O extends SignerOperation>(
  operation: O,
  args: SignerOperationArgs<O>
): string {
  let body: unknown;
  if (isNamedOperation(operation)) {
    const named: Record<string, unknown> = {};
    NAMED_ARGUMENTS[operation].forEach((name, index) => {
      const value = (args as readonly unknown[])[index];
      if (value !== undefined) named[name] = value;
    });
    body = named;
  } else {
    const [request] = args as readonly unknown[];
    if (typeof request === 'object' && request !== null && !Array.isArray(request)) {
      const fields = { ...(request as Record<string, unknown>) };
      if (operation === 'signWebhook' && Object.hasOwn(fields, 'body')) {
        fields['body'] = bytesField(fields['body']);
      }
      if (operation === 'encrypt' && Object.hasOwn(fields, 'plaintext')) {
        fields['plaintext'] = bytesField(fields['plaintext']);
      }
      body = fields;
    } else {
      body = request;
    }
  }
  try {
    const text = JSON.stringify(body);
    if (typeof text !== 'string') throw new TypeError('not JSON');
    return text;
  } catch {
    throw new SignerRequestRefusedError('INVALID_CLAIMS', 'The request does not serialize as JSON');
  }
}

/**
 * The arguments the signer service hands its in-process signer for a body
 * it read: the request object with its bytes decoded, or the named
 * arguments in their order. Fields the operation does not take stay, so the
 * signer refuses them as it would in-process.
 *
 * @throws SignerRequestRefusedError (`UNEXPECTED_FIELD`) when the body is not
 *   a JSON object, or names an argument the operation does not take
 */
export function decodeSignerRequest<O extends SignerOperation>(
  operation: O,
  body: unknown
): SignerOperationArgs<O> {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new SignerRequestRefusedError('UNEXPECTED_FIELD', 'A signer request is a JSON object');
  }
  const fields = body as Record<string, unknown>;
  if (isNamedOperation(operation)) {
    const names: readonly string[] = NAMED_ARGUMENTS[operation];
    if (Object.keys(fields).some((field) => !names.includes(field))) {
      // The field's name is the caller's text: not echoed.
      throw new SignerRequestRefusedError(
        'UNEXPECTED_FIELD',
        'The request names an argument this operation does not take'
      );
    }
    return names.map((name) => fields[name]) as unknown as SignerOperationArgs<O>;
  }
  const request = { ...fields };
  if (operation === 'signWebhook' && typeof request['body'] !== 'string') {
    request['body'] = decodeWireBytes(request['body']) ?? request['body'];
  }
  if (operation === 'encrypt') {
    request['plaintext'] = decodeWireBytes(request['plaintext']) ?? request['plaintext'];
  }
  return [request] as unknown as SignerOperationArgs<O>;
}

// ---------------------------------------------------------------------------
// Answers
// ---------------------------------------------------------------------------

/**
 * The `result` member the signer service answers `result` of `operation`
 * with. The secrets it carries (cookie secrets, a decrypted plaintext) are
 * zeroed in `result` once encoded: the buffers belonged to the service.
 */
export function encodeSignerResult<O extends SignerOperation>(
  operation: O,
  result: SignerOperationResult<O>
): unknown {
  switch (operation) {
    case 'getCookieSecrets': {
      const secrets = result as CookieSecrets;
      const encode = (secret: CookieSecret) => {
        const encoded = { kid: secret.kid, ...encodeWireBytes(secret.secret) };
        secret.secret.fill(0);
        return encoded;
      };
      return {
        current: encode(secrets.current),
        previous: secrets.previous === null ? null : encode(secrets.previous),
      };
    }
    case 'getCookieDerivedKey': {
      const derived = result as CookieDerivedKey;
      const encoded = { kid: derived.kid, ...encodeWireBytes(derived.key) };
      derived.key.fill(0);
      return encoded;
    }
    case 'decrypt': {
      const plaintext = result as Buffer;
      const encoded = encodeWireBytes(plaintext);
      plaintext.fill(0);
      return encoded;
    }
    default:
      return result;
  }
}

/** An answer of the signer service that does not have the shape its operation answers. */
export class SignerWireFormatError extends Error {
  constructor(operation: SignerOperation) {
    super(`The signer service's answer to ${operation} is not in the form it answers`);
    this.name = 'SignerWireFormatError';
  }
}

/** The member `name` of `value`, an object, or `undefined`. */
function member(value: unknown, name: string): unknown {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)[name]
    : undefined;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/** A public JWK the answer carries, frozen, or `undefined` for one with a private member. */
function publicJwk(value: unknown): JWK | undefined {
  if (!isPlainObject(value) || typeof value['kty'] !== 'string') return undefined;
  if (PRIVATE_JWK_MEMBERS.some((member) => Object.hasOwn(value, member))) return undefined;
  return deepFreeze(structuredClone(value) as JWK);
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

function decodeJwks(operation: SignerOperation, value: unknown): RealmJwks {
  if (!isPlainObject(value) || !Array.isArray(value['keys'])) {
    throw new SignerWireFormatError(operation);
  }
  const keys = value['keys'].map((key) => {
    const jwk = publicJwk(key);
    if (jwk === undefined) throw new SignerWireFormatError(operation);
    return jwk;
  });
  return Object.freeze({ keys: Object.freeze(keys) });
}

function decodeCookieSecret(value: unknown): CookieSecret | undefined {
  if (!isPlainObject(value) || !isNonEmptyString(value['kid'])) return undefined;
  const { kid, ...rest } = value;
  const secret = decodeWireBytes(rest);
  if (secret === undefined || secret.length === 0) return undefined;
  return Object.freeze({ kid, secret });
}

/**
 * The answer of `operation` that a signer service's `result` member holds,
 * checked against what the operation answers: a remote signer hands its
 * caller nothing of another shape. A JWK with a private member is refused,
 * never passed on.
 *
 * @throws SignerWireFormatError for an answer of another shape
 */
export function decodeSignerResult<O extends SignerOperation>(
  operation: O,
  value: unknown
): SignerOperationResult<O> {
  const fail = (): never => {
    throw new SignerWireFormatError(operation);
  };
  switch (operation) {
    case 'signJws':
    case 'signWebhook':
    case 'signClientAssertion':
    case 'signRequestObject':
    case 'encrypt':
      return (isNonEmptyString(value) ? value : fail()) as SignerOperationResult<O>;
    case 'signHybrid': {
      if (
        !isPlainObject(value) ||
        !isNonEmptyString(value['token']) ||
        !isNonEmptyString(value['pqcSignature']) ||
        !isNonEmptyString(value['pqcAlg'])
      ) {
        return fail();
      }
      const signed: HybridSignedToken = {
        token: value['token'],
        pqcSignature: value['pqcSignature'],
        pqcAlg: value['pqcAlg'] as HybridSignedToken['pqcAlg'],
      };
      return Object.freeze(signed) as SignerOperationResult<O>;
    }
    case 'getCookieSecrets': {
      if (!isPlainObject(value)) return fail();
      const current = decodeCookieSecret(value['current']);
      const previous = value['previous'] === null ? null : decodeCookieSecret(value['previous']);
      if (current === undefined || previous === undefined) return fail();
      return Object.freeze({ current, previous }) as SignerOperationResult<O>;
    }
    case 'getCookieDerivedKey': {
      // Of the same shape as a cookie secret: a `kid` and the key's bytes.
      const derived = decodeCookieSecret(value);
      if (derived === undefined || derived.secret.length !== 32) return fail();
      return Object.freeze({ kid: derived.kid, key: derived.secret }) as SignerOperationResult<O>;
    }
    case 'verifyCookieMac':
      return (typeof value === 'boolean' ? value : fail()) as SignerOperationResult<O>;
    case 'decrypt': {
      const plaintext = decodeWireBytes(value);
      return (plaintext ?? fail()) as SignerOperationResult<O>;
    }
    case 'getVerificationKeys': {
      if (!Array.isArray(value)) return fail();
      const keys = value.map((entry): VerificationKey => {
        if (
          !isPlainObject(entry) ||
          !isNonEmptyString(entry['kid']) ||
          !isNonEmptyString(entry['algorithm']) ||
          (entry['status'] !== 'active' && entry['status'] !== 'retired')
        ) {
          return fail();
        }
        const jwk = publicJwk(entry['publicJwk']);
        if (jwk === undefined) return fail();
        return Object.freeze({
          kid: entry['kid'],
          algorithm: entry['algorithm'],
          status: entry['status'],
          publicJwk: jwk,
        });
      });
      return Object.freeze(keys) as SignerOperationResult<O>;
    }
    case 'getJwks':
    case 'getUpstreamJwks':
      return decodeJwks(operation, value) as SignerOperationResult<O>;
    default:
      return fail();
  }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** An algorithm name fit to travel, such as `EdDSA` or `EdDSA+ML-DSA-65`. */
const ALGORITHM_NAME = /^[A-Za-z0-9+-]{1,32}$/;

function publicAlgorithm(value: unknown): string | undefined {
  return typeof value === 'string' && ALGORITHM_NAME.test(value) ? value : undefined;
}

/** An error's class name or code fit for a log line: a short identifier. */
const IDENTIFIER = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

function publicIdentifier(value: unknown): string | undefined {
  return typeof value === 'string' && IDENTIFIER.test(value) ? value : undefined;
}

/** A key purpose fit to travel: one of `KEY_PURPOSES`, never the caller's text. */
function publicPurpose(value: unknown): string | undefined {
  return typeof value === 'string' && isKeyPurpose(value) ? value : undefined;
}

/** What {@link encodeSignerError} makes of an error: the answer, and what to log of it. */
export interface EncodedSignerError {
  readonly status: number;
  readonly body: { readonly error: SignerWireError };
  /**
   * For the service's log, never sent: the error's class name and code when
   * the signer did not name the failure. Its message is left out, as it may
   * quote what the request carried.
   */
  readonly fault?: { readonly name: string; readonly code?: string };
}

/**
 * The answer the signer service gives for `error`, thrown by the in-process
 * signer or by {@link decodeSignerRequest}. It carries the error's code and
 * the public fields its class names, each checked against what such a field
 * may hold; never its message, so no claim value, plaintext, ciphertext or
 * key byte the request or the signer held reaches the caller.
 *
 * - a key-custody error (the KEK provider, an unwrap) is `SIGNER_UNAVAILABLE`, 503;
 * - any other error is `SIGNER_FAULT`, 500.
 */
export function encodeSignerError(error: unknown): EncodedSignerError {
  const answer = (wire: SignerWireError, fault?: EncodedSignerError['fault']) => ({
    status: SIGNER_WIRE_ERROR_STATUS[wire.code],
    body: { error: Object.freeze(wire) },
    ...(fault === undefined ? {} : { fault }),
  });
  if (isSignerError(error)) {
    const fields = error as unknown as Record<string, unknown>;
    switch (error.code) {
      case 'SIGNER_ACCESS_DENIED': {
        const caller = isSignerCaller(fields['caller']) ? fields['caller'] : undefined;
        const operation = isSignerOperation(fields['operation']) ? fields['operation'] : undefined;
        const purpose = publicPurpose(fields['purpose']);
        return answer({
          code: error.code,
          ...(caller === undefined ? {} : { caller }),
          ...(operation === undefined ? {} : { operation }),
          ...(purpose === undefined ? {} : { purpose }),
        });
      }
      case 'SIGNER_REQUEST_REFUSED': {
        const reason = isSignerRefusalReason(fields['reason']) ? fields['reason'] : undefined;
        return answer({ code: error.code, ...(reason === undefined ? {} : { reason }) });
      }
      case 'SIGNER_KEY_NOT_FOUND': {
        const purpose = publicPurpose(fields['purpose']);
        const algorithm = publicAlgorithm(fields['algorithm']);
        return answer({
          code: error.code,
          ...(purpose === undefined ? {} : { purpose }),
          ...(algorithm === undefined ? {} : { algorithm }),
        });
      }
      case 'SIGNER_ISSUER_NOT_FOUND':
      case 'SIGNER_UPSTREAM_CLIENT_NOT_FOUND':
      case 'DATA_DECRYPTION_FAILED':
        return answer({ code: error.code });
    }
  }
  const name = error instanceof Error ? error.name : typeof error;
  const code = error instanceof Error ? publicIdentifier(member(error, 'code')) : undefined;
  const fault = {
    name: publicIdentifier(name) ?? 'Error',
    ...(code === undefined ? {} : { code }),
  };
  if (isKeyCustodyError(error)) return answer({ code: 'SIGNER_UNAVAILABLE' }, fault);
  return answer({ code: 'SIGNER_FAULT' }, fault);
}

/** What a remote call knows of the request an error answers. */
export interface SignerErrorContext {
  readonly operation: SignerOperation;
  /** The realm id the request named. */
  readonly realmId: unknown;
}

/**
 * The signer error a signer service's `error` member stands for, rebuilt
 * with this library's classes and a message made of its public fields
 * alone, or `undefined` when the member is not one a signer answers (an
 * unknown code, an unknown refusal reason), or names the service's own
 * trouble (`SIGNER_UNAVAILABLE`, `SIGNER_FAULT`): the caller then fails
 * closed as for an outage.
 */
export function decodeSignerError(value: unknown, context: SignerErrorContext): Error | undefined {
  if (!isPlainObject(value)) return undefined;
  const realmId = isRealmId(context.realmId) ? context.realmId.toLowerCase() : 'unknown';
  switch (value['code']) {
    case 'SIGNER_ACCESS_DENIED': {
      const caller = isSignerCaller(value['caller']) ? value['caller'] : undefined;
      const operation = isSignerOperation(value['operation'])
        ? value['operation']
        : context.operation;
      return new SignerAccessDeniedError(caller, operation, publicPurpose(value['purpose']));
    }
    case 'SIGNER_REQUEST_REFUSED': {
      const reason = value['reason'];
      if (!isSignerRefusalReason(reason)) return undefined;
      return new SignerRequestRefusedError(
        reason,
        `The signer service refused the ${context.operation} request (${reason})`
      );
    }
    case 'SIGNER_ISSUER_NOT_FOUND':
      return new RealmIssuerNotFoundError(realmId);
    case 'SIGNER_UPSTREAM_CLIENT_NOT_FOUND':
      return new UpstreamClientNotFoundError(realmId);
    case 'SIGNER_KEY_NOT_FOUND': {
      const algorithm = publicAlgorithm(value['algorithm']);
      return new SignerKeyNotFoundError(
        realmId,
        publicPurpose(value['purpose']) ?? 'unknown',
        algorithm === undefined ? {} : { algorithm }
      );
    }
    case 'DATA_DECRYPTION_FAILED':
      return new DataDecryptionError('answered by the signer service');
    default:
      return undefined;
  }
}
