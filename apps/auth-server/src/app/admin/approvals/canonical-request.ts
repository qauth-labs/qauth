import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { canonicalizeJson } from '@qauth-labs/fastify-plugin-db';

/**
 * THE CANONICAL OPERATION (ADR-019 Decision 7, issue #512).
 *
 * An approval is bound to one exact request of one operation: its operation
 * id, method, path parameters, query and body, the realm it acts on and the
 * account that asks. The canonical request holds those, serialized with the
 * JSON Canonicalization Scheme (RFC 8785, the canonicalizer the admin audit
 * log hashes with), and two SHA-256 digests are taken over it:
 *
 * - `request_hash`, without the nonce: the admin pipeline recomputes it from
 *   the retried call and compares it with the stored one, so a changed body,
 *   path parameter, query, realm or requester finds no approval;
 * - `op_hash`, with the server's nonce: the challenge an approver's factor
 *   signs is derived from it, so an approval given for one filing never
 *   approves another, even of the same request.
 *
 * Values are compared after the route's own validation: the approval routes
 * parse the filed path parameters, query and body with the schemas of the
 * operation's route, as the retried call is parsed. The path's `realmId` is
 * the realm's stored id, so a retry that spells it in upper case still
 * matches.
 */

/** Who files an approval: an account, of the realm it lives in. */
export interface ApprovalRequester {
  readonly kind: 'human' | 'service_account';
  /** The realm the account lives in. */
  readonly realmId: string;
  readonly accountId: string;
}

/** A JSON value, as the canonicalizer takes it. */
export type CanonicalValue =
  | string
  | number
  | boolean
  | null
  | readonly CanonicalValue[]
  | { readonly [member: string]: CanonicalValue };

/** The request an approval is bound to, without the nonce. */
export interface CanonicalRequest {
  readonly operationId: string;
  /** Upper case, as HTTP names it. */
  readonly method: string;
  /** Every path parameter, `realmId` included. */
  readonly params: { readonly [name: string]: CanonicalValue };
  readonly query: { readonly [name: string]: CanonicalValue };
  /** `null` for a request with no body. */
  readonly body: CanonicalValue;
  /** The realm the operation acts on. */
  readonly realmId: string;
  readonly requester: ApprovalRequester;
}

/** The parts of a request {@link canonicalRequest} binds, as the route parsed them. */
export interface CanonicalRequestInput {
  readonly operationId: string;
  readonly method: string;
  readonly params: unknown;
  readonly query: unknown;
  readonly body: unknown;
  readonly realmId: string;
  readonly requester: ApprovalRequester;
}

/** A request that has no canonical form: a value outside JSON, or one the approval store cannot keep. */
export class CanonicalRequestError extends Error {
  override readonly name = 'CanonicalRequestError';
}

/** The length of the server's nonce. */
export const APPROVAL_NONCE_BYTES = 32;

/** Whether `value` is a plain object, as the canonicalizer takes one. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Whether `value` is one of the objects Fastify hands a route with no params
 * or querystring schema: the router's `NullObject` and the query parser's
 * `Empty`, each made from a prototype that is an empty object with no
 * prototype of its own.
 */
function isParsedRecord(value: object): boolean {
  const prototype: unknown = Object.getPrototypeOf(value);
  return (
    typeof prototype === 'object' &&
    prototype !== null &&
    Object.getPrototypeOf(prototype) === null &&
    Reflect.ownKeys(prototype).length === 0
  );
}

/**
 * The path parameters or the query as a plain object of their own members:
 * a plain object as it is, and Fastify's own parsed objects copied. Anything
 * else, such as a `Map` or a class instance a schema's transform made, is not
 * a set of parameters: its members would not say what it holds.
 */
function parameterRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  if (!isPlainObject(value) && !isParsedRecord(value)) return undefined;
  return Object.fromEntries(Object.entries(value));
}

/**
 * Throw when a string of `value`, member names included, holds U+0000:
 * Postgres `jsonb` cannot store it, so such a request could be approved but
 * never filed.
 */
function assertStorable(value: unknown, path: string): void {
  if (typeof value === 'string') {
    if (value.includes('\u0000')) {
      throw new CanonicalRequestError(`${path} holds U+0000, which no approval can store`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertStorable(item, `${path}[${index}]`));
    return;
  }
  if (isPlainObject(value)) {
    for (const [key, item] of Object.entries(value)) {
      assertStorable(key, `${path} member name`);
      assertStorable(item, `${path}.${key}`);
    }
  }
}

/**
 * The canonical request of `input`: the method in upper case, the path
 * parameters and the query as plain objects of their own members, an absent
 * query as `{}`, an absent body as `null`, and the path's `realmId` replaced
 * by the realm's stored id.
 *
 * @throws {CanonicalRequestError} when the parameters or the query are not
 *   objects, or any part holds a value outside the I-JSON model the
 *   canonicalizer takes (a binary body among them) or a U+0000
 */
export function canonicalRequest(input: CanonicalRequestInput): CanonicalRequest {
  const params = parameterRecord(input.params ?? {});
  const query = parameterRecord(input.query ?? {});
  if (params === undefined || query === undefined) {
    throw new CanonicalRequestError('the path parameters and the query are objects');
  }
  const request = {
    operationId: input.operationId,
    method: input.method.toUpperCase(),
    params: { ...params, realmId: input.realmId },
    query,
    body: input.body === undefined ? null : input.body,
    realmId: input.realmId,
    requester: {
      kind: input.requester.kind,
      realmId: input.requester.realmId,
      accountId: input.requester.accountId,
    },
  };
  assertStorable(request, 'the request');
  try {
    canonicalizeJson(request);
  } catch (error) {
    throw new CanonicalRequestError(
      `the request has no canonical form: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  return request as CanonicalRequest;
}

const sha256 = (text: string): Buffer => createHash('sha256').update(text, 'utf8').digest();

/** `request_hash`: SHA-256 of the RFC 8785 form of the canonical request, without the nonce. */
export function requestHashOf(request: CanonicalRequest): Buffer {
  return sha256(canonicalizeJson(request));
}

/**
 * `op_hash`: SHA-256 of the RFC 8785 form of the canonical request with the
 * nonce, base64url, as its `nonce` member.
 */
export function opHashOf(request: CanonicalRequest, nonce: Buffer): Buffer {
  if (nonce.length !== APPROVAL_NONCE_BYTES) {
    throw new CanonicalRequestError(`the nonce is ${APPROVAL_NONCE_BYTES} bytes`);
  }
  return sha256(canonicalizeJson({ ...request, nonce: nonce.toString('base64url') }));
}

/** A fresh server nonce. */
export function newApprovalNonce(): Buffer {
  return randomBytes(APPROVAL_NONCE_BYTES);
}

/** Whether two digests are the same, compared in constant time. */
export function sameDigest(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}
