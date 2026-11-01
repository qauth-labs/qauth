import type { AuthMethodEgress, AuthMethodEgressResponse } from '@qauth-labs/server-federation';

import { invalidResponse, UpstreamOidcError } from './errors';

/**
 * Every call the client makes, through the egress client (ADR-019
 * Decision 8): one place that sets the caps.
 *
 * - **No redirect is followed.** Each call asks for `redirect: 'error'`, so
 *   a redirect answer rejects the call before anything reaches its target: a
 *   token request carries a code, a verifier and a client credential in its
 *   body, and a `307` would send that body on. The answering URL must be the
 *   one called.
 * - **Time.** Each call has its own deadline, under the egress client's.
 * - **Size.** Each answer has its own cap, under the egress client's.
 */

/** The caps of one kind of call. */
export interface UpstreamCallCaps {
  /** The whole call, in milliseconds. */
  readonly timeoutMs: number;
  /** The largest answer body, in bytes. */
  readonly maxBytes: number;
}

/** The caps of each call the client makes. */
export const UPSTREAM_OIDC_CALL_CAPS = Object.freeze({
  discovery: Object.freeze({ timeoutMs: 5_000, maxBytes: 64 * 1024 }),
  jwks: Object.freeze({ timeoutMs: 5_000, maxBytes: 64 * 1024 }),
  token: Object.freeze({ timeoutMs: 10_000, maxBytes: 64 * 1024 }),
  userinfo: Object.freeze({ timeoutMs: 5_000, maxBytes: 64 * 1024 }),
} satisfies Record<string, UpstreamCallCaps>);

/** The egress purposes of the client's calls: fixed labels for counts and logs. */
export const UPSTREAM_OIDC_PURPOSES = Object.freeze({
  discovery: 'upstream-discovery',
  jwks: 'upstream-jwks',
  token: 'upstream-token',
  userinfo: 'upstream-userinfo',
});

/** One call. */
export interface UpstreamCall {
  readonly method: 'GET' | 'POST';
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string;
  readonly purpose: string;
  /** `admin` for a URL the realm's config names, `remote_document` for a discovered one. */
  readonly source: 'admin' | 'remote_document';
  readonly caps: UpstreamCallCaps;
}

/**
 * Send one call through `egress` and check its answer against the caps.
 * Resolves with the answer whatever its status.
 *
 * @throws UpstreamOidcError `upstream_unavailable` when the egress client
 *   refuses or fails the call or the deadline passes; `invalid_response`
 *   when the answer is over its cap or came from another URL
 */
export async function upstreamCall(
  egress: AuthMethodEgress,
  call: UpstreamCall
): Promise<AuthMethodEgressResponse> {
  // The URL as parsed, so the answering URL compares with what was sent.
  const url = new URL(call.url).href;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new UpstreamOidcError(
            'upstream_unavailable',
            `${call.purpose}: no answer within ${call.caps.timeoutMs} ms`
          )
        ),
      call.caps.timeoutMs
    );
  });
  let response: AuthMethodEgressResponse;
  try {
    const sent = egress.request({
      method: call.method,
      url,
      ...(call.headers === undefined ? {} : { headers: call.headers }),
      ...(call.body === undefined ? {} : { body: call.body }),
      purpose: call.purpose,
      source: call.source,
      redirect: 'error',
    });
    // An abandoned call settles later; its rejection is not left unhandled.
    sent.catch(() => undefined);
    response = await Promise.race([sent, deadline]);
  } catch (error) {
    if (error instanceof UpstreamOidcError) throw error;
    throw new UpstreamOidcError(
      'upstream_unavailable',
      `${call.purpose}: the egress client refused or failed the call`,
      { cause: error }
    );
  } finally {
    clearTimeout(timer);
  }
  if (response.body.byteLength > call.caps.maxBytes) {
    throw invalidResponse(`${call.purpose}: the answer is larger than ${call.caps.maxBytes} bytes`);
  }
  if (response.url !== url) {
    throw invalidResponse(`${call.purpose}: the answer came from another URL`);
  }
  return response;
}

/** A JSON media type: `application/json` or a `+json` type, with parameters. */
const JSON_MEDIA_TYPE = /^application\/(?:[a-z0-9.+-]+\+)?json\s*(?:;|$)/i;

/**
 * The answer's body as a JSON object: the content type must be a JSON one,
 * the body well-formed UTF-8 and the value an object.
 *
 * @throws UpstreamOidcError `invalid_response` otherwise
 */
export function jsonObjectBody(
  response: AuthMethodEgressResponse,
  purpose: string
): Record<string, unknown> {
  const contentType = response.headers['content-type'];
  if (typeof contentType !== 'string' || !JSON_MEDIA_TYPE.test(contentType)) {
    throw invalidResponse(`${purpose}: the answer is not JSON`);
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(response.body));
  } catch (cause) {
    throw invalidResponse(`${purpose}: the answer is not well-formed JSON`, { cause });
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalidResponse(`${purpose}: the answer is not a JSON object`);
  }
  return value as Record<string, unknown>;
}
