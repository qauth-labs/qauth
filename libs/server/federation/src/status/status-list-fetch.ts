import type { ClientRequest, IncomingMessage } from 'node:http';
import https from 'node:https';
import { gunzipSync } from 'node:zlib';

import { MAX_STATUS_LIST_TOKEN_BYTES, STATUS_LIST_TOKEN_MEDIA_TYPE } from './status-list-spec';

/**
 * The outbound HTTP seam of the status path (draft-14 §6, issue #297).
 *
 * ## A seam, because the network is the part that must be faked
 *
 * Every interesting behaviour of status checking — an endpoint that is down,
 * one that returns HTML, one that hangs, one that serves a token signed by the
 * wrong key — is a property of the RESPONSE. Making the fetch a function the
 * caller supplies is what lets all of that be tested deterministically, and it
 * is what lets a deployment substitute an agent with its own proxy, DNS pinning
 * or mTLS without this module knowing.
 *
 * ## The default implementation refuses redirects
 *
 * A 3xx is not a 200, and nothing is followed. The URI has already passed an
 * operator allowlist (`status-list-uri.ts`); a redirect is the cheapest way to
 * leave it, and following one would mean re-running the allowlist per hop. An
 * issuer that needs to move a status list can publish the new URI in the
 * credential — the URI is per-credential data, not a deployment constant — so
 * refusing redirects costs nothing real and closes the SSRF bypass that would
 * otherwise make the allowlist decorative.
 *
 * The residual gap is DNS rebinding: an allowlisted hostname that resolves to a
 * private address. Closing it needs a socket-level check inside the HTTP agent,
 * which a pure `scope:server` library has no access to. A deployment that needs
 * that protection supplies its own {@link StatusListFetch} over an agent that
 * pins resolved addresses. This is stated here rather than left implicit
 * because a reader could otherwise reasonably conclude the allowlist is a
 * complete SSRF defence.
 *
 * ## The default implementation is `node:https`, not the platform `fetch`
 *
 * `fetch` resolves on the headers, with the body still arriving on a live
 * socket. A response that is refused at that point — here for its status or
 * media type, or inside `fetch` itself for a redirect, a 421 or its
 * `Content-Encoding` — leaves a body nobody reads, and Node's `fetch` pauses its
 * parser once 64 KiB of it are buffered. A peer that closes while the parser is
 * paused fails an assertion in a socket event handler, outside every promise
 * and every `try`, and the PROCESS exits: one 404 with a large error page takes
 * the authorization server down. Only some of those responses ever reach the
 * caller to be cancelled. Here each exchange owns its socket, and every way out
 * of the exchange destroys it.
 */

/** What the orchestrator asks the transport to do. */
export interface StatusListFetchRequest {
  /** The status list URI — already allowlisted by the caller. */
  readonly uri: string;
  /** Abort budget for the whole exchange, in milliseconds. */
  readonly timeoutMs: number;
}

/**
 * The transport's answer.
 *
 * Deliberately binary. HTTP status codes, error messages and timing are NOT
 * surfaced: the caller turns any failure into the same refusal anyway, and a
 * richer result would invite a call site that branches on it — which is how a
 * status endpoint's 404 becomes distinguishable from its 500 in QAuth's own
 * responses.
 */
export type StatusListFetchResult =
  { readonly outcome: 'ok'; readonly token: string } | { readonly outcome: 'failed' };

/** The transport seam. Implementations must never throw. */
export type StatusListFetch = (request: StatusListFetchRequest) => Promise<StatusListFetchResult>;

/** 1xx responses tolerated ahead of the final one (e.g. 103 Early Hints). */
const MAX_INTERIM_RESPONSES = 3;

/** Whether a `Content-Type` header names the Status List Token media type. */
function isStatusListMediaType(contentType: string | undefined): boolean {
  if (contentType === undefined) return false;
  // Strip parameters (`;charset=...`) and normalise case and whitespace.
  const [type] = contentType.split(';');
  return (type ?? '').trim().toLowerCase() === STATUS_LIST_TOKEN_MEDIA_TYPE;
}

/**
 * Undo the response's `Content-Encoding` under the same byte bound as the read.
 *
 * draft-14 §8.2 says the response SHOULD be gzip-encoded, so the request offers
 * `gzip`, and `gzip` or no coding at all is what is accepted.
 *
 * @returns the decoded body, or `undefined` for any other coding, a stream that
 * is not gzip, or one that would inflate past the bound.
 */
function decodeBody(body: Buffer, contentEncoding: string | undefined): Buffer | undefined {
  const coding = (contentEncoding ?? 'identity').trim().toLowerCase();
  if (coding === 'identity') return body;
  if (coding !== 'gzip') return undefined;
  try {
    return gunzipSync(body, { maxOutputLength: MAX_STATUS_LIST_TOKEN_BYTES });
  } catch {
    return undefined;
  }
}

/**
 * Read a response body under a hard byte bound.
 *
 * Counted chunk by chunk rather than on the assembled body, because a bound
 * applied to the result is applied after the allocation it was supposed to
 * prevent. Here the read ABORTS the moment the running total passes the limit.
 *
 * @param done - called with the body as UTF-8, or with `undefined` when it
 * exceeded the bound or could not be decoded. Not called when the stream fails:
 * that is the response's `error` event.
 */
function readBoundedBody(
  response: IncomingMessage,
  done: (body: string | undefined) => void
): void {
  const declaredLength = Number(response.headers['content-length'] ?? Number.NaN);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_STATUS_LIST_TOKEN_BYTES) {
    done(undefined);
    return;
  }

  const chunks: Buffer[] = [];
  let total = 0;

  response.on('data', (chunk: Buffer) => {
    total += chunk.byteLength;
    if (total > MAX_STATUS_LIST_TOKEN_BYTES) {
      done(undefined);
      return;
    }
    chunks.push(chunk);
  });
  response.on('end', () => {
    done(decodeBody(Buffer.concat(chunks), response.headers['content-encoding'])?.toString('utf8'));
  });
}

/**
 * Build the default HTTPS transport for Status List Tokens (#297).
 *
 * Applies, in order: a deadline for the whole exchange, `Accept:
 * application/statuslist+jwt`, no redirects, a 200-only status check, a
 * `Content-Type` check, and a bounded body read.
 *
 * The `Content-Type` check is not pedantry. Without it, an endpoint that
 * answers with an HTML captive-portal page, an authentication redirect body, or
 * a JSON error object hands that text to the JWS parser, and every subsequent
 * failure is reported as "unverifiable token" — which is true but useless, and
 * hides a misconfiguration behind a security refusal.
 *
 * Never throws: a transport that threw would surface network conditions as
 * uncontained faults on the login path.
 *
 * @param requestImpl - injectable `request`, defaulting to `node:https`'s,
 * looked up per exchange so a harness that intercepts `https.request` reaches
 * the default transport too.
 * @returns a {@link StatusListFetch}.
 */
export function createHttpsStatusListFetch(requestImpl?: typeof https.request): StatusListFetch {
  return ({ uri, timeoutMs }: StatusListFetchRequest): Promise<StatusListFetchResult> =>
    new Promise((resolve) => {
      let req: ClientRequest;
      try {
        req = (requestImpl ?? https.request)(uri, {
          method: 'GET',
          // A socket of its own, closed with the exchange: none is left in a pool
          // for the endpoint to keep writing to.
          agent: false,
          headers: {
            accept: STATUS_LIST_TOKEN_MEDIA_TYPE,
            'accept-encoding': 'gzip',
            'user-agent': 'qauth-status-list-resolver',
          },
        });
      } catch {
        // Not a URL, or not an `https:` one.
        resolve({ outcome: 'failed' });
        return;
      }

      // The only way out. A refusal must not walk away from a response that is
      // still arriving, so it takes the socket with it. Repeat calls are no-ops.
      const finish = (result: StatusListFetchResult): void => {
        clearTimeout(deadline);
        req.destroy();
        resolve(result);
      };
      const fail = (): void => finish({ outcome: 'failed' });

      // A deadline for the whole exchange, NOT `req.setTimeout()`: that is a
      // socket idle timer, which every byte from the endpoint restarts.
      const deadline = setTimeout(fail, timeoutMs);

      req.on('response', (response) => {
        response.on('error', fail);

        if (
          response.statusCode !== 200 ||
          !isStatusListMediaType(response.headers['content-type'])
        ) {
          fail();
          return;
        }

        readBoundedBody(response, (body) => {
          const token = body?.trim();
          if (token === undefined || token.length === 0) {
            fail();
            return;
          }
          finish({ outcome: 'ok', token });
        });
      });
      // 1xx responses never reach `response`, so the byte bound does not see them.
      let interimResponses = 0;
      req.on('information', () => {
        interimResponses += 1;
        if (interimResponses > MAX_INTERIM_RESPONSES) fail();
      });
      req.on('error', fail);
      // Node drops the socket without a `response` or an `error` on, e.g., an
      // unsolicited 101 upgrade.
      req.on('close', fail);
      req.end();
    });
}
