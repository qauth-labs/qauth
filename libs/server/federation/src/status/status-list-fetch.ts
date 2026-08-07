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
 * `redirect: 'error'`. The URI has already passed an operator allowlist
 * (`status-list-uri.ts`); a redirect is the cheapest way to leave it, and
 * following one would mean re-running the allowlist per hop, which the platform
 * `fetch` gives no hook for. An issuer that needs to move a status list can
 * publish the new URI in the credential — the URI is per-credential data, not a
 * deployment constant — so refusing redirects costs nothing real and closes the
 * SSRF bypass that would otherwise make the allowlist decorative.
 *
 * The residual gap is DNS rebinding: an allowlisted hostname that resolves to a
 * private address. Closing it needs a socket-level check inside the HTTP agent,
 * which a pure `scope:server` library has no access to. A deployment that needs
 * that protection supplies its own {@link StatusListFetch} over an agent that
 * pins resolved addresses. This is stated here rather than left implicit
 * because a reader could otherwise reasonably conclude the allowlist is a
 * complete SSRF defence.
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

/** Whether a `Content-Type` header names the Status List Token media type. */
function isStatusListMediaType(contentType: string | null): boolean {
  if (contentType === null) return false;
  // Strip parameters (`;charset=...`) and normalise case and whitespace.
  const [type] = contentType.split(';');
  return (type ?? '').trim().toLowerCase() === STATUS_LIST_TOKEN_MEDIA_TYPE;
}

/**
 * Read a response body under a hard byte bound.
 *
 * Streamed rather than `await response.text()`, because `text()` buffers the
 * whole body first — so a bound applied to its result is applied after the
 * allocation it was supposed to prevent. Here the read ABORTS the moment the
 * running total passes the limit.
 *
 * @returns the body as UTF-8, or `undefined` when it exceeded the bound or the
 * stream failed.
 */
async function readBoundedBody(response: Response): Promise<string | undefined> {
  const declaredLength = Number(response.headers.get('content-length') ?? Number.NaN);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_STATUS_LIST_TOKEN_BYTES) {
    return undefined;
  }

  const body = response.body;
  if (body === null) return undefined;

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done === true) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > MAX_STATUS_LIST_TOKEN_BYTES) {
        await reader.cancel();
        return undefined;
      }
      chunks.push(value);
    }
  } catch {
    return undefined;
  }

  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString('utf8');
}

/**
 * Build the default HTTPS transport for Status List Tokens (#297).
 *
 * Applies, in order: an abort timeout, `Accept:
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
 * @param fetchImpl - injectable `fetch`, defaulting to the platform global.
 * @returns a {@link StatusListFetch}.
 */
export function createHttpsStatusListFetch(fetchImpl: typeof fetch = fetch): StatusListFetch {
  return async ({ uri, timeoutMs }: StatusListFetchRequest): Promise<StatusListFetchResult> => {
    let response: Response;
    try {
      response = await fetchImpl(uri, {
        method: 'GET',
        redirect: 'error',
        headers: { accept: STATUS_LIST_TOKEN_MEDIA_TYPE },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      return { outcome: 'failed' };
    }

    if (response.status !== 200) return { outcome: 'failed' };
    if (!isStatusListMediaType(response.headers.get('content-type'))) {
      return { outcome: 'failed' };
    }

    const token = await readBoundedBody(response);
    if (token === undefined || token.trim().length === 0) return { outcome: 'failed' };

    return { outcome: 'ok', token: token.trim() };
  };
}
