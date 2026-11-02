/**
 * The request code of the generated account API client: generic, with no type
 * of the API in it. `generated/account-api.ts` gives each operation its types
 * and calls {@link callOperation}.
 *
 * The client runs on a backend that holds the person's access token, such as
 * the account console's: the account API takes no cookie and sends no CORS
 * headers (ADR-019 Decision 7). It sends the token under the `Bearer` scheme,
 * or under `DPoP` with a proof when the caller gives one (RFC 9449).
 */

/** The access token, or a function that returns the current one. */
export type AccessTokenSource = string | (() => string | Promise<string>);

/** What a DPoP proof is made for: the request's method and its URL without query (RFC 9449 §4.2 `htu`). */
export interface DpopProofInput {
  readonly method: string;
  readonly url: string;
  readonly accessToken: string;
}

/** The part of `fetch` the client uses. */
export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface AccountClientOptions {
  /**
   * The auth server's origin for the realm, such as `https://auth.example.com`:
   * the access token goes there and nowhere else. No trailing slash.
   */
  readonly baseUrl: string;
  /** The person's access token for the account audience. */
  readonly accessToken: AccessTokenSource;
  /**
   * For a DPoP-bound token: a function that signs a proof for one request
   * (`htm`, `htu`, and `ath` from the token). With it the token goes under the
   * `DPoP` scheme and the proof in the `DPoP` header; without it, under
   * `Bearer`.
   */
  readonly dpopProof?: (input: DpopProofInput) => string | Promise<string>;
  /**
   * How to send a request: the backend's own `fetch`, or its egress client's.
   * Required: the client picks no transport of its own, so the backend decides
   * where its outbound traffic goes and how it is checked.
   */
  readonly fetch: FetchLike;
  /** Headers sent with every request. They never replace the client's own. */
  readonly headers?: Readonly<Record<string, string>>;
}

export interface CallInit {
  readonly signal?: AbortSignal;
}

/** What the operation table says about one operation. */
export interface OperationInfo {
  readonly method: string;
  readonly path: string;
  /** The pattern each path parameter must match, from the document. */
  readonly pathPatterns: Readonly<Record<string, string>>;
  /** The names of its query parameters. */
  readonly query: readonly string[];
  /** The names of its header parameters, such as `If-Match`. */
  readonly headers: readonly string[];
  /** The media type of its request body, if it takes one. */
  readonly bodyMediaType: string | undefined;
  readonly freshAuthentication: string;
  readonly actChain: string;
  /** Every status the document declares for it. */
  readonly statuses: readonly number[];
  /** The declared statuses whose answer has no body, such as 204. */
  readonly emptyStatuses: readonly number[];
}

/** What one operation takes: its parameters by location, and its body. */
export interface OperationRequest {
  readonly path?: object;
  readonly query?: object;
  readonly headers?: object;
  readonly body?: unknown;
}

/** The shape every operation of the generated `Operations` table has. */
export interface OperationShape {
  readonly request: OperationRequest;
  readonly responses: object;
}

/** One answer of an operation: a status the document declares, its body, and the raw response. */
export type OperationResult<O extends OperationShape> = {
  [S in keyof O['responses']]: {
    readonly status: S;
    readonly data: O['responses'][S];
    readonly response: Response;
  };
}[keyof O['responses']];

/**
 * An answer with a status the document does not declare for the operation,
 * such as a proxy's 502, or a redirect, which the API never sends. The client
 * does not guess at its body, and never follows a redirect: the token would go
 * with it.
 */
export class UnexpectedStatusError extends Error {
  readonly status: number;
  readonly response: Response;

  constructor(operation: OperationInfo, response: Response) {
    super(
      `${operation.method} ${operation.path} answered ${response.status}, which the document does not declare`
    );
    this.name = 'UnexpectedStatusError';
    this.status = response.status;
    this.response = response;
  }
}

/**
 * An answer with a declared status whose body is not the JSON document the
 * status promises, such as a proxy's HTML page under 413 or 503. The client
 * does not hand back a body of the wrong type.
 */
export class UnexpectedBodyError extends Error {
  readonly status: number;
  readonly response: Response;

  constructor(operation: OperationInfo, response: Response, reason: string) {
    super(`${operation.method} ${operation.path} answered ${response.status} with ${reason}`);
    this.name = 'UnexpectedBodyError';
    this.status = response.status;
    this.response = response;
  }
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Check `baseUrl` once: an origin under `https` (plain `http` only on a
 * loopback host, for development), with no user, path, query or fragment, so
 * the token cannot go in clear or to a path the API does not serve.
 *
 * @throws TypeError for any other value
 */
export function checkBaseUrl(baseUrl: string): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new TypeError('baseUrl is not a URL');
  }
  const secure =
    url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname));
  if (!secure) throw new TypeError('baseUrl must use https, or http on a loopback host');
  if (url.username !== '' || url.password !== '') {
    throw new TypeError('baseUrl must not carry a user or a password');
  }
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '' || /[?#]$/.test(baseUrl)) {
    throw new TypeError('baseUrl must be an origin, with no path, query or fragment');
  }
  return url.origin;
}

/**
 * Replace each `{name}` of `path` with its parameter, which must match the
 * pattern the document gives it, so a value such as `..` or `../deletion`
 * cannot send the request, and the token, to another path.
 */
export function expandPath(
  path: string,
  params: object | undefined,
  patterns: Readonly<Record<string, string>>
): string {
  return path.replace(/\{([^}]+)\}/g, (_match, name: string) => {
    const value = (params as Record<string, unknown> | undefined)?.[name];
    const pattern = patterns[name];
    if (
      typeof value !== 'string' ||
      pattern === undefined ||
      !new RegExp(pattern, 'u').test(value)
    ) {
      throw new TypeError(`the path parameter ${name} is missing or malformed`);
    }
    return encodeURIComponent(value);
  });
}

/** The query string of the declared parameters that have a value, in the document's order. */
export function queryString(names: readonly string[], query: object | undefined): string {
  const search = new URLSearchParams();
  for (const name of names) {
    const value = (query as Record<string, unknown> | undefined)?.[name];
    if (value === undefined || value === null) continue;
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') {
      throw new TypeError(`the query parameter ${name} is not a scalar`);
    }
    search.append(name, String(value));
  }
  const text = search.toString();
  return text === '' ? '' : `?${text}`;
}

/** The declared header parameters that have a value. */
function headerParameters(names: readonly string[], headers: object | undefined) {
  const out: Record<string, string> = {};
  for (const name of names) {
    const value = (headers as Record<string, unknown> | undefined)?.[name];
    if (value === undefined) continue;
    if (typeof value !== 'string') throw new TypeError(`the header ${name} is not a string`);
    out[name.toLowerCase()] = value;
  }
  return out;
}

const isJson = (contentType: string | null) =>
  contentType !== null && /^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/i.test(contentType);

const OWN_HEADERS = new Set(['accept', 'authorization', 'content-type', 'dpop', 'if-match']);

/** Send one operation and read its answer. */
export async function callOperation<O extends OperationShape>(
  options: AccountClientOptions,
  operation: OperationInfo,
  request: O['request'],
  init?: CallInit
): Promise<OperationResult<O>> {
  const target = `${checkBaseUrl(options.baseUrl)}${expandPath(operation.path, request.path, operation.pathPatterns)}`;
  const url = `${target}${queryString(operation.query, request.query)}`;
  const accessToken =
    typeof options.accessToken === 'function' ? await options.accessToken() : options.accessToken;
  const hasBody = operation.bodyMediaType !== undefined && request.body !== undefined;
  const headers: Record<string, string> = Object.fromEntries(
    Object.entries(options.headers ?? {}).filter(([name]) => !OWN_HEADERS.has(name.toLowerCase()))
  );
  headers['accept'] = 'application/json, application/problem+json';
  if (hasBody) headers['content-type'] = operation.bodyMediaType as string;
  Object.assign(headers, headerParameters(operation.headers, request.headers));
  if (options.dpopProof === undefined) {
    headers['authorization'] = `Bearer ${accessToken}`;
  } else {
    headers['authorization'] = `DPoP ${accessToken}`;
    headers['dpop'] = await options.dpopProof({
      method: operation.method,
      url: target,
      accessToken,
    });
  }
  const response = await options.fetch(url, {
    method: operation.method,
    // Server to server: no cookie, and never a redirect, which would carry the token on.
    credentials: 'omit',
    redirect: 'manual',
    headers,
    ...(hasBody ? { body: JSON.stringify(request.body) } : {}),
    ...(init?.signal === undefined ? {} : { signal: init.signal }),
  });
  if (!operation.statuses.includes(response.status)) {
    throw new UnexpectedStatusError(operation, response);
  }
  if (operation.emptyStatuses.includes(response.status)) {
    return { status: response.status, data: undefined, response } as OperationResult<O>;
  }
  if (!isJson(response.headers.get('content-type'))) {
    throw new UnexpectedBodyError(operation, response, 'a body that is not JSON');
  }
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw new UnexpectedBodyError(operation, response, 'a JSON body that does not parse');
  }
  return { status: response.status, data, response } as OperationResult<O>;
}
