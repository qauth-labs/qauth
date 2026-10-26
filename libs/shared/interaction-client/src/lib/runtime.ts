/**
 * The request code of the generated Interaction API client: generic, with no
 * type of the API in it. `generated/interaction-api.ts` gives each operation
 * its types and calls {@link callOperation}.
 *
 * The client speaks JSON only. A page without JavaScript posts its forms
 * straight to the auth server; it does not go through a client.
 */

export interface InteractionClientOptions {
  /**
   * The origin the API is served on, such as `https://auth.example.com`. Leave
   * it out in a browser: the API is same-origin.
   */
  readonly baseUrl?: string;
  /** The `fetch` to use. Defaults to the global one. */
  readonly fetch?: typeof fetch;
  /** Headers sent with every request. */
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
  readonly flowCookie: boolean;
  readonly csrf: boolean;
  /** Every status the document declares for it. */
  readonly statuses: readonly number[];
}

/** The shape every operation of the generated `Operations` table has. */
export interface OperationShape {
  readonly pathParams: object;
  readonly requestBody: unknown;
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
 * such as a proxy's 502, or a redirect a JSON request should never get. The
 * client does not guess at its body.
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
 * A redirect a JSON request got. The server sends `303 See Other` only to a
 * form post, so a JSON request never gets one; the client never follows it.
 * A browser hides such a redirect from `fetch` with `redirect: 'manual'` (an
 * `opaqueredirect` response with status 0), so the client says so here
 * instead of reporting status 0.
 */
export class UnexpectedRedirectError extends UnexpectedStatusError {
  constructor(operation: OperationInfo, response: Response) {
    super(operation, response);
    this.name = 'UnexpectedRedirectError';
    this.message = `${operation.method} ${operation.path} answered with a redirect, which a JSON request never gets`;
  }
}

/**
 * Replace each `{name}` of `path` with its parameter, which must match the
 * pattern the document gives it. The id comes from the page's own URL, which
 * anyone can link to: a value such as `..` or `../answer` would otherwise send
 * the request, and what it carries, to another path of the origin.
 */
export function expandPath(
  path: string,
  params: object,
  patterns: Readonly<Record<string, string>>
): string {
  return path.replace(/\{([^}]+)\}/g, (_match, name: string) => {
    const value = (params as Record<string, unknown>)[name];
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

const isJson = (contentType: string | null) =>
  contentType !== null && /^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/i.test(contentType);

/** Send one operation and read its answer. */
export async function callOperation<O extends OperationShape>(
  options: InteractionClientOptions,
  operation: OperationInfo,
  pathParams: O['pathParams'],
  body: O['requestBody'] | undefined,
  init?: CallInit
): Promise<OperationResult<O>> {
  const send = options.fetch ?? fetch;
  const url = `${options.baseUrl ?? ''}${expandPath(operation.path, pathParams, operation.pathPatterns)}`;
  const response = await send(url, {
    method: operation.method,
    // Same-origin by design: the flow cookie travels only to the realm origin.
    credentials: 'same-origin',
    // A JSON answer never redirects; a 303 is for form posts. Never follow one.
    redirect: 'manual',
    headers: {
      accept: 'application/json, application/problem+json',
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...options.headers,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    ...(init?.signal === undefined ? {} : { signal: init.signal }),
  });
  if (response.type === 'opaqueredirect') throw new UnexpectedRedirectError(operation, response);
  if (!operation.statuses.includes(response.status)) {
    throw new UnexpectedStatusError(operation, response);
  }
  const data = isJson(response.headers.get('content-type')) ? await response.json() : undefined;
  return { status: response.status, data, response } as OperationResult<O>;
}
