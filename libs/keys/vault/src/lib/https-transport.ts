import { Agent, request as httpsRequest } from 'node:https';

/**
 * One HTTPS exchange with Vault (ADR-019 Decision 9, #578).
 *
 * A port, so the provider's tests run against a Vault test double and only
 * `https-transport.test.ts` and the dev-server suite open connections.
 *
 * Vault's address is an operator setting, never user input, so the egress
 * client that guards user-supplied URLs does not apply here. What the
 * transport does instead:
 *
 * - TLS always, with certificate and host name checks that cannot be turned
 *   off. `KEK_VAULT_CA_CERT_FILE` replaces Node's CA store for these calls.
 * - One deadline per request, connection and TLS handshake included, so a
 *   Vault that stops answering fails the call instead of holding the signer.
 * - A cap on the answer's size; a larger answer is dropped unread.
 * - Redirects are not followed: a request carries a token, which must reach
 *   no other host. A standby that answers with a redirect fails the attempt.
 */

/** A request to Vault. The client adds every header. */
export interface VaultHttpRequest {
  readonly method: 'GET' | 'POST';
  /** The request path, starting with `/v1/`. */
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  /** The JSON body, for a POST. */
  readonly body?: string;
}

/** Vault's answer. */
export interface VaultHttpResponse {
  readonly status: number;
  /** The parsed JSON body, or `undefined` when there was none or it was not JSON. */
  readonly body: unknown;
}

/** Sends one request and resolves with Vault's answer, whatever its status. */
export type VaultTransport = (request: VaultHttpRequest) => Promise<VaultHttpResponse>;

/** The longest one request may take, connecting included, in ms. */
export const VAULT_REQUEST_TIMEOUT_MS = 5_000;

/** The largest answer read, in bytes. A Transit or token answer is well under 4 KiB. */
export const MAX_RESPONSE_BYTES = 64 * 1024;

/** What {@link createHttpsTransport} needs. */
export interface HttpsTransportOptions {
  /** The Vault origin, `https://host[:port]`. */
  readonly origin: string;
  /** PEM CA certificates to trust instead of Node's defaults. */
  readonly ca?: string;
  /** Replaces {@link VAULT_REQUEST_TIMEOUT_MS}, for tests. */
  readonly timeoutMs?: number;
}

/** Why a request failed without an answer, with a code like Node's own. */
class TransportFailure extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'TransportFailure';
    this.code = code;
  }
}

function parseJson(bytes: Buffer): unknown {
  if (bytes.length === 0) return undefined;
  try {
    return JSON.parse(bytes.toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * The transport to the Vault server at `origin`.
 *
 * Connections are kept alive between calls. Node unreferences an idle kept
 * socket, so it never holds the process open.
 */
export function createHttpsTransport(options: HttpsTransportOptions): VaultTransport {
  const url = new URL(options.origin);
  if (url.protocol !== 'https:') throw new TypeError('The Vault transport speaks https only');
  // `URL` keeps the brackets of an IPv6 literal; the socket wants the address.
  const hostname = url.hostname.replace(/^\[(.*)\]$/, '$1');
  const port = url.port === '' ? 443 : Number(url.port);
  const timeoutMs = options.timeoutMs ?? VAULT_REQUEST_TIMEOUT_MS;
  const agent = new Agent({
    keepAlive: true,
    maxSockets: 16,
    ...(options.ca !== undefined ? { ca: options.ca } : {}),
  });

  return (request) =>
    new Promise<VaultHttpResponse>((resolve, reject) => {
      let settled = false;
      const settle = (outcome: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        outcome();
      };

      const headers: Record<string, string | number> = {
        ...request.headers,
        accept: 'application/json',
      };
      if (request.body !== undefined) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(request.body);
      }

      const outgoing = httpsRequest(
        {
          protocol: 'https:',
          hostname,
          port,
          method: request.method,
          path: request.path,
          headers,
          agent,
          rejectUnauthorized: true,
        },
        (response) => {
          const chunks: Buffer[] = [];
          let size = 0;
          response.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_RESPONSE_BYTES) {
              fail(
                new TransportFailure(
                  'ERR_VAULT_RESPONSE_TOO_LARGE',
                  `Vault's answer is larger than ${MAX_RESPONSE_BYTES} bytes`
                )
              );
              return;
            }
            chunks.push(chunk);
          });
          response.on('end', () =>
            settle(() =>
              resolve({ status: response.statusCode ?? 0, body: parseJson(Buffer.concat(chunks)) })
            )
          );
          response.on('error', (error) => settle(() => reject(error)));
        }
      );

      /** Reject now and drop the connection; its own later errors find the call settled. */
      const fail = (failure: Error) => {
        settle(() => reject(failure));
        outgoing.destroy(failure);
      };

      const deadline = setTimeout(
        () =>
          fail(new TransportFailure('ETIMEDOUT', `Vault did not answer within ${timeoutMs} ms`)),
        timeoutMs
      );

      outgoing.on('error', (error) => settle(() => reject(error)));
      outgoing.end(request.body);
    });
}
