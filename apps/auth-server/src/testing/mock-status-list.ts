import { type KeyObject, sign as signBytes } from 'node:crypto';
import { deflateSync } from 'node:zlib';

import { createTestCertificate, type TestCertificate } from './x509-der';

/**
 * A REFERENCE / MOCK STATUS LIST ISSUER (issues #297, #378).
 *
 * The third party in the E2E ecosystem. `mock-wallet.ts` plays the wallet and
 * the credential issuer; this plays the party that publishes whether those
 * credentials are still live — a Token Status List (draft-14) served as a
 * Status List Token over HTTPS, signed by a certificate chaining to an anchor
 * the deployment configured in `OID4VP_STATUS_LIST_TRUST_ANCHORS`.
 *
 * ## Why it lives here rather than reusing the verifier's fixtures
 *
 * Exactly the argument `mock-wallet.ts` makes, and for the same reason it is
 * worth repeating rather than working around: `libs/server/federation` holds the
 * VERIFIER's attack harness, `apps/auth-server` is `scope:app` and the
 * workspace's module boundaries forbid it from importing `scope:server`
 * libraries at all. A status list issuer is not part of the verifier — it holds
 * keys the verifier never sees, decides what its list says, and speaks to QAuth
 * only over HTTP.
 *
 * That separation is what makes the E2E an INTEROPERABILITY test. `x509-der.ts`
 * and `status/test/x509-fixtures.ts` are independent implementations of the same
 * standard; if QAuth's chain reader and this app's encoder ever disagree, the
 * E2E fails rather than a shared helper absorbing the divergence. The encoder
 * itself moved to `x509-der.ts` with #377 so the app has ONE of them rather than
 * one per fixture — the boundary that buys independence is the app/lib one, and
 * a second copy inside `src/testing/` would buy nothing.
 *
 * ## What is implemented
 *
 * Only what the E2E exercises: the certificates `x509-der.ts` builds; a 2-bit
 * status list; and a compact ES256 JWS. It is a TEST helper and must not become
 * a certificate-issuing or status-publishing utility.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/
 */

/**
 * A built certificate, as this module passes it around.
 *
 * An alias rather than a distinct shape: the members it needs — `pem` for the
 * anchor variable, `x5c` for the token header, `privateKey` to sign with — are
 * exactly what {@link createTestCertificate} returns.
 */
export type MockCertificate = TestCertificate;

// ---------------------------------------------------------- status lists

/** The `typ` a Status List Token carries (draft-14 §5.1). */
const STATUS_LIST_TOKEN_TYP = 'statuslist+jwt';

/** The media type the endpoint must serve it as (draft-14 §6). */
export const STATUS_LIST_MEDIA_TYPE = 'application/statuslist+jwt';

/** Status values draft-14 §7.1 defines, plus one it leaves to the application. */
export const MOCK_STATUS = Object.freeze({
  VALID: 0x00,
  INVALID: 0x01,
  SUSPENDED: 0x02,
  /** Application-specific: a value THIS deployment has no meaning for. */
  UNSPECIFIED: 0x03,
});

/** base64url without padding. */
function b64url(input: Buffer | string): string {
  return Buffer.from(input as never).toString('base64url');
}

/**
 * Pack status values into the draft-14 §4.1 byte array and compress it.
 *
 * Entries are packed from the LEAST significant bit of each byte upward, which
 * is the direction the whole encoding hinges on.
 */
function encodeStatusList(entries: readonly number[], bits: 2): string {
  const entriesPerByte = 8 / bits;
  const bytes = Buffer.alloc(Math.max(1, Math.ceil(entries.length / entriesPerByte)));

  entries.forEach((value, index) => {
    const byteIndex = Math.floor(index / entriesPerByte);
    const shift = (index % entriesPerByte) * bits;
    bytes[byteIndex] = (bytes[byteIndex] as number) | ((value & 0b11) << shift);
  });

  return b64url(deflateSync(bytes));
}

/**
 * Sign a compact ES256 JWS.
 *
 * `dsaEncoding: 'ieee-p1363'` is what makes this a JWS rather than an X.509
 * signature: JOSE ES256 is the raw 64-byte R‖S pair, while `node:crypto`
 * defaults to the DER-wrapped form.
 */
function signCompactJws(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  key: KeyObject
): string {
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const signature = signBytes('sha256', Buffer.from(signingInput, 'ascii'), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${signature.toString('base64url')}`;
}

/** How a mock endpoint should answer, so a suite can express an outage. */
export type MockStatusEndpointBehaviour =
  /** Serve the signed list with the right media type. */
  | { readonly kind: 'ok' }
  /** Answer with an HTTP status other than 200. */
  | { readonly kind: 'http-error'; readonly status: number }
  /** Serve the token with the WRONG `Content-Type` (a captive portal, say). */
  | { readonly kind: 'wrong-media-type' }
  /** Fail the request outright, as a timeout or a refused connection would. */
  | { readonly kind: 'unreachable' };

/** A status list this issuer publishes, plus the levers a test needs. */
export interface MockStatusList {
  /** The `status_list.uri` a credential points at. */
  readonly uri: string;
  /** PEM anchor for `OID4VP_STATUS_LIST_TRUST_ANCHORS`. */
  readonly anchorPem: string;
  /** Prefix for `OID4VP_STATUS_LIST_URI_ALLOWLIST`. */
  readonly uriAllowlistPrefix: string;
  /** The `status` claim a credential at `idx` must carry. */
  statusClaimFor(idx: number): Record<string, unknown>;
  /** Set the published value at `idx` — this is what "revoke" means. */
  setStatus(idx: number, value: number): void;
  /** Change how the endpoint answers. */
  setBehaviour(behaviour: MockStatusEndpointBehaviour): void;
  /** How many times the endpoint has been dialled. */
  readonly requestCount: number;
  /** Reset the counter between scenarios. */
  resetRequestCount(): void;
  /**
   * Serve one request, or return `undefined` when `uri` is not this endpoint.
   *
   * @throws Error when the behaviour is `unreachable` — which is what the
   * platform `fetch` does for a refused connection or an aborted timeout.
   */
  serve(uri: string): Response | undefined;
}

/** What {@link createMockStatusList} may vary. */
export interface CreateMockStatusListOptions {
  /** Host serving the list. Must not be `localhost` or an IP literal. */
  readonly host?: string;
  /** Number of entries the published list holds. */
  readonly size?: number;
}

/**
 * Create a status list issuer: a CA, a signing certificate bound to the
 * endpoint's host, and a published list.
 *
 * The `iss` of every token is `https://<host>`, and the signing certificate
 * carries `<host>` as a `dNSName` SAN — the binding
 * `status-list-chain.ts` requires, without which any holder of an anchored
 * certificate could publish status on behalf of any other issuer.
 */
export function createMockStatusList(options: CreateMockStatusListOptions = {}): MockStatusList {
  const host = options.host ?? 'status.issuer.example';
  const issuer = `https://${host}`;
  const uri = `${issuer}/lists/1`;

  const root = createTestCertificate({ subject: `${host} Root CA`, ca: true });
  const signer = createTestCertificate({ subject: host, issuer: root, dnsNames: [host] });

  const entries = new Array<number>(options.size ?? 64).fill(MOCK_STATUS.VALID);
  let behaviour: MockStatusEndpointBehaviour = { kind: 'ok' };
  let requestCount = 0;

  /** Sign the list as it stands right now, so a revocation takes effect. */
  function token(): string {
    const nowSeconds = Math.floor(Date.now() / 1000);
    return signCompactJws(
      { alg: 'ES256', typ: STATUS_LIST_TOKEN_TYP, x5c: [signer.x5c] },
      {
        iss: issuer,
        sub: uri,
        iat: nowSeconds - 60,
        exp: nowSeconds + 3_600,
        // No `ttl`, so QAuth's own 300 s ceiling decides. A verified list is
        // therefore cached for the LIFETIME OF A DEPLOYMENT here, which is why
        // each scenario below boots its own: mutating `entries` or `behaviour`
        // after a successful check inside one deployment would be answered from
        // that cache, and the suite would assert the wrong thing. The cache is
        // correct and covered by `credential-status-checker.test.ts`.
        status_list: { bits: 2, lst: encodeStatusList(entries, 2) },
      },
      signer.privateKey
    );
  }

  return {
    uri,
    anchorPem: root.pem,
    uriAllowlistPrefix: `${issuer}/lists`,

    statusClaimFor(idx: number): Record<string, unknown> {
      return { status_list: { idx, uri } };
    },

    setStatus(idx: number, value: number): void {
      entries[idx] = value;
    },

    setBehaviour(next: MockStatusEndpointBehaviour): void {
      behaviour = next;
    },

    get requestCount(): number {
      return requestCount;
    },

    resetRequestCount(): void {
      requestCount = 0;
    },

    serve(candidate: string): Response | undefined {
      if (candidate !== uri) return undefined;
      requestCount += 1;

      switch (behaviour.kind) {
        case 'unreachable':
          throw new Error('mock status endpoint is unreachable');
        case 'http-error':
          return new Response('upstream error', { status: behaviour.status });
        case 'wrong-media-type':
          return new Response(token(), { status: 200, headers: { 'content-type': 'text/html' } });
        case 'ok':
        default:
          return new Response(token(), {
            status: 200,
            headers: { 'content-type': STATUS_LIST_MEDIA_TYPE },
          });
      }
    },
  };
}

/**
 * Route the process's `fetch` at a mock status endpoint, passing everything
 * else through.
 *
 * A stub rather than a real listener because the SSRF allowlist refuses
 * `localhost` and IP literals outright (and rightly: they are every classic SSRF
 * target), so a loopback server could not be reached by a correctly-configured
 * deployment at all. Intercepting the transport keeps the URI a plausible public
 * `https://` name while keeping the suite offline.
 *
 * @param lists - endpoints to serve.
 * @returns a restore function; call it in `afterEach`.
 */
export function installMockStatusEndpoints(lists: readonly MockStatusList[]): () => void {
  const original = globalThis.fetch;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const uri = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

    for (const list of lists) {
      const response = list.serve(uri);
      if (response !== undefined) return response;
    }

    return original(input as RequestInfo, init);
  }) as typeof fetch;

  return (): void => {
    globalThis.fetch = original;
  };
}
