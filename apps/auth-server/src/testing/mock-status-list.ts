import {
  generateKeyPairSync,
  type KeyObject,
  sign as signBytes,
  X509Certificate,
} from 'node:crypto';
import { deflateSync } from 'node:zlib';

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
 * That separation is what makes the E2E an INTEROPERABILITY test. The DER below
 * and `status/test/x509-fixtures.ts` are independent implementations of the same
 * standard; if QAuth's chain reader and this encoder ever disagree, the E2E
 * fails rather than a shared helper absorbing the divergence.
 *
 * ## What is implemented
 *
 * Only what the E2E exercises: ECDSA P-256 keys, `ecdsa-with-SHA256`, a
 * single-CN name, a validity window, `basicConstraints` and `dNSName` SANs; a
 * 2-bit status list; and a compact ES256 JWS. It is a TEST helper and must not
 * become a certificate-issuing or status-publishing utility.
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/
 */

// ------------------------------------------------------------------- DER

/** ASN.1 tag numbers used below. */
const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  UTC_TIME: 0x17,
} as const;

/** Encode a DER length header. */
function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Wrap `content` in a DER TLV with the given tag. */
function der(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

/** A context-specific constructed `[n]` wrapper. */
function contextConstructed(n: number, content: Buffer): Buffer {
  return der(0xa0 | n, content);
}

/** DER INTEGER from a non-negative JS integer. */
function derInteger(value: number): Buffer {
  const bytes: number[] = [];
  let remaining = value;
  do {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  } while (remaining > 0);
  // A leading bit of 1 would make the INTEGER negative.
  if (((bytes[0] as number) & 0x80) !== 0) bytes.unshift(0x00);
  return der(TAG.INTEGER, Buffer.from(bytes));
}

/** Encode a dotted OID string as DER. */
function derOid(dotted: string): Buffer {
  const parts = dotted.split('.').map((part) => Number.parseInt(part, 10));
  const bytes: number[] = [(parts[0] as number) * 40 + (parts[1] as number)];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [part & 0x7f];
    let remaining = part >> 7;
    while (remaining > 0) {
      chunk.unshift((remaining & 0x7f) | 0x80);
      remaining >>= 7;
    }
    bytes.push(...chunk);
  }
  return der(TAG.OID, Buffer.from(bytes));
}

/** `AlgorithmIdentifier` for `ecdsa-with-SHA256` (no parameters). */
function ecdsaWithSha256(): Buffer {
  return der(TAG.SEQUENCE, derOid('1.2.840.10045.4.3.2'));
}

/** A `Name` holding a single CN. */
function commonName(value: string): Buffer {
  const attribute = der(
    TAG.SEQUENCE,
    Buffer.concat([derOid('2.5.4.3'), der(TAG.UTF8_STRING, Buffer.from(value, 'utf8'))])
  );
  return der(TAG.SEQUENCE, der(TAG.SET, attribute));
}

/** `UTCTime` as `YYMMDDHHMMSSZ`. */
function utcTime(date: Date): Buffer {
  const pad = (n: number): string => n.toString().padStart(2, '0');
  const text =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z';
  return der(TAG.UTC_TIME, Buffer.from(text, 'ascii'));
}

/** A single X.509 v3 extension. */
function extension(oid: string, critical: boolean, value: Buffer): Buffer {
  return der(
    TAG.SEQUENCE,
    Buffer.concat([
      derOid(oid),
      ...(critical ? [der(TAG.BOOLEAN, Buffer.from([0xff]))] : []),
      der(TAG.OCTET_STRING, value),
    ])
  );
}

/** `basicConstraints`; `cA` is omitted when false, per DER DEFAULT rules. */
function basicConstraints(isCa: boolean): Buffer {
  return extension(
    '2.5.29.19',
    true,
    der(TAG.SEQUENCE, isCa ? der(TAG.BOOLEAN, Buffer.from([0xff])) : Buffer.alloc(0))
  );
}

/** `subjectAltName` holding `dNSName` entries (`[2] IMPLICIT IA5String`). */
function subjectAltName(dnsNames: readonly string[]): Buffer {
  return extension(
    '2.5.29.17',
    false,
    der(
      TAG.SEQUENCE,
      Buffer.concat(dnsNames.map((name) => der(0x80 | 2, Buffer.from(name, 'ascii'))))
    )
  );
}

// ----------------------------------------------------------- certificates

/** A built certificate and everything a test needs to use it. */
export interface MockCertificate {
  /** PEM form — what an operator puts in `OID4VP_STATUS_LIST_TRUST_ANCHORS`. */
  readonly pem: string;
  /** Standard-alphabet base64 DER, i.e. an `x5c` entry. */
  readonly x5c: string;
  readonly privateKey: KeyObject;
  readonly subject: string;
}

/** What {@link createMockCertificate} may vary. */
interface CreateMockCertificateOptions {
  readonly subject: string;
  /** Issuer; omit for a self-signed certificate. */
  readonly issuer?: MockCertificate;
  readonly ca?: boolean;
  readonly dnsNames?: readonly string[];
}

let nextSerial = 1;

/** Build a signed X.509 v3 certificate. */
function createMockCertificate(options: CreateMockCertificateOptions): MockCertificate {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const notBefore = new Date(Date.now() - 3_600_000);
  const notAfter = new Date(Date.now() + 30 * 24 * 3_600_000);

  const extensions: Buffer[] = [basicConstraints(options.ca === true)];
  if (options.dnsNames !== undefined && options.dnsNames.length > 0) {
    extensions.push(subjectAltName(options.dnsNames));
  }

  const tbs = der(
    TAG.SEQUENCE,
    Buffer.concat([
      contextConstructed(0, derInteger(2)),
      derInteger(nextSerial++),
      ecdsaWithSha256(),
      commonName(options.issuer?.subject ?? options.subject),
      der(TAG.SEQUENCE, Buffer.concat([utcTime(notBefore), utcTime(notAfter)])),
      commonName(options.subject),
      Buffer.from(publicKey.export({ type: 'spki', format: 'der' })),
      contextConstructed(3, der(TAG.SEQUENCE, Buffer.concat(extensions))),
    ])
  );

  const signature = signBytes('sha256', tbs, options.issuer?.privateKey ?? privateKey);

  const certificateDer = der(
    TAG.SEQUENCE,
    Buffer.concat([
      tbs,
      ecdsaWithSha256(),
      der(TAG.BIT_STRING, Buffer.concat([Buffer.from([0x00]), signature])),
    ])
  );

  return {
    pem: new X509Certificate(certificateDer).toString(),
    x5c: certificateDer.toString('base64'),
    privateKey,
    subject: options.subject,
  };
}

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

  const root = createMockCertificate({ subject: `${host} Root CA`, ca: true });
  const signer = createMockCertificate({ subject: host, issuer: root, dnsNames: [host] });

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
