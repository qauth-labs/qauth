import { randomBytes } from 'node:crypto';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import { type AddressInfo, createServer as createTcpServer, type Socket } from 'node:net';

import { type DecryptCommandInput, type EncryptCommandInput, KMSClient } from '@aws-sdk/client-kms';
import { isKeyCustodyError } from '@qauth-labs/server-keys';
import {
  KEY_AAD_VERSION,
  type KeyAad,
  runKekProviderContract,
} from '@qauth-labs/server-keys/custody';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createKmsDouble, DOUBLE_KEY_ARN, type KmsDouble } from '../testing/kms-double';
import { createAwsKmsKekProvider, createKekProvider } from './aws-kms-kek-provider';
import {
  KMS_CONNECTION_TIMEOUT_MS,
  KMS_MAX_ATTEMPTS,
  KMS_REQUEST_TIMEOUT_MS,
  kmsClientConfig,
  kmsOperationsOf,
} from './kms-client';

/**
 * The real SDK client, as `createKekProvider` builds it, against a local
 * server that speaks KMS's JSON protocol (awsJson1_1) and serves the KMS test
 * double. It checks what the double alone cannot: the attempt limit, which
 * failures are retried, the default credential chain and the timeouts.
 *
 * The SDK reads the endpoint from `AWS_ENDPOINT_URL_KMS` and the credentials
 * from `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, the first source of
 * its default chain, so the provider is created exactly as in production.
 */

const ACCESS_KEY_ID = 'AKIDQAUTHKMSTEST0001';

const AAD: KeyAad = Object.freeze({
  realmId: 'realm-a',
  purpose: 'token_signing',
  scopeId: null,
  kid: 'kid-1',
  algorithm: 'EdDSA',
  version: KEY_AAD_VERSION,
});

/** What the server answers: the double, or one KMS exception every time. */
type Mode = { readonly kind: 'double' } | { readonly kind: 'fail'; readonly name: string };

interface ReceivedRequest {
  readonly target: string | undefined;
  readonly headers: IncomingHttpHeaders;
  readonly body: Record<string, unknown>;
}

const BLOB_FIELDS = ['Plaintext', 'CiphertextBlob'];

/** A request body with its blobs decoded, as the double takes it. */
function decodeBlobs<T>(body: Record<string, unknown>): T {
  const decoded = { ...body };
  for (const field of BLOB_FIELDS) {
    if (typeof decoded[field] === 'string') {
      decoded[field] = new Uint8Array(Buffer.from(decoded[field] as string, 'base64'));
    }
  }
  return decoded as T;
}

function encodeBlobs(output: Record<string, unknown>): Record<string, unknown> {
  const encoded: Record<string, unknown> = {};
  for (const [field, value] of Object.entries(output)) {
    if (field === '$metadata') continue;
    encoded[field] = value instanceof Uint8Array ? Buffer.from(value).toString('base64') : value;
  }
  return encoded;
}

let server: Server;
let endpoint: string;
let kms: KmsDouble;
let mode: Mode;
let received: ReceivedRequest[];

beforeAll(async () => {
  server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      const target = request.headers['x-amz-target'] as string | undefined;
      received.push({ target, headers: request.headers, body });

      const fail = (name: string, status: number) => {
        response.writeHead(status, {
          'content-type': 'application/x-amz-json-1.1',
          'x-amzn-errortype': name,
        });
        response.end(JSON.stringify({ __type: name, message: `${name} from the test server` }));
      };
      if (mode.kind === 'fail') {
        fail(mode.name, mode.name === 'KMSInternalException' ? 500 : 400);
        return;
      }
      const operation =
        target === 'TrentService.Encrypt'
          ? kms.encrypt(decodeBlobs<EncryptCommandInput>(body))
          : target === 'TrentService.Decrypt'
            ? kms.decrypt(decodeBlobs<DecryptCommandInput>(body))
            : Promise.reject(
                Object.assign(new Error('unknown'), { name: 'UnknownOperationException' })
              );
      operation.then(
        (output) => {
          response.writeHead(200, { 'content-type': 'application/x-amz-json-1.1' });
          response.end(JSON.stringify(encodeBlobs(output as unknown as Record<string, unknown>)));
        },
        (error: Error) => fail(error.name, 400)
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  kms = createKmsDouble();
  mode = { kind: 'double' };
  received = [];
  vi.stubEnv('AWS_ENDPOINT_URL_KMS', endpoint);
  vi.stubEnv('AWS_ACCESS_KEY_ID', ACCESS_KEY_ID);
  vi.stubEnv('AWS_SECRET_ACCESS_KEY', 'kms-test-secret-access-key');
  vi.stubEnv('AWS_SESSION_TOKEN', undefined);
  // A profile would make the chain skip the variables above.
  vi.stubEnv('AWS_PROFILE', undefined);
  vi.stubEnv('AWS_EC2_METADATA_DISABLED', 'true');
});

afterEach(() => {
  vi.unstubAllEnvs();
});

/** The provider exactly as `KEK_PROVIDER=aws-kms` creates it. */
function productionProvider() {
  return createKekProvider({ env: { KEK_AWS_KMS_KEY_ID: DOUBLE_KEY_ARN }, warn: () => undefined });
}

async function rejection(promise: Promise<unknown>): Promise<Error & { cause?: unknown }> {
  return promise.then(
    () => {
      throw new Error('expected a rejection');
    },
    (reason: Error) => reason
  );
}

describe('the KMS client configuration', () => {
  it('limits the attempts, sets both timeouts and passes no credentials', () => {
    const config = kmsClientConfig('eu-central-1');

    expect(config).toEqual({
      region: 'eu-central-1',
      maxAttempts: 3,
      retryMode: 'standard',
      requestHandler: {
        connectionTimeout: 2_000,
        requestTimeout: 3_000,
        throwOnRequestTimeout: true,
      },
    });
    expect(config).not.toHaveProperty('credentials');
    expect([KMS_MAX_ATTEMPTS, KMS_CONNECTION_TIMEOUT_MS, KMS_REQUEST_TIMEOUT_MS]).toEqual([
      3, 2_000, 3_000,
    ]);
  });
});

describe('the SDK client against a KMS endpoint', () => {
  it('makes no KMS call when the provider is created', async () => {
    await productionProvider();

    expect(received).toEqual([]);
  });

  it('wraps and unwraps over the KMS protocol, signed with credentials from the default chain', async () => {
    const provider = await productionProvider();
    const dek = randomBytes(32);

    const { wrapped, kekRef } = await provider.wrap(Buffer.from(dek), AAD);
    const opened = await provider.unwrap(wrapped, AAD, kekRef);

    expect(Buffer.from(opened)).toEqual(dek);
    expect(kekRef).toBe(`${DOUBLE_KEY_ARN}#${kms.currentKeyMaterialId()}`);
    expect(received.map((request) => request.target)).toEqual([
      'TrentService.Encrypt',
      'TrentService.Decrypt',
      'TrentService.Decrypt',
    ]);
    expect(received[0].body).toMatchObject({
      KeyId: DOUBLE_KEY_ARN,
      EncryptionContext: { 'qauth:realm-id': 'realm-a', 'qauth:kid': 'kid-1' },
      EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
    });
    for (const request of received) {
      expect(request.headers.authorization).toContain(`Credential=${ACCESS_KEY_ID}/`);
      expect(request.headers.authorization).toContain('/eu-central-1/kms/aws4_request');
    }
  });

  it('stops after the attempt limit under throttling, even when AWS_MAX_ATTEMPTS asks for more', async () => {
    vi.stubEnv('AWS_MAX_ATTEMPTS', '10');
    mode = { kind: 'fail', name: 'ThrottlingException' };
    const provider = await productionProvider();

    const error = await rejection(provider.wrap(randomBytes(32), AAD));

    expect(isKeyCustodyError(error, 'KEK_UNAVAILABLE')).toBe(true);
    expect((error.cause as Error).name).toBe('ThrottlingException');
    expect(received).toHaveLength(KMS_MAX_ATTEMPTS);
  }, 20_000);

  it('retries a KMS server fault up to the limit', async () => {
    mode = { kind: 'fail', name: 'KMSInternalException' };
    const provider = await productionProvider();

    const error = await rejection(provider.wrap(randomBytes(32), AAD));

    expect(isKeyCustodyError(error, 'KEK_UNAVAILABLE')).toBe(true);
    expect(received).toHaveLength(KMS_MAX_ATTEMPTS);
  }, 20_000);

  it.each([
    ['AccessDeniedException', 'KEK_ACCESS_DENIED'],
    ['UnrecognizedClientException', 'KEK_ACCESS_DENIED'],
    ['InvalidCiphertextException', 'KEY_DECRYPTION_FAILED'],
  ] as const)('does not retry %s, reported as %s', async (name, code) => {
    const provider = await productionProvider();
    const { wrapped, kekRef } = await provider.wrap(randomBytes(32), AAD);
    received = [];
    mode = { kind: 'fail', name };

    const error = await rejection(provider.unwrap(wrapped, AAD, kekRef));

    expect(isKeyCustodyError(error, code)).toBe(true);
    expect((error.cause as Error).name).toBe(name);
    expect(received).toHaveLength(1);
  });

  it('turns a KMS endpoint that never answers into an outage, within the attempt limit', async () => {
    const sockets: Socket[] = [];
    const blackHole = createTcpServer((socket) => {
      sockets.push(socket);
      socket.resume();
    });
    await new Promise<void>((resolve) => blackHole.listen(0, '127.0.0.1', resolve));
    vi.stubEnv(
      'AWS_ENDPOINT_URL_KMS',
      `http://127.0.0.1:${(blackHole.address() as AddressInfo).port}`
    );
    // The production timeouts, shortened so the test is quick.
    const config = kmsClientConfig('eu-central-1');
    const client = new KMSClient({
      ...config,
      requestHandler: { connectionTimeout: 200, requestTimeout: 200, throwOnRequestTimeout: true },
    });
    const provider = createAwsKmsKekProvider({
      keyArn: DOUBLE_KEY_ARN,
      kms: kmsOperationsOf(client),
    });

    try {
      const error = await rejection(provider.wrap(randomBytes(32), AAD));

      expect(isKeyCustodyError(error, 'KEK_UNAVAILABLE')).toBe(true);
      expect((error.cause as Error).name).toBe('TimeoutError');
      expect(sockets).toHaveLength(KMS_MAX_ATTEMPTS);
    } finally {
      client.destroy();
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => blackHole.close(resolve));
    }
  }, 20_000);
});

// The whole contract once more, through the SDK client and the KMS protocol.
// The server delegates to whichever double the current case set up.
runKekProviderContract({
  name: 'aws-kms (SDK client, KMS protocol, KMS test double)',
  createProvider: () => productionProvider(),
  describe,
  it,
});
