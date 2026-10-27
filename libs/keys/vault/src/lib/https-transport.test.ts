import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createHttpsTransport,
  MAX_KEY_READ_RESPONSE_BYTES,
  MAX_RESPONSE_BYTES,
  type VaultHttpRequest,
} from './https-transport';

/**
 * The HTTPS transport against a local TLS server. The certificates are made
 * with the host's `openssl` for each run: a CA and a leaf for `localhost` and
 * 127.0.0.1 it signs, and a second CA that signs nothing the server shows.
 */

const dir = mkdtempSync(join(tmpdir(), 'qauth-vault-tls-'));

function openssl(...args: string[]): void {
  execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' });
}

function makeCa(name: string): void {
  openssl(
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-keyout',
    `${name}.key`,
    '-out',
    `${name}.pem`,
    '-days',
    '1',
    '-subj',
    `/CN=${name}`
  );
}

let ca: string;
let otherCa: string;
let key: string;
let cert: string;
/** A leaf the same CA signed, for another host name only. */
let otherNameKey: string;
let otherNameCert: string;

interface Seen {
  readonly method: string | undefined;
  readonly url: string | undefined;
  readonly headers: Record<string, unknown>;
  readonly body: string;
}

const servers: Server[] = [];

/** A TLS server with the leaf certificate, answering with `handler`, at an origin. */
async function serve(
  handler: (
    seen: Seen,
    reply: (status: number, body?: string, headers?: Record<string, string>) => void
  ) => void,
  identity: { key: string; cert: string } = { key, cert }
): Promise<{ origin: string; seen: Seen[] }> {
  const seen: Seen[] = [];
  const server = createServer(identity, (request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      const entry = {
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      };
      seen.push(entry);
      handler(entry, (status, body = '', headers = {}) => {
        response.writeHead(status, headers);
        response.end(body);
      });
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { origin: `https://localhost:${(server.address() as AddressInfo).port}`, seen };
}

const REQUEST: VaultHttpRequest = {
  method: 'POST',
  path: '/v1/transit/encrypt/qauth-kek',
  headers: { 'X-Vault-Token': 'hvs.test-token', 'X-Vault-Request': 'true' },
  body: '{"plaintext":"AAAA"}',
};

beforeAll(() => {
  makeCa('ca');
  makeCa('other-ca');
  openssl(
    'req',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-keyout',
    'leaf.key',
    '-out',
    'leaf.csr',
    '-subj',
    '/CN=localhost'
  );
  writeFileSync(join(dir, 'leaf.ext'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
  openssl(
    'x509',
    '-req',
    '-in',
    'leaf.csr',
    '-CA',
    'ca.pem',
    '-CAkey',
    'ca.key',
    '-CAcreateserial',
    '-out',
    'leaf.pem',
    '-days',
    '1',
    '-extfile',
    'leaf.ext'
  );
  openssl(
    'req',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-keyout',
    'other-name.key',
    '-out',
    'other-name.csr',
    '-subj',
    '/CN=vault.other.test'
  );
  writeFileSync(join(dir, 'other-name.ext'), 'subjectAltName=DNS:vault.other.test\n');
  openssl(
    'x509',
    '-req',
    '-in',
    'other-name.csr',
    '-CA',
    'ca.pem',
    '-CAkey',
    'ca.key',
    '-CAcreateserial',
    '-out',
    'other-name.pem',
    '-days',
    '1',
    '-extfile',
    'other-name.ext'
  );
  otherNameKey = readFileSync(join(dir, 'other-name.key'), 'utf8');
  otherNameCert = readFileSync(join(dir, 'other-name.pem'), 'utf8');
  ca = readFileSync(join(dir, 'ca.pem'), 'utf8');
  otherCa = readFileSync(join(dir, 'other-ca.pem'), 'utf8');
  key = readFileSync(join(dir, 'leaf.key'), 'utf8');
  cert = readFileSync(join(dir, 'leaf.pem'), 'utf8');
}, 30_000);

afterAll(async () => {
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  rmSync(dir, { recursive: true, force: true });
});

describe('the HTTPS transport to Vault', () => {
  it('sends the method, the path, the headers and the JSON body, and parses the JSON answer', async () => {
    const { origin, seen } = await serve((_seen, reply) =>
      reply(200, '{"data":{"ciphertext":"vault:v1:AAAA"}}', { 'content-type': 'application/json' })
    );

    const answer = await createHttpsTransport({ origin, ca })(REQUEST);

    expect(answer).toEqual({ status: 200, body: { data: { ciphertext: 'vault:v1:AAAA' } } });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      method: 'POST',
      url: '/v1/transit/encrypt/qauth-kek',
      body: '{"plaintext":"AAAA"}',
    });
    expect(seen[0].headers).toMatchObject({
      'x-vault-token': 'hvs.test-token',
      'x-vault-request': 'true',
      'content-type': 'application/json',
      'content-length': String(REQUEST.body?.length),
      accept: 'application/json',
    });
  });

  it('reaches 127.0.0.1 by address too', async () => {
    const { origin } = await serve((_seen, reply) => reply(204));

    const answer = await createHttpsTransport({
      origin: origin.replace('localhost', '127.0.0.1'),
      ca,
    })(REQUEST);

    expect(answer).toEqual({ status: 204, body: undefined });
  });

  it('refuses a server whose certificate the configured CA did not sign, before sending anything', async () => {
    const { origin, seen } = await serve((_seen, reply) => reply(200, '{}'));

    const error = await createHttpsTransport({ origin, ca: otherCa })(REQUEST).catch(
      (reason: unknown) => reason
    );

    expect(error).toMatchObject({
      code: expect.stringMatching(/UNABLE_TO_VERIFY|SELF_SIGNED|UNABLE_TO_GET_ISSUER/),
    });
    expect(seen).toEqual([]);
  });

  it("refuses the same server with Node's default CA store", async () => {
    const { origin, seen } = await serve((_seen, reply) => reply(200, '{}'));

    await expect(createHttpsTransport({ origin })(REQUEST)).rejects.toMatchObject({
      code: expect.any(String),
    });
    expect(seen).toEqual([]);
  });

  it('refuses a certificate the CA signed for another host name', async () => {
    const { origin, seen } = await serve((_seen, reply) => reply(200, '{}'), {
      key: otherNameKey,
      cert: otherNameCert,
    });

    await expect(createHttpsTransport({ origin, ca })(REQUEST)).rejects.toMatchObject({
      code: 'ERR_TLS_CERT_ALTNAME_INVALID',
    });
    expect(seen).toEqual([]);
  });

  it('gives up on a server that does not answer within the deadline', async () => {
    const { origin } = await serve(() => undefined);
    const started = Date.now();

    await expect(
      createHttpsTransport({ origin, ca, timeoutMs: 300 })(REQUEST)
    ).rejects.toMatchObject({
      code: 'ETIMEDOUT',
    });
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it('drops an answer larger than the cap', async () => {
    const { origin } = await serve((_seen, reply) =>
      reply(200, 'x'.repeat(MAX_RESPONSE_BYTES + 1))
    );

    await expect(createHttpsTransport({ origin, ca })(REQUEST)).rejects.toMatchObject({
      code: 'ERR_VAULT_RESPONSE_TOO_LARGE',
    });
  });

  it('reads a larger answer for a request that sets its own cap, and drops one above it', async () => {
    const body = JSON.stringify({ data: { keys: 'x'.repeat(MAX_RESPONSE_BYTES * 4) } });
    const { origin } = await serve((_seen, reply) => reply(200, body));
    const transport = createHttpsTransport({ origin, ca });

    const answer = await transport({ ...REQUEST, maxResponseBytes: MAX_KEY_READ_RESPONSE_BYTES });

    expect(answer.status).toBe(200);
    expect(JSON.stringify(answer.body)).toBe(body);
    await expect(transport({ ...REQUEST, maxResponseBytes: 1024 })).rejects.toMatchObject({
      code: 'ERR_VAULT_RESPONSE_TOO_LARGE',
    });
  });

  it('does not follow a redirect, so the token reaches no other host', async () => {
    const other = await serve((_seen, reply) => reply(200, '{}'));
    const { origin } = await serve((_seen, reply) =>
      reply(307, '', { location: `${other.origin}/v1/transit/encrypt/qauth-kek` })
    );

    const answer = await createHttpsTransport({ origin, ca })(REQUEST);

    expect(answer.status).toBe(307);
    expect(other.seen).toEqual([]);
  });

  it('reads an answer that is not JSON as no body', async () => {
    const { origin } = await serve((_seen, reply) => reply(502, '<html>Bad Gateway</html>'));

    expect(await createHttpsTransport({ origin, ca })(REQUEST)).toEqual({
      status: 502,
      body: undefined,
    });
  });

  it('speaks https only', () => {
    expect(() => createHttpsTransport({ origin: 'http://localhost:8200' })).toThrow(TypeError);
  });
});
