import { Writable } from 'node:stream';

import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  buildLoggerOptions,
  LOG_REDACT_CENSOR,
  LOG_REDACT_PATHS,
  LOG_REDACTED_QUERY_PARAMETERS,
  redactLoggedUrl,
  serializeRequestForLog,
} from './logger';

type EnvSubset = Parameters<typeof buildLoggerOptions>[0];
type LoggerOptions = Exclude<ReturnType<typeof buildLoggerOptions>, boolean | undefined>;

const baseEnv: EnvSubset = {
  LOG_LEVEL: 'info',
  LOG_PRETTY: false,
  NODE_ENV: 'test',
};

describe('buildLoggerOptions', () => {
  it('honours LOG_LEVEL', () => {
    const options = buildLoggerOptions({ ...baseEnv, LOG_LEVEL: 'warn' }) as LoggerOptions;
    expect(options.level).toBe('warn');
  });

  it('does not configure pino-pretty in production even when LOG_PRETTY is on', () => {
    const options = buildLoggerOptions({
      ...baseEnv,
      LOG_PRETTY: true,
      NODE_ENV: 'production',
    }) as LoggerOptions;
    expect(options.transport).toBeUndefined();
  });

  it('configures pino-pretty in development when LOG_PRETTY is on', () => {
    const options = buildLoggerOptions({
      ...baseEnv,
      LOG_PRETTY: true,
      NODE_ENV: 'development',
    }) as LoggerOptions & { transport?: { target: string } };
    expect(options.transport?.target).toBe('pino-pretty');
  });

  it('exposes a stable set of redaction paths covering core secret fields', () => {
    expect(LOG_REDACT_PATHS).toContain('req.headers.authorization');
    expect(LOG_REDACT_PATHS).toContain('req.headers.cookie');
    expect(LOG_REDACT_PATHS).toContain('password');
    expect(LOG_REDACT_PATHS).toContain('client_secret');
    expect(LOG_REDACT_PATHS).toContain('refresh_token');
    expect(LOG_REDACT_PATHS).toContain('code_verifier');
  });

  it('redacts passwords, tokens, secrets, authorization headers and cookies in log output', async () => {
    // Use Fastify's own logger (pino) so we exercise the real redaction config
    // end to end and capture the serialised JSON output.
    const captured: string[] = [];
    const stream = new Writable({
      write(chunk, _enc, cb) {
        captured.push(chunk.toString());
        cb();
      },
    });

    const loggerOptions = buildLoggerOptions(baseEnv) as LoggerOptions;
    const app = Fastify({ logger: { ...loggerOptions, stream } });

    app.log.info(
      {
        password: 'hunter2',
        client_secret: 'super-secret',
        access_token: 'eyJhbGciOi...',
        refresh_token: 'rt-leak',
        code_verifier: 'pkce-verifier',
        nested: { password: 'nested-secret', token: 'nested-token' },
        req: {
          headers: {
            authorization: 'Bearer leaked-jwt',
            cookie: 'session=leaked',
          },
        },
      },
      'sensitive payload'
    );

    await app.close();

    const serialized = captured.join('');

    for (const secret of [
      'hunter2',
      'super-secret',
      'eyJhbGciOi...',
      'rt-leak',
      'pkce-verifier',
      'nested-secret',
      'nested-token',
      'Bearer leaked-jwt',
      'session=leaked',
    ]) {
      expect(serialized).not.toContain(secret);
    }

    expect(serialized).toContain('[Redacted]');
  });

  it('(OID4VP 1.0 §14.2) redacts the same-device response_code from the request log line', async () => {
    // A real request through Fastify's own request/response logging, so what is
    // asserted is the `req` serializer as the server actually uses it — not a
    // hand-built object. The code is what the wallet's browser brings back to
    // `/ui/wallet-login/return`; the line must still carry the path.
    const captured: string[] = [];
    const stream = new Writable({
      write(chunk, _enc, cb) {
        captured.push(chunk.toString());
        cb();
      },
    });

    const loggerOptions = buildLoggerOptions(baseEnv) as LoggerOptions;
    const app = Fastify({ logger: { ...loggerOptions, stream } });
    app.get('/ui/wallet-login/return', async () => ({ ok: true }));

    const code = 'gLDFeWTVs5PTZcgEjhwwPpTmxIkXIv0CpyHiURdO_-A';
    await app.inject({
      method: 'GET',
      url: `/ui/wallet-login/return?response_code=${code}&next=1`,
      headers: { 'accept-version': '1.0.0' },
    });
    await app.close();

    const serialized = captured.join('');
    const requestLine = captured.find((line) => line.includes('"req"'));

    expect(serialized).not.toContain(code);
    expect(serialized).toContain(
      `/ui/wallet-login/return?response_code=${LOG_REDACT_CENSOR}&next=1`
    );

    // Everything Fastify's default serializer carried is still there.
    const parsed = JSON.parse(requestLine ?? '{}') as { req?: Record<string, unknown> };
    expect(parsed.req).toMatchObject({
      method: 'GET',
      url: `/ui/wallet-login/return?response_code=${LOG_REDACT_CENSOR}&next=1`,
      version: '1.0.0',
      remoteAddress: '127.0.0.1',
    });
    expect(parsed.req).toHaveProperty('host');
    // ...and nothing that was not: the six fields of the pino-http shape Fastify
    // inlined (`remotePort` is undefined under `inject`, so JSON drops it).
    for (const key of Object.keys(parsed.req ?? {})) {
      expect(['method', 'url', 'version', 'host', 'remoteAddress', 'remotePort']).toContain(key);
    }
  });
});

describe('redactLoggedUrl', () => {
  it('lists response_code as the one bearer value that rides in a query string', () => {
    expect(LOG_REDACTED_QUERY_PARAMETERS).toEqual(['response_code']);
  });

  it('censors the value and keeps the rest of the URL byte-for-byte', () => {
    expect(redactLoggedUrl('/ui/wallet-login/return?response_code=abc-_XYZ')).toBe(
      `/ui/wallet-login/return?response_code=${LOG_REDACT_CENSOR}`
    );
    expect(redactLoggedUrl('/r?a=1&response_code=abc&b=%2F')).toBe(
      `/r?a=1&response_code=${LOG_REDACT_CENSOR}&b=%2F`
    );
  });

  it('censors every occurrence, including a repeated parameter', () => {
    expect(redactLoggedUrl('/r?response_code=one&response_code=two')).toBe(
      `/r?response_code=${LOG_REDACT_CENSOR}&response_code=${LOG_REDACT_CENSOR}`
    );
  });

  it('censors an empty value without eating the following parameter', () => {
    expect(redactLoggedUrl('/r?response_code=&next=1')).toBe(
      `/r?response_code=${LOG_REDACT_CENSOR}&next=1`
    );
  });

  it('leaves a URL without the parameter untouched', () => {
    for (const url of [
      '/health',
      '/oauth/authorize?client_id=abc&state=response_code',
      '/r?x_response_code=notours',
      '/r?response_code_extra=notours',
      '/r?RESPONSE_CODE=casesensitive',
      '/ui/wallet-login/return',
    ]) {
      expect(redactLoggedUrl(url)).toBe(url);
    }
  });
});

describe('serializeRequestForLog', () => {
  it('reproduces the six fields of the default serializer and nothing else', () => {
    const serialized = serializeRequestForLog({
      method: 'GET',
      url: '/ui/wallet-login/return?response_code=secret',
      headers: { 'accept-version': '2.0.0', cookie: 'session=leaked' },
      host: 'auth.example.com',
      ip: '10.0.0.1',
      socket: { remotePort: 4242 },
    } as unknown as Parameters<typeof serializeRequestForLog>[0]);

    expect(serialized).toEqual({
      method: 'GET',
      url: `/ui/wallet-login/return?response_code=${LOG_REDACT_CENSOR}`,
      version: '2.0.0',
      host: 'auth.example.com',
      remoteAddress: '10.0.0.1',
      remotePort: 4242,
    });
    expect(Object.keys(serialized)).toEqual([
      'method',
      'url',
      'version',
      'host',
      'remoteAddress',
      'remotePort',
    ]);
  });

  it('survives a hand-built partial req object, as the default serializer does', () => {
    expect(() =>
      serializeRequestForLog({} as unknown as Parameters<typeof serializeRequestForLog>[0])
    ).not.toThrow();
    expect(
      serializeRequestForLog({
        headers: {},
      } as unknown as Parameters<typeof serializeRequestForLog>[0])
    ).toEqual({
      method: undefined,
      url: undefined,
      version: undefined,
      host: undefined,
      remoteAddress: undefined,
      remotePort: undefined,
    });
  });
});
