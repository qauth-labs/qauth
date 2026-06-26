import { Writable } from 'node:stream';

import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import { buildLoggerOptions, LOG_REDACT_PATHS } from './logger';

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
});
