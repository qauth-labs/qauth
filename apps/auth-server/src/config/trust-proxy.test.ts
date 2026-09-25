import { baseEnvSchema } from '@qauth-labs/server-config';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

/**
 * TRUST_PROXY end to end through Fastify's own `trustProxy` handling: the value
 * `baseEnvSchema` produces must make `request.ip` the client behind a trusted
 * proxy, and must never let an untrusted peer choose its address.
 */
async function ipSeenBy(trustProxyEnv: string | undefined, remoteAddress: string, xff?: string) {
  const env = baseEnvSchema.parse(
    trustProxyEnv === undefined ? {} : { TRUST_PROXY: trustProxyEnv }
  );
  const app = Fastify({ trustProxy: env.TRUST_PROXY });
  app.get('/ip', async (request) => ({ ip: request.ip }));
  const res = await app.inject({
    method: 'GET',
    url: '/ip',
    remoteAddress,
    headers: xff ? { 'x-forwarded-for': xff } : {},
  });
  await app.close();
  return (res.json() as { ip: string }).ip;
}

describe('TRUST_PROXY → request.ip', () => {
  it('unset: request.ip is the TCP peer, X-Forwarded-For is ignored', async () => {
    expect(await ipSeenBy(undefined, '10.0.0.2', '203.0.113.9')).toBe('10.0.0.2');
  });

  it('a trusted proxy CIDR: request.ip is the client the proxy reports', async () => {
    expect(await ipSeenBy('10.0.0.0/8', '10.0.0.2', '203.0.113.9')).toBe('203.0.113.9');
  });

  it('an untrusted peer cannot choose its address with X-Forwarded-For', async () => {
    expect(await ipSeenBy('10.0.0.0/8', '198.51.100.7', '203.0.113.9')).toBe('198.51.100.7');
  });

  it('a spoofed hop before the trusted proxy is not believed', async () => {
    // The client sent "X-Forwarded-For: 1.2.3.4"; the proxy appended the real
    // client address. Only the proxy's own hop is trusted.
    expect(await ipSeenBy('10.0.0.0/8', '10.0.0.2', '1.2.3.4, 203.0.113.9')).toBe('203.0.113.9');
  });
});
