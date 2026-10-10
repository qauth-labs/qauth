import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import rateLimit from '@fastify/rate-limit';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import { clientAddressKey, UNKNOWN_CLIENT_ADDRESS } from './client-address';

const key = (ip?: string, remoteAddress?: string) =>
  clientAddressKey({ ip, socket: remoteAddress === undefined ? undefined : { remoteAddress } });

describe('clientAddressKey', () => {
  it('keeps an IPv4 address unchanged', () => {
    expect(key('203.0.113.7')).toBe('203.0.113.7');
    expect(key('127.0.0.1')).toBe('127.0.0.1');
  });

  it('gives two IPv6 addresses in the same /64 the same key', () => {
    const a = key('2001:db8:1:2:aaaa:bbbb:cccc:dddd');
    const b = key('2001:db8:1:2::1');
    expect(a).toBe(b);
    expect(a).toBe('2001:db8:1:2::');
  });

  it('gives IPv6 addresses in different /64s different keys', () => {
    expect(key('2001:db8:1:2::1')).not.toBe(key('2001:db8:1:3::1'));
    expect(key('2001:db8:1:2::1')).not.toBe(key('2001:db9:1:2::1'));
  });

  it('keys an IPv4-mapped IPv6 address as its IPv4 form', () => {
    expect(key('::ffff:203.0.113.7')).toBe(key('203.0.113.7'));
    expect(key('::FFFF:203.0.113.7')).toBe('203.0.113.7');
    expect(key('0:0:0:0:0:ffff:cb00:7107')).toBe('203.0.113.7');
  });

  it('gives every textual form of one IPv6 address one key', () => {
    const forms = [
      '2001:db8:1:2::ff',
      '2001:DB8:1:2::FF',
      '2001:0db8:0001:0002:0000:0000:0000:00ff',
      '2001:db8:1:2:0:0:0:ff',
      '2001:db8:1:2::ff%eth0',
    ];
    expect(new Set(forms.map((form) => key(form)))).toEqual(new Set(['2001:db8:1:2::']));
  });

  it('falls back to the socket peer when request.ip is empty', () => {
    expect(key(undefined, '198.51.100.4')).toBe('198.51.100.4');
    expect(key('', '2001:db8:1:2::9')).toBe('2001:db8:1:2::');
  });

  it('returns the fallback key when no address is known', () => {
    expect(key()).toBe(UNKNOWN_CLIENT_ADDRESS);
    expect(key('')).toBe(UNKNOWN_CLIENT_ADDRESS);
    expect(clientAddressKey({})).toBe('unknown');
    expect(key(undefined, '')).toBe(UNKNOWN_CLIENT_ADDRESS);
  });

  it('keys an address in the 64:ff9b::/96 translation prefix per address', () => {
    expect(key('64:ff9b::203.0.113.7')).not.toBe(key('64:ff9b::198.51.100.4'));
    expect(key('64:ff9b::203.0.113.7')).toBe(key('64:ff9b::cb00:7107'));
    expect(key('64:ff9b:1::1')).toBe(key('64:ff9b:1::2'));
  });

  it('keys a value that is not an IP address as itself', () => {
    expect(key('Not-An-Address')).toBe('not-an-address');
  });
});

describe('clientAddressKey as a @fastify/rate-limit keyGenerator', () => {
  async function limitedApp() {
    const app = Fastify();
    await app.register(rateLimit, { max: 1, timeWindow: 60_000, keyGenerator: clientAddressKey });
    app.get('/', async () => 'ok');
    await app.ready();
    return app;
  }

  it('shares one bucket across a /64 and keeps other clients apart', async () => {
    const app = await limitedApp();
    const status = async (remoteAddress: string) =>
      (await app.inject({ method: 'GET', url: '/', remoteAddress })).statusCode;
    try {
      expect(await status('2001:db8:1:2::1')).toBe(200);
      expect(await status('2001:db8:1:2:ffff:eeee:dddd:cccc')).toBe(429);
      expect(await status('2001:db8:1:3::1')).toBe(200);
      expect(await status('203.0.113.7')).toBe(200);
      expect(await status('::ffff:203.0.113.7')).toBe(429);
    } finally {
      await app.close();
    }
  });
});

describe('rate-limit key functions in the app', () => {
  it('derive every key from clientAddressKey', () => {
    const appDir = fileURLToPath(new URL('..', import.meta.url));
    const files = readdirSync(appDir, { recursive: true, encoding: 'utf8' }).filter(
      (file) => file.endsWith('.ts') && !file.endsWith('.test.ts')
    );
    const offenders: string[] = [];
    let keyGenerators = 0;
    for (const file of files) {
      const source = readFileSync(join(appDir, file), 'utf8');
      for (const match of source.matchAll(/keyGenerator\s*:\s*([^,\n}]+)/g)) {
        keyGenerators += 1;
        if (match[1].trim() !== 'clientAddressKey') offenders.push(`${file}: ${match[0]}`);
      }
    }
    expect(keyGenerators).toBeGreaterThan(20);
    expect(offenders).toEqual([]);
  });
});
