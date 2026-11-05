import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { EgressError, type EgressRequest, type EgressResponse } from '@qauth-labs/server-egress';
import { describe, expect, it, vi } from 'vitest';

import {
  BOT_CHALLENGE_LIMITS,
  BOT_CHALLENGE_PURPOSE,
  botChallengeVerifyUrlProblem,
  createSiteVerifyChallengeProvider,
  type SiteVerifyChallengeOptions,
} from './bot-challenge';

/**
 * The hosted bot challenge (#643): one form POST of the secret and the token
 * to the operator's verify URL, through the egress client, read for its
 * `success`; an outage refuses, and neither the token nor the secret leaks.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const VERIFY_URL = 'https://challenges.example.com/siteverify';
const SECRET = 'SECRET-0x4AAAAAAAAAAAAAAAAAAA';
const TOKEN = 'TOKEN-XXXXXXXXXXXXXXXXXXXXXXXXXXXX.yyyy_zzz';
const PARAMS = { provider: 'hosted', name: 'turnstile', site_key: '0x4AAAAAAA' } as const;

function answering(response: Partial<EgressResponse> | Error) {
  const sent: EgressRequest[] = [];
  const egress = {
    request: vi.fn(async (request: EgressRequest): Promise<EgressResponse> => {
      sent.push(request);
      if (response instanceof Error) throw response;
      return {
        status: 200,
        headers: {},
        body: Buffer.from('{}'),
        url: String(request.url),
        redirects: 0,
        ...response,
      };
    }),
  };
  return { egress, sent };
}

const json = (value: unknown): Partial<EgressResponse> => ({
  body: Buffer.from(JSON.stringify(value)),
});

function provider(
  egress: SiteVerifyChallengeOptions['egress'],
  overrides: Partial<SiteVerifyChallengeOptions> = {}
) {
  return createSiteVerifyChallengeProvider({
    egress,
    name: 'turnstile',
    siteKey: '0x4AAAAAAA',
    secret: SECRET,
    verifyUrl: VERIFY_URL,
    ...overrides,
  });
}

describe('the hosted bot challenge', () => {
  it('offers its name and site key, the same for every challenge', async () => {
    const { egress } = answering(json({ success: true }));
    const hosted = provider(egress);
    expect(await hosted.params({ realmId: REALM, clientId: 'web' })).toEqual(PARAMS);
    expect(await hosted.params({ realmId: REALM, clientId: 'other' })).toEqual(PARAMS);
    expect(egress.request).not.toHaveBeenCalled();
  });

  it('checks a token with one POST to the configured host, through the egress client', async () => {
    const { egress, sent } = answering(json({ success: true, hostname: 'example.com' }));
    expect(await provider(egress).verify({ realmId: REALM, params: PARAMS, token: TOKEN })).toBe(
      true
    );
    expect(sent).toHaveLength(1);
    const [request] = sent;
    expect(request).toMatchObject({
      method: 'POST',
      url: VERIFY_URL,
      purpose: BOT_CHALLENGE_PURPOSE,
      source: 'operator',
      limits: BOT_CHALLENGE_LIMITS,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    expect(BOT_CHALLENGE_LIMITS.maxRedirects).toBe(0);
    expect(Object.fromEntries(new URLSearchParams(String(request?.body)))).toEqual({
      secret: SECRET,
      response: TOKEN,
    });
  });

  it('refuses a token the provider does not take, and one for other params unchecked', async () => {
    const { egress } = answering(json({ success: false, 'error-codes': ['invalid-input'] }));
    const hosted = provider(egress);
    expect(await hosted.verify({ realmId: REALM, params: PARAMS, token: TOKEN })).toBe(false);
    for (const params of [
      { ...PARAMS, name: 'hcaptcha' },
      { ...PARAMS, site_key: 'another' },
      { provider: 'pow', challenge: 'a'.repeat(43), difficulty: 4 },
    ] as const) {
      expect(await hosted.verify({ realmId: REALM, params, token: TOKEN })).toBe(false);
    }
    expect(egress.request).toHaveBeenCalledTimes(1);
  });

  it('throws on an outage, naming neither the token nor the secret', async () => {
    const outages: (Partial<EgressResponse> | Error)[] = [
      new EgressError({
        reason: 'address',
        outcome: 'blocked',
        purpose: BOT_CHALLENGE_PURPOSE,
        host: 'challenges.example.com',
        message: 'egress blocked: challenges.example.com resolves to a private address',
      }),
      new EgressError({
        reason: 'timeout',
        outcome: 'failed',
        purpose: BOT_CHALLENGE_PURPOSE,
        host: 'challenges.example.com',
        message: 'egress failed: challenges.example.com timed out',
      }),
      new Error(`socket closed while sending ${TOKEN}`),
      { status: 500 },
      { status: 302, headers: { location: 'https://elsewhere.example/' } },
      { body: Buffer.from('<html>success</html>') },
      json({ success: 'true' }),
      json({}),
      json([true]),
      json(null),
    ];
    for (const outage of outages) {
      const { egress } = answering(outage);
      const error = await provider(egress)
        .verify({ realmId: REALM, params: PARAMS, token: TOKEN })
        .then(
          () => undefined,
          (thrown: unknown) => thrown
        );
      expect(error, JSON.stringify(outage)).toBeInstanceOf(Error);
      const told = JSON.stringify(error, Object.getOwnPropertyNames(error as Error));
      expect(told).not.toContain(TOKEN);
      expect(told).not.toContain(SECRET);
      expect(String((error as Error).message)).not.toContain(TOKEN);
    }
  });

  it('fails the boot on an option out of shape', () => {
    const { egress } = answering(json({ success: true }));
    for (const overrides of [
      { name: 'pow' },
      { name: 'Turnstile' },
      { name: '' },
      { siteKey: 'a key with spaces' },
      { siteKey: '' },
      { secret: '' },
      { verifyUrl: 'http://challenges.example.com/siteverify' },
      { verifyUrl: 'https://user:pass@challenges.example.com/siteverify' },
      { verifyUrl: 'https://challenges.example.com/siteverify?x=1' },
      { verifyUrl: 'https://challenges.example.com/siteverify#x' },
      { verifyUrl: '/siteverify' },
    ]) {
      expect(() => provider(egress, overrides), JSON.stringify(overrides)).toThrow(TypeError);
    }
    expect(botChallengeVerifyUrlProblem(VERIFY_URL)).toBeUndefined();
  });
});

describe('the hosted bot challenge reaches the network through the egress client only (#643)', () => {
  /** The modules that open a connection, or wrap one. */
  const NETWORK_IMPORT =
    /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)['"`](?:node:)?(?:http|https|http2|net|tls|dgram|undici|axios|node-fetch|got)(?:\/[^'"`]*)?['"`]/;
  const GLOBAL_FETCH =
    /(?:^|[^.\w$])fetch\s*\(|\b(?:globalThis|global|window|self)\s*(?:\.\s*fetch\b|\[\s*['"`]fetch['"`]\s*\])/;

  it('imports no network module, calls no fetch, and sends through egress.request alone', () => {
    const source = readFileSync(join(__dirname, 'bot-challenge.ts'), 'utf8');
    expect(NETWORK_IMPORT.test(source)).toBe(false);
    expect(GLOBAL_FETCH.test(source)).toBe(false);
    expect(source.match(/\.request\(/g)).toEqual(['.request(']);
    expect(source).toContain("from '@qauth-labs/server-egress'");
  });

  it('declares the egress client and no network library among its dependencies', () => {
    const manifest = JSON.parse(
      readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8')
    ) as { dependencies?: Record<string, string> };
    const declared = Object.keys(manifest.dependencies ?? {});
    expect(declared).toContain('@qauth-labs/server-egress');
    expect(
      declared.filter((name) =>
        ['undici', 'axios', 'node-fetch', 'got', 'cross-fetch'].includes(name)
      )
    ).toEqual([]);
  });
});
