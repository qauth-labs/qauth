import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import {
  createStatusListUriAllowlist,
  DENY_ALL_STATUS_LIST_URI_ALLOWLIST,
} from './status-list-uri';

describe('createStatusListUriAllowlist (#297)', () => {
  it('permits a URI under a configured origin', () => {
    const allowlist = createStatusListUriAllowlist(['https://issuer.example']);
    expect(allowlist.permits('https://issuer.example/statuslists/1')).toBe(true);
  });

  it('permits a URI under a configured path prefix', () => {
    const allowlist = createStatusListUriAllowlist(['https://issuer.example/status']);
    expect(allowlist.permits('https://issuer.example/status')).toBe(true);
    expect(allowlist.permits('https://issuer.example/status/1')).toBe(true);
  });

  it('permits a query string on an allowlisted path', () => {
    // draft-14 places no structure on the URI and issuers do shard by query.
    const allowlist = createStatusListUriAllowlist(['https://issuer.example/status']);
    expect(allowlist.permits('https://issuer.example/status/1?shard=7')).toBe(true);
  });

  it('anchors the path match at a SEGMENT boundary', () => {
    // A naive startsWith() would let `/status-evil` through a `/status` prefix.
    const allowlist = createStatusListUriAllowlist(['https://issuer.example/status']);
    expect(allowlist.permits('https://issuer.example/status-evil/1')).toBe(false);
    expect(allowlist.permits('https://issuer.example/statuses/1')).toBe(false);
  });

  it('anchors the host match at the ORIGIN, not at a string prefix', () => {
    const allowlist = createStatusListUriAllowlist(['https://issuer.example']);
    expect(allowlist.permits('https://issuer.example.attacker.test/statuslists/1')).toBe(false);
    expect(allowlist.permits('https://attacker.test/issuer.example/1')).toBe(false);
  });

  it('distinguishes ports', () => {
    const allowlist = createStatusListUriAllowlist(['https://issuer.example']);
    expect(allowlist.permits('https://issuer.example:8443/statuslists/1')).toBe(false);
  });

  it('normalises host case and path traversal on both sides', () => {
    const allowlist = createStatusListUriAllowlist(['https://Issuer.EXAMPLE/status/']);
    expect(allowlist.permits('https://issuer.example/status/sub/../1')).toBe(true);
  });

  it('refuses a traversal that escapes the configured prefix', () => {
    const allowlist = createStatusListUriAllowlist(['https://issuer.example/status']);
    expect(allowlist.permits('https://issuer.example/status/../secrets/1')).toBe(false);
  });

  describe('unconditional SSRF refusals', () => {
    const allowlist = createStatusListUriAllowlist(['https://issuer.example']);

    it.each([
      ['plain HTTP', 'http://issuer.example/statuslists/1'],
      ['userinfo', 'https://issuer.example@attacker.test/1'],
      ['a fragment', 'https://issuer.example/statuslists/1#x'],
      ['a non-URL', 'not a url'],
      ['a data URI', 'data:text/plain,hello'],
      ['a file URI', 'file:///etc/passwd'],
    ])('refuses %s', (_label, uri) => {
      expect(allowlist.permits(uri)).toBe(false);
    });

    it.each([
      ['loopback IPv4', 'https://127.0.0.1/1'],
      ['the cloud metadata address', 'https://169.254.169.254/latest/meta-data/'],
      ['a decimal-encoded IPv4', 'https://2130706433/1'],
      ['a shorthand IPv4', 'https://127.1/1'],
      ['loopback IPv6', 'https://[::1]/1'],
      ['IPv4-mapped IPv6', 'https://[::ffff:127.0.0.1]/1'],
      ['localhost', 'https://localhost/1'],
      ['a localhost subdomain', 'https://issuer.localhost/1'],
    ])('refuses %s even before the allowlist is consulted', (_label, uri) => {
      // Configured wide open on purpose: these must be refused by the floor
      // beneath the allowlist, not by the allowlist.
      const wideOpen = createStatusListUriAllowlist([
        'https://issuer.example',
        'https://another.example',
      ]);
      expect(wideOpen.permits(uri)).toBe(false);
      expect(allowlist.permits(uri)).toBe(false);
    });
  });

  it('permits nothing when configured empty', () => {
    expect(createStatusListUriAllowlist([]).permits('https://issuer.example/1')).toBe(false);
    expect(DENY_ALL_STATUS_LIST_URI_ALLOWLIST.permits('https://issuer.example/1')).toBe(false);
  });

  it.each([
    ['a non-string entry', [42]],
    ['a blank entry', ['   ']],
    ['a non-HTTPS entry', ['http://issuer.example']],
    ['an entry with userinfo', ['https://user:pw@issuer.example']],
    ['an entry with a query string', ['https://issuer.example/status?v=1']],
    ['an entry with a fragment', ['https://issuer.example/status#x']],
    ['an IP-literal entry', ['https://127.0.0.1']],
    ['a localhost entry', ['https://localhost']],
    ['a nonsense entry', ['not a url']],
  ])('throws InvalidConfigurationError for %s', (_label, entries) => {
    expect(() => createStatusListUriAllowlist(entries as string[])).toThrow(
      InvalidConfigurationError
    );
  });

  it('reports the offending entry on details, never in the message', () => {
    try {
      createStatusListUriAllowlist(['https://ok.example', 'http://leaky.example/secret-path']);
      expect.unreachable('expected a configuration error');
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as InvalidConfigurationError).message).not.toContain('leaky.example');
      expect((error as InvalidConfigurationError).details?.['index']).toBe(1);
      expect((error as InvalidConfigurationError).details?.['entry']).toBe(
        'http://leaky.example/secret-path'
      );
    }
  });

  it('rejects a non-array configuration', () => {
    expect(() => createStatusListUriAllowlist('https://issuer.example' as never)).toThrow(
      InvalidConfigurationError
    );
  });
});
