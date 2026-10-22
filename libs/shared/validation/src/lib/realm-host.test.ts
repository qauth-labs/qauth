import { describe, expect, it } from 'vitest';

import {
  InvalidRealmHostError,
  type InvalidRealmHostReason,
  normaliseRealmHost,
  REALM_HOST_KINDS,
  REALM_HOST_MAX_LENGTH,
  type RealmHostKind,
} from './realm-host';

/** The reason `normaliseRealmHost` gives for refusing `input`. */
function reasonFor(input: string, kind?: RealmHostKind): InvalidRealmHostReason {
  try {
    normaliseRealmHost(input, kind);
  } catch (error) {
    expect(error).toBeInstanceOf(InvalidRealmHostError);
    return (error as InvalidRealmHostError).reason;
  }
  throw new Error(`expected "${input}" to be refused`);
}

/** A host of `length` ASCII characters made of valid 63-character labels. */
function hostOfLength(length: number): string {
  const labels: string[] = [];
  let remaining = length;
  while (remaining > 0) {
    const size = Math.min(63, remaining);
    labels.push('a'.repeat(size));
    remaining -= size + 1; // the dot before the next label
  }
  const host = labels.join('.');
  expect(host).toHaveLength(length);
  return host;
}

describe('normaliseRealmHost', () => {
  describe('the stored form', () => {
    it('lower-cases', () => {
      expect(normaliseRealmHost('AUTH.Example.COM')).toBe('auth.example.com');
    });

    it('converts an internationalised name to punycode', () => {
      expect(normaliseRealmHost('bücher.example')).toBe('xn--bcher-kva.example');
      expect(normaliseRealmHost('BÜCHER.example')).toBe('xn--bcher-kva.example');
      expect(normaliseRealmHost('münchen.de')).toBe('xn--mnchen-3ya.de');
    });

    it('leaves a name that is already punycode as it is', () => {
      expect(normaliseRealmHost('xn--bcher-kva.example')).toBe('xn--bcher-kva.example');
    });

    it('maps full-width characters and the ideographic full stop (UTS #46)', () => {
      expect(normaliseRealmHost('ｅｘａｍｐｌｅ.com')).toBe('example.com');
      expect(normaliseRealmHost('auth。example。com')).toBe('auth.example.com');
    });

    it('drops the port', () => {
      expect(normaliseRealmHost('auth.example.com:8443')).toBe('auth.example.com');
      expect(normaliseRealmHost('auth.example.com:443')).toBe('auth.example.com');
      expect(normaliseRealmHost('auth-server:3000', 'endpoint')).toBe('auth-server');
    });

    it('drops a trailing dot', () => {
      expect(normaliseRealmHost('auth.example.com.')).toBe('auth.example.com');
      expect(normaliseRealmHost('auth.example.com.:8443')).toBe('auth.example.com');
      expect(normaliseRealmHost('auth.example.com。')).toBe('auth.example.com');
    });

    it('gives one form for every spelling of the same host', () => {
      const spellings = [
        'auth.example.com',
        'AUTH.Example.com',
        'auth.example.com:8443',
        'auth.example.com.',
        'Auth.Example.Com.:443',
      ];
      expect(new Set(spellings.map((host) => normaliseRealmHost(host)))).toEqual(
        new Set(['auth.example.com'])
      );
    });

    it('keeps single-label names and container service names', () => {
      expect(normaliseRealmHost('localhost')).toBe('localhost');
      expect(normaliseRealmHost('auth-server', 'endpoint')).toBe('auth-server');
      expect(normaliseRealmHost('auth_server', 'endpoint')).toBe('auth_server');
    });

    it('is idempotent', () => {
      for (const host of ['Bücher.example.', 'AUTH.example.com:8443', '[0:0::1]:80']) {
        const once = normaliseRealmHost(host);
        expect(normaliseRealmHost(once)).toBe(once);
      }
    });
  });

  describe('IP literals', () => {
    it('refuses an IPv4 address as a primary host', () => {
      expect(reasonFor('192.0.2.10', 'primary')).toBe('ip_literal');
      expect(reasonFor('127.0.0.1:3000', 'primary')).toBe('ip_literal');
    });

    it('refuses an IPv6 address as a primary host', () => {
      expect(reasonFor('[::1]', 'primary')).toBe('ip_literal');
      expect(reasonFor('[2001:db8::1]:8443', 'primary')).toBe('ip_literal');
    });

    it('refuses the IPv4 spellings the URL standard maps to an address', () => {
      expect(reasonFor('０x7f.1', 'primary')).toBe('ip_literal');
      expect(reasonFor('１２７.0.0.1', 'primary')).toBe('ip_literal');
    });

    it('accepts an IP literal as an endpoint host, in its canonical form', () => {
      expect(normaliseRealmHost('192.0.2.10:3000', 'endpoint')).toBe('192.0.2.10');
      expect(normaliseRealmHost('[2001:DB8:0:0::1]:8443', 'endpoint')).toBe('[2001:db8::1]');
    });

    it('accepts an IP literal for a lookup, where the kind is not known', () => {
      expect(normaliseRealmHost('[::1]:3000')).toBe('[::1]');
      expect(normaliseRealmHost('127.0.0.1')).toBe('127.0.0.1');
    });

    it('refuses an IPv6 address without brackets', () => {
      expect(reasonFor('::1', 'endpoint')).toBe('malformed');
      expect(reasonFor('2001:db8::1', 'endpoint')).toBe('malformed');
    });

    it('refuses a bracketed value that is not an IPv6 address', () => {
      expect(reasonFor('[::1', 'endpoint')).toBe('malformed');
      expect(reasonFor('[]', 'endpoint')).toBe('malformed');
      expect(reasonFor('[192.0.2.10]', 'endpoint')).toBe('malformed');
      expect(reasonFor('[fe80::1%25eth0]', 'endpoint')).toBe('malformed');
    });
  });

  describe('refused values', () => {
    it('refuses a wildcard', () => {
      expect(reasonFor('*.example.com')).toBe('wildcard');
      expect(reasonFor('auth.*.example.com')).toBe('wildcard');
      expect(reasonFor('*')).toBe('wildcard');
    });

    it('refuses white space anywhere', () => {
      expect(reasonFor('auth example.com')).toBe('whitespace');
      expect(reasonFor(' auth.example.com')).toBe('whitespace');
      expect(reasonFor('auth.example.com ')).toBe('whitespace');
      expect(reasonFor('auth.example.com\t')).toBe('whitespace');
      expect(reasonFor('auth.example.com\n')).toBe('whitespace');
      expect(reasonFor('auth example.com')).toBe('whitespace');
      expect(reasonFor('auth　example.com')).toBe('whitespace');
    });

    it('refuses an empty label', () => {
      expect(reasonFor('auth..example.com')).toBe('empty_label');
      expect(reasonFor('.example.com')).toBe('empty_label');
      expect(reasonFor('example.com..')).toBe('empty_label');
    });

    it('refuses an empty value', () => {
      expect(reasonFor('')).toBe('empty');
      expect(reasonFor('.')).toBe('empty');
      expect(reasonFor(':443')).toBe('empty');
    });

    it(`accepts ${REALM_HOST_MAX_LENGTH} characters and refuses ${REALM_HOST_MAX_LENGTH + 1}`, () => {
      const longest = hostOfLength(REALM_HOST_MAX_LENGTH);
      expect(normaliseRealmHost(longest)).toBe(longest);
      expect(normaliseRealmHost(`${longest}.`)).toBe(longest);
      expect(normaliseRealmHost(`${longest}:443`)).toBe(longest);

      const input = hostOfLength(REALM_HOST_MAX_LENGTH + 1);
      expect(input).toHaveLength(254);
      expect(reasonFor(input)).toBe('too_long');
    });

    it('counts the length of the ASCII form, not of the input', () => {
      // A label of 20 "ü" is 26 characters in punycode (`xn--tda…`).
      const label = 'ü'.repeat(20);

      const fits = Array(9).fill(label).join('.');
      expect(fits).toHaveLength(188);
      expect(normaliseRealmHost(fits)).toHaveLength(242);

      const tooLong = Array(10).fill(label).join('.');
      expect(tooLong).toHaveLength(209);
      expect(reasonFor(tooLong)).toBe('too_long');
    });

    it('refuses a label longer than 63 characters', () => {
      expect(reasonFor(`${'a'.repeat(64)}.example.com`)).toBe('malformed');
    });

    it('refuses a label that starts or ends with a hyphen', () => {
      expect(reasonFor('-auth.example.com')).toBe('malformed');
      expect(reasonFor('auth-.example.com')).toBe('malformed');
    });

    it('refuses an invalid port', () => {
      expect(reasonFor('auth.example.com:')).toBe('invalid_port');
      expect(reasonFor('auth.example.com:65536')).toBe('invalid_port');
      expect(reasonFor('auth.example.com:123456')).toBe('invalid_port');
      expect(reasonFor('auth.example.com:https')).toBe('invalid_port');
      expect(reasonFor('[::1]x', 'endpoint')).toBe('invalid_port');
    });

    it('refuses anything that is more than a host', () => {
      expect(reasonFor('https://auth.example.com')).toBe('malformed');
      expect(reasonFor('auth.example.com/realms/a')).toBe('malformed');
      expect(reasonFor('user@auth.example.com')).toBe('malformed');
      expect(reasonFor('auth.example.com?x=1')).toBe('malformed');
      expect(reasonFor('auth.example.com#x')).toBe('malformed');
      expect(reasonFor('auth\\example.com')).toBe('malformed');
    });

    it('refuses percent-encoding instead of decoding it', () => {
      expect(reasonFor('auth%2eexample.com')).toBe('malformed');
      expect(reasonFor('%41uth.example.com')).toBe('malformed');
    });

    it('refuses a name whose last label is a number but not an IPv4 address', () => {
      expect(reasonFor('auth.example.123')).toBe('malformed');
      expect(reasonFor('256.0.0.1', 'endpoint')).toBe('malformed');
    });

    it('refuses characters a host name cannot carry', () => {
      expect(reasonFor('auth!.example.com')).toBe('malformed');
      expect(reasonFor('auth\u0000.example.com')).toBe('malformed');
    });
  });

  it('names the kinds a realm host can have', () => {
    expect(REALM_HOST_KINDS).toEqual(['primary', 'endpoint']);
  });

  it('throws an error that carries a stable code and reason', () => {
    try {
      normaliseRealmHost('*.example.com');
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidRealmHostError);
      expect(error).toMatchObject({
        name: 'InvalidRealmHostError',
        statusCode: 400,
        code: 'INVALID_REALM_HOST',
        reason: 'wildcard',
        input: '*.example.com',
      });
    }
  });

  it('keeps the refused value out of the message', () => {
    const inputs = [
      '',
      'evil\nhost',
      '*.evil-marker.example',
      'evil-marker..example',
      'evil-marker.example:99999',
      'user@evil-marker.example',
      `${'evil-marker.'.repeat(30)}example`,
      '-evil-marker.example',
      '[evil-marker',
      '192.0.2.66',
    ];
    for (const input of inputs) {
      try {
        normaliseRealmHost(input, 'primary');
        expect.unreachable(input);
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidRealmHostError);
        const { message } = error as InvalidRealmHostError;
        expect(message).not.toMatch(/evil|192\.0\.2\.66/);
        expect(message).not.toContain('\n');
      }
    }
  });
});
