import { describe, expect, it } from 'vitest';

import {
  InvalidVerifiedDomainError,
  type InvalidVerifiedDomainReason,
  isVerifiedDomain,
  normaliseVerifiedDomain,
  VERIFIED_DOMAIN_MAX_LENGTH,
  VERIFIED_DOMAIN_PATTERN,
} from './verified-domain';

/** The reason `normaliseVerifiedDomain` gives for refusing `input`. */
function reasonFor(input: string): InvalidVerifiedDomainReason {
  try {
    normaliseVerifiedDomain(input);
  } catch (error) {
    expect(error).toBeInstanceOf(InvalidVerifiedDomainError);
    if (input !== '') expect((error as Error).message).not.toContain(input);
    return (error as InvalidVerifiedDomainError).reason;
  }
  throw new Error(`expected "${input}" to be refused`);
}

describe('normaliseVerifiedDomain (#593)', () => {
  it('lower-cases and drops a trailing dot', () => {
    expect(normaliseVerifiedDomain('App.Example.COM.')).toBe('app.example.com');
  });

  it('writes an internationalised name in its xn-- form', () => {
    expect(normaliseVerifiedDomain('bücher.example')).toBe('xn--bcher-kva.example');
    expect(normaliseVerifiedDomain('xn--bcher-kva.example')).toBe('xn--bcher-kva.example');
  });

  it('refuses an IP address', () => {
    expect(reasonFor('192.0.2.1')).toBe('ip_literal');
    expect(reasonFor('[2001:db8::1]')).toBe('ip_literal');
  });

  it('refuses a single label', () => {
    expect(reasonFor('localhost')).toBe('single_label');
    expect(reasonFor('intranet')).toBe('single_label');
  });

  it('refuses anything that is not a bare DNS name', () => {
    for (const input of [
      '',
      'example.com:443',
      'https://example.com',
      'example.com/path',
      '*.example.com',
      'a..example.com',
      'auth_server.example',
      'user@example.com',
      'exa mple.com',
      '-a.example.com',
      'example.123',
    ]) {
      expect(['malformed', 'single_label'], input).toContain(reasonFor(input));
    }
  });

  it('refuses a name over 253 characters', () => {
    const label = 'a'.repeat(63);
    const long = [label, label, label, label].join('.') + '.example';
    expect(long.length).toBeGreaterThan(VERIFIED_DOMAIN_MAX_LENGTH);
    expect(reasonFor(long)).toBe('too_long');
  });
});

describe('isVerifiedDomain (#593)', () => {
  it('accepts the stored form only', () => {
    expect(isVerifiedDomain('app.example.com')).toBe(true);
    expect(isVerifiedDomain('xn--bcher-kva.example')).toBe(true);
    for (const value of [
      'App.example.com',
      'bücher.example',
      'example.com.',
      'localhost',
      '192.0.2.1',
      'example.com:443',
      '',
      null,
      42,
    ]) {
      expect(isVerifiedDomain(value), String(value)).toBe(false);
    }
  });

  it('reads the pattern the same way as a POSIX expression would: no lookaround or shorthand', () => {
    expect(VERIFIED_DOMAIN_PATTERN).not.toMatch(/\(\?|\\[dws]/);
  });
});
