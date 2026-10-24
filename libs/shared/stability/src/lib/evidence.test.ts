import { describe, expect, it } from 'vitest';

import { evidenceKind, evidencePath } from './evidence';

describe('evidenceKind', () => {
  it.each([
    ['RFC 9449', 'rfc'],
    ['#476', 'issue'],
    ['https://openid.net/specs/openid-4-verifiable-presentations-1_0.html', 'link'],
    ['apps/auth-server/src/app/wallet-federation.integration.test.ts', 'path'],
    ['docs/security/audit.md#wallet-sign-in', 'path'],
    ['docs/adr/README.md', 'path'],
  ])('reads %s as %s', (evidence, kind) => {
    expect(evidenceKind(evidence)).toBe(kind);
  });

  it.each([
    ['an empty string', ''],
    ['prose', 'a beta ran'],
    ['an RFC without its number', 'RFC '],
    ['an RFC number with a letter', 'RFC 9449a'],
    ['RFC zero', 'RFC 0'],
    ['issue zero', '#0'],
    ['an http link', 'http://example.com'],
    ['an absolute path', '/etc/passwd'],
    ['a path out of the repository', '../outside.md'],
    ['a path through a parent', 'docs/../../outside.md'],
    ['a path through the current directory', './docs/adr/018.md'],
    ['an empty segment', 'docs//adr.md'],
  ])('refuses %s', (_label, evidence) => {
    expect(evidenceKind(evidence)).toBeNull();
  });

  it('refuses a long link that ends in a space in linear time', () => {
    expect(evidenceKind(`https://${'!'.repeat(100_000)} `)).toBeNull();
  });
});

describe('evidencePath', () => {
  it('drops the section', () => {
    expect(evidencePath('docs/security/audit.md#wallet-sign-in')).toBe('docs/security/audit.md');
    expect(evidencePath('docs/security/audit.md')).toBe('docs/security/audit.md');
  });
});
