import { describe, expect, it } from 'vitest';

import { extractUrlScheme, isScriptCapableUrl, SCRIPT_CAPABLE_URL_SCHEMES } from './url';

/**
 * The bypass corpus (#239).
 *
 * A scheme denylist is only worth having if it survives the encodings that
 * defeat the naive `value.toLowerCase().startsWith('javascript:')` version:
 * case, TAB/LF/CR/NUL inside the scheme, leading control characters, and HTML
 * character references. Each entry below is a shape a browser navigates as
 * `javascript:` (or another script-capable scheme) despite not reading as one.
 */
const SCRIPT_CAPABLE_BYPASSES: readonly string[] = [
  'javascript:alert(1)',
  'JavaScript:alert(1)',
  'JAVASCRIPT:alert(1)',
  'jAvAsCrIpT:alert(1)',
  ' javascript:alert(1)',
  '\tjavascript:alert(1)',
  '\njavascript:alert(1)',
  '\u0000javascript:alert(1)',
  'java\tscript:alert(1)',
  'java\nscript:alert(1)',
  'java\rscript:alert(1)',
  'java\u0000script:alert(1)',
  'java script:alert(1)',
  'java&#9;script:alert(1)',
  'java&#x09;script:alert(1)',
  'java&Tab;script:alert(1)',
  'java&NewLine;script:alert(1)',
  '&#106;avascript:alert(1)',
  '&#x6A;avascript:alert(1)',
  '&#106avascript:alert(1)',
  'javascript&colon;alert(1)',
  'javascript&#58;alert(1)',
  'vbscript:msgbox(1)',
  'VBScript:msgbox(1)',
  'livescript:alert(1)',
  'mocha:alert(1)',
  'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
  'DATA:text/html,<script>alert(1)</script>',
  'blob:https://evil.example/1234',
  'filesystem:https://evil.example/temporary/x.html',
];

/** Schemes a wallet deployment legitimately configures (OID4VP 1.0 §5). */
const LEGITIMATE_INVOCATION_URIS: readonly string[] = [
  'openid4vp://',
  'openid4vp://authorize?request_uri=https%3A%2F%2Fa.example%2Fr',
  'OpenID4VP://authorize',
  'haip://',
  'eudi-wallet://authorize',
  'eudi-openid4vp://',
  'mdoc-openid4vp://',
  'https://wallet.example/authorize',
  'https://wallet.example/authorize?x=1',
  'x-wallet.vendor+v2://go',
];

describe('extractUrlScheme (#239)', () => {
  it('lowercases the scheme and drops the colon', () => {
    expect(extractUrlScheme('OpenID4VP://authorize')).toBe('openid4vp');
    expect(extractUrlScheme('HTTPS://wallet.example/a')).toBe('https');
    expect(extractUrlScheme('x-wallet.vendor+v2://go')).toBe('x-wallet.vendor+v2');
  });

  it('sees through the encodings a browser strips before navigating', () => {
    expect(extractUrlScheme('java\tscript:alert(1)')).toBe('javascript');
    expect(extractUrlScheme('java&#9;script:alert(1)')).toBe('javascript');
    expect(extractUrlScheme('&#106;avascript:alert(1)')).toBe('javascript');
    expect(extractUrlScheme('javascript&colon;alert(1)')).toBe('javascript');
  });

  it('reports no scheme for a value a browser would treat as relative', () => {
    expect(extractUrlScheme('/ui/login')).toBeUndefined();
    expect(extractUrlScheme('no-scheme')).toBeUndefined();
    expect(extractUrlScheme(':leading-colon')).toBeUndefined();
    // A "scheme" holding characters RFC 3986 forbids is not a scheme at all.
    expect(extractUrlScheme('java script%3Aalert(1)')).toBeUndefined();
    expect(extractUrlScheme('9lives:x')).toBeUndefined();
  });

  it('decodes character references ONCE, exactly like an HTML parser', () => {
    // A browser decodes `&amp;` to `&`, leaving the literal text
    // `&#106;avascript:` in the href — which is a relative reference, not a
    // scheme. Re-scanning here would make this filter disagree with reality.
    expect(extractUrlScheme('&amp;#106;avascript:alert(1)')).toBeUndefined();
  });

  it('rejects non-strings and the empty string', () => {
    expect(extractUrlScheme('')).toBeUndefined();
    expect(extractUrlScheme(undefined)).toBeUndefined();
    expect(extractUrlScheme(null)).toBeUndefined();
    expect(extractUrlScheme(42)).toBeUndefined();
    expect(extractUrlScheme({ toString: () => 'javascript:alert(1)' })).toBeUndefined();
  });
});

describe('isScriptCapableUrl (#239)', () => {
  it.each(SCRIPT_CAPABLE_BYPASSES)('refuses %j', (value) => {
    expect(isScriptCapableUrl(value)).toBe(true);
  });

  it.each(LEGITIMATE_INVOCATION_URIS)('permits the wallet scheme %j', (value) => {
    expect(isScriptCapableUrl(value)).toBe(false);
  });

  it('does not refuse a relative reference or a non-string', () => {
    expect(isScriptCapableUrl('/ui/login')).toBe(false);
    expect(isScriptCapableUrl(undefined)).toBe(false);
  });

  it('names every scheme it refuses in lowercase, colon-free form', () => {
    for (const scheme of SCRIPT_CAPABLE_URL_SCHEMES) {
      expect(scheme).toMatch(/^[a-z][a-z0-9+.-]*$/);
    }
    expect(SCRIPT_CAPABLE_URL_SCHEMES.has('javascript')).toBe(true);
    expect(SCRIPT_CAPABLE_URL_SCHEMES.has('data')).toBe(true);
    expect(SCRIPT_CAPABLE_URL_SCHEMES.has('vbscript')).toBe(true);
  });
});
