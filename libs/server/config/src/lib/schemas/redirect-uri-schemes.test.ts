import { describe, expect, it } from 'vitest';

import { authEnvSchema } from './auth';
import { REFUSED_CUSTOM_REDIRECT_URI_SCHEMES } from './redirect-uri-schemes';

/**
 * REDIRECT_URI_CUSTOM_SCHEMES (#774) names the bare schemes, such as `cursor`,
 * a redirect URI may use besides https, loopback http and reverse-domain
 * schemes. It widens what registration and authorization accept, so boot
 * refuses an entry that is not a scheme name or that a browser or the
 * operating system acts on itself.
 */
function customSchemes(raw: string | undefined): readonly string[] {
  return authEnvSchema.parse(raw === undefined ? {} : { REDIRECT_URI_CUSTOM_SCHEMES: raw })
    .REDIRECT_URI_CUSTOM_SCHEMES;
}

/** The boot errors for `raw`, as the operator reads them. */
function bootErrors(raw: string): string[] {
  const result = authEnvSchema.safeParse({ REDIRECT_URI_CUSTOM_SCHEMES: raw });
  if (result.success) return [];
  return result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`);
}

describe('authEnvSchema REDIRECT_URI_CUSTOM_SCHEMES', () => {
  it('is empty when unset or blank', () => {
    expect(customSchemes(undefined)).toEqual([]);
    expect(customSchemes('')).toEqual([]);
    expect(customSchemes(' , ')).toEqual([]);
  });

  it('splits on spaces and commas, lower-cases and drops repeats', () => {
    expect(customSchemes('cursor')).toEqual(['cursor']);
    expect(customSchemes('Cursor, vscode-insiders  cursor,app+dev')).toEqual([
      'cursor',
      'vscode-insiders',
      'app+dev',
    ]);
  });

  it('accepts a name with a period, which the reverse-domain rule already allows', () => {
    expect(customSchemes('com.example.app')).toEqual(['com.example.app']);
  });

  it.each(['cursor:', 'cursor://', '1app', '-app', 'my_app', 'app/x', 'çursor'])(
    'refuses %s, which is not a scheme name, naming the variable and the entry',
    (raw) => {
      expect(bootErrors(raw)).toEqual([
        expect.stringMatching(
          /^REDIRECT_URI_CUSTOM_SCHEMES: REDIRECT_URI_CUSTOM_SCHEMES entry ".+" is not a URI scheme name/
        ),
      ]);
    }
  );

  it.each(['http', 'HTTPS'])('refuses %s, which has rules of its own', (raw) => {
    expect(bootErrors(`cursor ${raw}`)).toEqual([
      expect.stringContaining(
        `REDIRECT_URI_CUSTOM_SCHEMES entry "${raw.toLowerCase()}" is not allowed: https redirect URIs`
      ),
    ]);
  });

  it.each([...REFUSED_CUSTOM_REDIRECT_URI_SCHEMES].filter((s) => s !== 'http' && s !== 'https'))(
    'refuses %s, which a browser or the operating system acts on itself',
    (scheme) => {
      expect(bootErrors(`cursor,${scheme}`)).toEqual([
        expect.stringContaining(
          `REDIRECT_URI_CUSTOM_SCHEMES entry "${scheme}" is not allowed: a browser or the operating system`
        ),
      ]);
    }
  );

  it('refuses the schemes the redirect gate has always refused', () => {
    for (const scheme of ['javascript', 'data', 'vbscript', 'file', 'blob', 'about', 'intent']) {
      expect(REFUSED_CUSTOM_REDIRECT_URI_SCHEMES.has(scheme)).toBe(true);
    }
  });

  it('reports every bad entry, not only the first', () => {
    const errors = bootErrors('javascript cursor: file cursor');
    expect(errors).toHaveLength(3);
    expect(errors.join('\n')).toContain('"javascript"');
    expect(errors.join('\n')).toContain('"cursor:"');
    expect(errors.join('\n')).toContain('"file"');
  });
});
