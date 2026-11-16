import { describe, expect, it } from 'vitest';

import {
  ANY_CLIENT,
  consentTextFor,
  isQauthOwnScope,
  protectedResourceClientsSchema,
  protectedResourceIndicatorProblem,
  protectedResourceScopesSchema,
} from './protected-resource';

describe('protected resource rules (#1087)', () => {
  it('takes an absolute URI with no fragment as the indicator, and no QAuth API audience', () => {
    expect(protectedResourceIndicatorProblem('https://mcp.example.com/mcp')).toBeUndefined();
    expect(protectedResourceIndicatorProblem('http://localhost:8088')).toBeUndefined();
    expect(protectedResourceIndicatorProblem('urn:example:files')).toBeUndefined();
    expect(protectedResourceIndicatorProblem('')).toBe('is empty');
    expect(protectedResourceIndicatorProblem('/mcp')).toMatch(/absolute URI/);
    expect(protectedResourceIndicatorProblem('https://mcp.example.com/#x')).toMatch(/fragment/);
    expect(protectedResourceIndicatorProblem('https://mcp.example.com/a b')).toMatch(/character/);
    expect(protectedResourceIndicatorProblem(`https://e.example/${'a'.repeat(2048)}`)).toMatch(
      /longer/
    );
    expect(protectedResourceIndicatorProblem('urn:qauth:aud:admin')).toMatch(/QAuth API audience/);
  });

  it("never lets a resource define one of QAuth's own scopes, in any case", () => {
    for (const scope of ['openid', 'Profile', 'email', 'offline_access', 'agent:exec', 'AGENT:x']) {
      expect(isQauthOwnScope(scope)).toBe(true);
    }
    expect(isQauthOwnScope('qauth:admin:read')).toBe(true);
    expect(isQauthOwnScope('QAuth:anything')).toBe(true);
    expect(isQauthOwnScope('files:read')).toBe(false);
    expect(isQauthOwnScope('write:files')).toBe(false);

    const refused = protectedResourceScopesSchema.safeParse([
      { scope: 'openid', text: { en: 'Your identity' } },
    ]);
    expect(refused.success).toBe(false);
  });

  it('needs English text, keys texts by BCP 47 tags and refuses text the consent step cannot show', () => {
    const ok = protectedResourceScopesSchema.safeParse([
      { scope: 'files:read', text: { en: 'Read your files', 'pt-BR': 'Ler seus arquivos' } },
      { scope: 'files:write', text: { en: 'Change your files' }, sensitive: true },
    ]);
    expect(ok.success).toBe(true);

    const cases: unknown[] = [
      [{ scope: 'files:read', text: { tr: 'Dosyalarınızı okuma' } }],
      [{ scope: 'files:read', text: { en: 'Read <b>files</b>' } }],
      [{ scope: 'files:read', text: { en: ' padded' } }],
      [{ scope: 'files:read', text: { en: 'zero​width' } }],
      [{ scope: 'files:read', text: { en: 'x'.repeat(281) } }],
      [{ scope: 'files:read', text: { en: 'Read', EN_us: 'Read' } }],
      [{ scope: 'files read', text: { en: 'Read' } }],
      [{ scope: 'files:read', text: { en: 'Read' }, extra: true }],
      [
        { scope: 'files:read', text: { en: 'Read' } },
        { scope: 'files:read', text: { en: 'Read again' } },
      ],
      [],
    ];
    for (const value of cases) {
      expect(protectedResourceScopesSchema.safeParse(value).success, JSON.stringify(value)).toBe(
        false
      );
    }
  });

  it('opens a resource to every client or to listed clients, one at least, each once', () => {
    expect(protectedResourceClientsSchema.parse(ANY_CLIENT)).toBe(ANY_CLIENT);
    expect(protectedResourceClientsSchema.parse(['app', 'https://agent.example/c.json'])).toEqual([
      'app',
      'https://agent.example/c.json',
    ]);
    expect(protectedResourceClientsSchema.safeParse([]).success).toBe(false);
    expect(protectedResourceClientsSchema.safeParse(['app', 'app']).success).toBe(false);
    expect(protectedResourceClientsSchema.safeParse('every_client').success).toBe(false);
  });

  it('picks the text of the first matching locale, by tag then language, else English', () => {
    const text = { en: 'Read your files', tr: 'Dosyalarınızı okuma', 'pt-BR': 'Ler arquivos' };
    expect(consentTextFor(text, ['tr'])).toBe('Dosyalarınızı okuma');
    expect(consentTextFor(text, ['tr-TR'])).toBe('Dosyalarınızı okuma');
    expect(consentTextFor(text, ['PT-br'])).toBe('Ler arquivos');
    expect(consentTextFor(text, ['de', 'tr'])).toBe('Dosyalarınızı okuma');
    expect(consentTextFor(text, ['de'])).toBe('Read your files');
    expect(consentTextFor(text, [])).toBe('Read your files');
  });
});
