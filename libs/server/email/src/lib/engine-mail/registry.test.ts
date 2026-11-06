import { describe, expect, it } from 'vitest';

import { DEFAULT_MAIL_BRAND, type MailBrand, resolveMailBrand } from './brand';
import { MAIL_PASS_PATH } from './links';
import {
  ENGINE_MAIL_NAMES,
  ENGINE_MAIL_TEMPLATES,
  type EngineMail,
  engineMailCarriesCode,
  EngineMailError,
  isSwitchedOffByRealm,
  renderEngineMail,
} from './registry';

/** A realm issuer with a path, as the default realm's may carry one. */
const BASE_URL = 'https://auth.acme.example/realms/acme';
const PASS = 'A'.repeat(21) + '-' + 'b'.repeat(20) + '_';

const BRANDED: MailBrand = resolveMailBrand({
  name: 'Acme Login',
  logo: { path: '/assets/brand/logo.png', width: 120, height: 40 },
  colors: { primary: '#aa0011', background: '#fafafa' },
  footer: 'Acme Inc., 1 Main Street',
});

/** One mail of every template, and of every variant a template has. */
const EVERY_MAIL: readonly EngineMail[] = [
  { template: 'code', purpose: 'verify_account', code: '12345678', expiresInSeconds: 600 },
  { template: 'code', purpose: 'verify_account', code: '123456', expiresInSeconds: 600 },
  { template: 'code', purpose: 'recovery', code: '87654321', expiresInSeconds: 600 },
  { template: 'code', purpose: 'confirm_sign_in', code: '654321', expiresInSeconds: 300 },
  { template: 'account_exists' },
  { template: 'account_exists', code: '24681357', expiresInSeconds: 600 },
  { template: 'password_changed' },
  { template: 'password_disabled', pass: PASS, passExpiresInSeconds: 86_400 },
  { template: 'send_ceiling', flow: 'reset', pass: PASS, passExpiresInSeconds: 86_400 },
  { template: 'send_ceiling', flow: 'register', pass: PASS, passExpiresInSeconds: 86_400 },
  { template: 'recovery_code_used', unusedCodes: 9 },
  { template: 'recovery_code_used', unusedCodes: 1 },
  { template: 'recovery_code_used', unusedCodes: 0 },
  { template: 'recovery_codes_regenerated' },
  { template: 'recovery_codes_failed' },
  { template: 'passkey_added' },
];

/** Every `href` and `src` of the HTML, and every URL the plain text spells out. */
function linksOf(html: string, text: string): string[] {
  const attributes = [...html.matchAll(/\b(?:href|src)\s*=\s*"([^"]*)"/gi)].map(
    (match) => match[1]
  );
  const spelled = [...text.matchAll(/[a-z][a-z0-9+.-]*:\/\/[^\s\]<>"')]+/gi)].map(
    (match) => match[0]
  );
  return [...attributes, ...spelled].map((link) => link.replace(/&amp;/g, '&'));
}

describe('the engine mail registry (#637)', () => {
  it('has a sample of every template', () => {
    expect(new Set(EVERY_MAIL.map((mail) => mail.template))).toEqual(new Set(ENGINE_MAIL_NAMES));
  });

  it.each(
    EVERY_MAIL.flatMap((mail) => [
      [mail.template, mail, DEFAULT_MAIL_BRAND] as const,
      [`${mail.template} (branded)`, mail, BRANDED] as const,
    ])
  )('points every link of %s at the realm’s own host', async (_name, mail, brand) => {
    const { html, text } = await renderEngineMail(mail, { baseUrl: BASE_URL, brand });

    for (const link of linksOf(html, text)) {
      expect(link.startsWith(`${BASE_URL}/`), link).toBe(true);
      expect(new URL(link).host).toBe('auth.acme.example');
    }
  });

  it('puts the pass link on the realm’s auth server, never under /ui/', async () => {
    for (const mail of EVERY_MAIL.filter((m) => 'pass' in m)) {
      const { html, text } = await renderEngineMail(mail, {
        baseUrl: BASE_URL,
        brand: DEFAULT_MAIL_BRAND,
      });
      const links = linksOf(html, text).filter((link) => link.includes('pass='));
      expect(links.length, mail.template).toBeGreaterThan(0);
      for (const link of links) {
        expect(link).toBe(`${BASE_URL}${MAIL_PASS_PATH}?pass=${PASS}`);
      }
    }
  });

  it('loads the logo from the realm origin, with the name as its text alternative', async () => {
    const { html } = await renderEngineMail(
      { template: 'password_disabled', pass: PASS, passExpiresInSeconds: 86_400 },
      { baseUrl: BASE_URL, brand: BRANDED }
    );

    expect(html).toContain(`src="${BASE_URL}/assets/brand/logo.png"`);
    expect(html).toContain('alt="Acme Login"');
    expect(html).toContain('#aa0011');
    expect(html).toContain('Acme Inc., 1 Main Street');
  });

  it('renders with the default brand when the realm set none', async () => {
    const { html } = await renderEngineMail(
      { template: 'password_changed' },
      { baseUrl: BASE_URL, brand: resolveMailBrand(undefined) }
    );

    expect(html).toContain('QAuth');
    expect(html).not.toContain('<img');
  });

  it('carries no link and no secret where it carries no pass', async () => {
    for (const mail of EVERY_MAIL.filter((m) => !ENGINE_MAIL_TEMPLATES[m.template].carriesPass)) {
      const { html, text } = await renderEngineMail(mail, {
        baseUrl: BASE_URL,
        brand: DEFAULT_MAIL_BRAND,
      });
      expect(linksOf(html, text), mail.template).toEqual([]);
    }
  });

  it.each([
    ['verify_account', '12345678'],
    ['recovery', '87654321'],
    ['confirm_sign_in', '654321'],
  ] as const)('puts the %s code in the mail and its subject apart', async (purpose, code) => {
    const { subject, text } = await renderEngineMail(
      { template: 'code', purpose, code, expiresInSeconds: 600 },
      { baseUrl: BASE_URL, brand: DEFAULT_MAIL_BRAND }
    );

    expect(text).toContain(code);
    expect(text).toContain('10 minutes');
    expect(subject).not.toContain(code);
  });

  it('counts only the mails that carry a code toward the send caps', () => {
    const counted = EVERY_MAIL.filter(engineMailCarriesCode).map((mail) => mail.template);

    expect(counted).toEqual(['code', 'code', 'code', 'code', 'account_exists']);
    expect(engineMailCarriesCode({ template: 'account_exists' })).toBe(false);
  });

  it('lets no realm switch off the send-ceiling or password-disabled notice', () => {
    const everything = new Set<string>(ENGINE_MAIL_NAMES);

    expect(isSwitchedOffByRealm('send_ceiling', everything)).toBe(false);
    expect(isSwitchedOffByRealm('password_disabled', everything)).toBe(false);
    expect(ENGINE_MAIL_TEMPLATES.send_ceiling.realmMaySwitchOff).toBe(false);
    expect(ENGINE_MAIL_TEMPLATES.password_disabled.realmMaySwitchOff).toBe(false);
  });

  it('lets no realm switch off the recovery codes’ three notices (#649)', () => {
    const everything = new Set<string>(ENGINE_MAIL_NAMES);

    for (const name of [
      'recovery_code_used',
      'recovery_codes_regenerated',
      'recovery_codes_failed',
    ] as const) {
      expect(isSwitchedOffByRealm(name, everything), name).toBe(false);
      expect(ENGINE_MAIL_TEMPLATES[name].realmMaySwitchOff, name).toBe(false);
    }
  });

  it('tells the owner a passkey was added, with no link of its own (#651)', async () => {
    const { subject, text } = await renderEngineMail(
      { template: 'passkey_added' },
      { baseUrl: BASE_URL, brand: DEFAULT_MAIL_BRAND }
    );
    expect(subject).toBe('A passkey was added to your account');
    expect(text.replace(/\s+/g, ' ')).toContain('tell the administrator of this service at once');
    expect(engineMailCarriesCode({ template: 'passkey_added' })).toBe(false);
    expect(isSwitchedOffByRealm('passkey_added', new Set(ENGINE_MAIL_NAMES))).toBe(false);
  });

  it.each([
    [9, '9 of your codes are left'],
    [1, '1 of your codes is left'],
    [0, 'It was the last unused code of your set'],
  ])('says how many recovery codes are left: %i', async (unusedCodes, says) => {
    const { subject, text } = await renderEngineMail(
      { template: 'recovery_code_used', unusedCodes },
      { baseUrl: BASE_URL, brand: DEFAULT_MAIL_BRAND }
    );
    expect(subject).toBe('A recovery code was used to sign in');
    expect(text.replace(/\s+/g, ' ')).toContain(says);
  });

  it('lets no realm switch off any template of the registry', () => {
    const everything = new Set<string>(ENGINE_MAIL_NAMES);

    for (const name of ENGINE_MAIL_NAMES) {
      expect(isSwitchedOffByRealm(name, everything), name).toBe(false);
    }
  });

  it.each([
    [
      'a recovery code of 6 digits',
      { template: 'code', purpose: 'recovery', code: '123456', expiresInSeconds: 600 },
    ],
    [
      'a confirmation code of 8 digits',
      { template: 'code', purpose: 'confirm_sign_in', code: '12345678', expiresInSeconds: 600 },
    ],
    [
      'a code that is not digits',
      { template: 'code', purpose: 'verify_account', code: '12345a', expiresInSeconds: 600 },
    ],
    [
      'a code that lives past 10 minutes',
      { template: 'code', purpose: 'recovery', code: '12345678', expiresInSeconds: 601 },
    ],
    [
      'a pass out of shape',
      { template: 'password_disabled', pass: 'short', passExpiresInSeconds: 60 },
    ],
    [
      'a pass that lives past 24 hours',
      { template: 'send_ceiling', flow: 'reset', pass: PASS, passExpiresInSeconds: 86_401 },
    ],
    [
      'a pass for no flow',
      { template: 'send_ceiling', flow: 'login', pass: PASS, passExpiresInSeconds: 60 },
    ],
    [
      'a count of unused recovery codes past a set',
      { template: 'recovery_code_used', unusedCodes: 11 },
    ],
    [
      'a count of unused recovery codes that is no count',
      { template: 'recovery_code_used', unusedCodes: 1.5 },
    ],
    ['an unknown template', { template: 'welcome' }],
  ])('refuses %s', async (_label, mail) => {
    await expect(
      renderEngineMail(mail as EngineMail, { baseUrl: BASE_URL, brand: DEFAULT_MAIL_BRAND })
    ).rejects.toBeInstanceOf(EngineMailError);
  });

  it.each([
    'https://auth.acme.example/',
    'https://auth.acme.example?x=1',
    'https://auth.acme.example#x',
    'https://user:pw@auth.acme.example',
    'javascript:alert(1)',
    '/relative',
  ])('refuses the base URL %s', async (baseUrl) => {
    await expect(
      renderEngineMail({ template: 'password_changed' }, { baseUrl, brand: DEFAULT_MAIL_BRAND })
    ).rejects.toBeInstanceOf(EngineMailError);
  });
});
