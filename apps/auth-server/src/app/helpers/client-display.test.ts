import { InvalidRequestError } from '@qauth-labs/shared-errors';
import { INTERACTION_OPENAPI } from '@qauth-labs/shared-interaction-contract';
import {
  componentValidator,
  describeErrors,
} from '@qauth-labs/shared-interaction-contract/src/testing/schema-validator';
import {
  DISPLAY_HOST_MAX_LENGTH,
  DISPLAY_HOST_PATTERN,
  DISPLAY_SCHEME_MAX_LENGTH,
  DISPLAY_SCHEME_PATTERN,
  isLoopbackHost,
} from '@qauth-labs/shared-validation';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
  },
}));

import {
  clientDisplay,
  type ClientDisplaySource,
  DECLARED_NAME_MAX_LENGTH,
  declaredText,
} from './client-display';

/** The contract's ClientDisplay schema, which every result must meet. */
const components = componentValidator(INTERACTION_OPENAPI);
const validateClientDisplay = components.schema('ClientDisplay');
const contractClientDisplay = (
  INTERACTION_OPENAPI['components'] as {
    schemas: Record<string, { properties: Record<string, Record<string, unknown>> }>;
  }
).schemas['ClientDisplay'];

/** A logo URL a client supplied: no result may ever carry it. */
const CLIENT_LOGO = 'https://cdn.example.net/logo.png';

const cimdClient = (clientId: string, extra: Partial<ClientDisplaySource> = {}) => ({
  clientId,
  name: 'Example Notes',
  metadata: { registrationType: 'cimd', client_id_metadata_url: clientId, logo_uri: CLIENT_LOGO },
  dynamicRegisteredAt: null,
  provisionedByOperator: false,
  verifiedDomain: null,
  ...extra,
});

const dynamicClient = (extra: Partial<ClientDisplaySource> = {}): ClientDisplaySource => ({
  clientId: '01890f4e-7a3b-7c1d-8e2f-000000000001',
  name: 'Notes Helper',
  metadata: { registrationType: 'dynamic', logoUri: CLIENT_LOGO, clientUri: 'https://x.example' },
  dynamicRegisteredAt: Date.now() - 60_000,
  provisionedByOperator: false,
  verifiedDomain: null,
  ...extra,
});

const developerClient = (extra: Partial<ClientDisplaySource> = {}): ClientDisplaySource => ({
  clientId: '01890f4e-7a3b-7c1d-8e2f-000000000002',
  name: 'My App',
  metadata: null,
  dynamicRegisteredAt: null,
  provisionedByOperator: false,
  verifiedDomain: null,
  ...extra,
});

const adminClient = (extra: Partial<ClientDisplaySource> = {}): ClientDisplaySource => ({
  clientId: 'notes',
  name: 'Notes',
  metadata: { logo_uri: CLIENT_LOGO },
  dynamicRegisteredAt: null,
  provisionedByOperator: true,
  verifiedDomain: 'notes.example.com',
  ...extra,
});

/** `clientDisplay`, checked against the contract on every call. */
function display(client: ClientDisplaySource, redirectUri?: string) {
  const result = clientDisplay(client, redirectUri === undefined ? {} : { redirectUri });
  expect(validateClientDisplay(result), describeErrors(validateClientDisplay)).toBe(true);
  return result;
}

describe('clientDisplay (ADR-019 Decision 6, #593)', () => {
  describe('a CIMD client: the host of its client id URL', () => {
    it('returns an IDN host in its xn-- form', () => {
      expect(display(cimdClient('https://bücher.example/client.json')).verifiedDomain).toEqual({
        host: 'xn--bcher-kva.example',
        registrableDomain: 'xn--bcher-kva.example',
        sharedHosting: false,
      });
      expect(
        display(cimdClient('https://app.xn--80ak6aa92e.xn--p1ai/client.json')).verifiedDomain
      ).toEqual({
        host: 'app.xn--80ak6aa92e.xn--p1ai',
        registrableDomain: 'xn--80ak6aa92e.xn--p1ai',
        sharedHosting: false,
      });
    });

    it('marks the registrable domain, under multi-label public suffixes too', () => {
      expect(display(cimdClient('https://Notes.Example.com/c')).verifiedDomain).toEqual({
        host: 'notes.example.com',
        registrableDomain: 'example.com',
        sharedHosting: false,
      });
      expect(display(cimdClient('https://app.example.co.uk/c')).verifiedDomain).toEqual({
        host: 'app.example.co.uk',
        registrableDomain: 'example.co.uk',
        sharedHosting: false,
      });
      expect(display(cimdClient('https://example.com./c')).verifiedDomain?.host).toBe(
        'example.com'
      );
    });

    // Public Suffix List private section: names under these suffixes belong
    // to unrelated parties, so the registrable domain is the owner's name and
    // the screen flags the host.
    it.each([
      ['alice.eu.org', 'alice.eu.org'],
      ['notes.alice.eu.org', 'alice.eu.org'],
      ['notes.bob.co.com', 'bob.co.com'],
      ['carol.uk.com', 'carol.uk.com'],
    ])('flags %s as shared hosting', (host, registrableDomain) => {
      expect(display(cimdClient(`https://${host}/client.json`)).verifiedDomain).toEqual({
        host,
        registrableDomain,
        sharedHosting: true,
      });
    });

    it('flags a host that is itself a private-section suffix', () => {
      expect(display(cimdClient('https://eu.org/client.json')).verifiedDomain).toEqual({
        host: 'eu.org',
        registrableDomain: 'eu.org',
        sharedHosting: true,
      });
    });

    it('ignores the verified_domain column: only the client id URL is verified', () => {
      const result = display(
        cimdClient('https://notes.example.com/c', {
          provisionedByOperator: true,
          verifiedDomain: 'bank.example',
        })
      );
      expect(result.kind).toBe('cimd');
      expect(result.verifiedDomain?.host).toBe('notes.example.com');
    });

    it('is unverified when the client id is not an https URL with a showable host', () => {
      for (const clientId of [
        'not a url',
        'http://notes.example.com/c',
        'https://[2001:db8::1]/c',
      ]) {
        const result = display(cimdClient(clientId));
        expect(result.kind, clientId).toBe('unverified');
        expect(result.verifiedDomain, clientId).toBeUndefined();
      }
    });
  });

  describe('a client an admin registered: the domain the admin set', () => {
    it('returns the stored domain with its registrable domain', () => {
      const result = display(adminClient(), 'https://notes.example.com/cb');
      expect(result).toEqual({
        kind: 'admin_registered',
        verifiedDomain: {
          host: 'notes.example.com',
          registrableDomain: 'example.com',
          sharedHosting: false,
        },
        redirect: { target: 'host', host: 'notes.example.com' },
        declaredName: 'Notes',
        newClient: false,
      });
    });

    it('counts the domain only while the operator vouches for the client', () => {
      // An owner who changed the redirect URIs cleared provisioned_by_operator.
      expect(display(adminClient({ provisionedByOperator: false })).kind).toBe('unverified');
      expect(display(adminClient({ verifiedDomain: null })).kind).toBe('unverified');
    });

    it('reads a stored public suffix as no verified domain', () => {
      for (const verifiedDomain of ['co.uk', 'eu.org']) {
        expect(display(adminClient({ verifiedDomain })).kind, verifiedDomain).toBe('unverified');
      }
      expect(display(adminClient({ verifiedDomain: 'alice.eu.org' })).verifiedDomain).toEqual({
        host: 'alice.eu.org',
        registrableDomain: 'alice.eu.org',
        sharedHosting: true,
      });
    });

    it('reads a stored value in any other form as no verified domain', () => {
      for (const verifiedDomain of [
        'Notes.example.com',
        'bücher.example',
        'localhost',
        '1.2.3.4',
      ]) {
        expect(display(adminClient({ verifiedDomain })).kind, verifiedDomain).toBe('unverified');
      }
    });
  });

  describe('a dynamically registered or developer-portal client: unverified', () => {
    it('returns unverified, the host that receives the code, and no verified domain', () => {
      const result = display(dynamicClient(), 'https://notes-helper.example.net/callback');
      expect(result).toEqual({
        kind: 'unverified',
        redirect: { target: 'host', host: 'notes-helper.example.net' },
        declaredName: 'Notes Helper',
        newClient: true,
      });
      expect(result).not.toHaveProperty('verifiedDomain');
    });

    it('never verifies a self-registered client, whatever its row holds', () => {
      // No registration path writes the column; a hand-set value still does not count.
      for (const client of [
        dynamicClient({ verifiedDomain: 'bank.example' }),
        developerClient({ verifiedDomain: 'bank.example' }),
      ]) {
        const result = display(client, 'https://app.example/cb');
        expect(result.kind).toBe('unverified');
        expect(result.verifiedDomain).toBeUndefined();
      }
    });

    it('returns a developer-portal client as unverified, not new', () => {
      expect(display(developerClient(), 'https://app.example/cb')).toEqual({
        kind: 'unverified',
        redirect: { target: 'host', host: 'app.example' },
        declaredName: 'My App',
        newClient: false,
      });
    });

    it('shows a native app by its URI scheme', () => {
      expect(display(dynamicClient(), 'com.example.notes:/callback').redirect).toEqual({
        target: 'app',
        scheme: 'com.example.notes',
      });
    });

    // Registration refuses these since #593; a client registered before can hold one.
    it.each([
      'https://[2001:db8::1]/cb',
      'https://my_app.example.com/cb',
      'https://a..b.example/cb',
      `com.example.${'a'.repeat(60)}:/cb`,
    ])('refuses to describe %s, which the contract cannot carry', (redirectUri) => {
      expect(() => clientDisplay(dynamicClient(), { redirectUri })).toThrow(InvalidRequestError);
    });

    it('omits the redirect where no code goes', () => {
      expect(display(dynamicClient())).not.toHaveProperty('redirect');
    });
  });

  describe('a loopback redirect: "this device", with the warning', () => {
    it.each([
      'http://localhost/cb',
      'http://localhost:8080/cb',
      'http://127.0.0.1:3000/cb',
      'http://127.1.2.3/cb',
      'http://127.255.255.254:9000/cb',
      'http://[::1]:5173/cb',
      'http://[::ffff:127.0.0.1]/cb',
      'https://dev.localhost/cb',
      'http://0.0.0.0:8080/cb',
    ])('returns %s as this device', (redirectUri) => {
      // `this_device` is the contract's warning flag: the screen shows "this
      // device" with a warning, for every client class.
      expect(display(dynamicClient(), redirectUri).redirect).toEqual({ target: 'this_device' });
      expect(display(cimdClient('https://notes.example.com/c'), redirectUri).redirect).toEqual({
        target: 'this_device',
      });
    });

    it.each([
      'https://app.example.com/cb',
      'https://12.7.0.0.1.example.com/cb',
      'https://128.0.0.1/cb',
      'https://localhost.example.com/cb',
    ])('does not return %s as this device', (redirectUri) => {
      expect(display(dynamicClient(), redirectUri).redirect?.target).toBe('host');
    });

    it('reads the host as the URL parser writes it', () => {
      expect(isLoopbackHost('[::1]')).toBe(true);
      expect(isLoopbackHost('LOCALHOST')).toBe(true);
      expect(isLoopbackHost('localhost.')).toBe(true);
      expect(isLoopbackHost('[::ffff:7f00:1]')).toBe(true);
      expect(isLoopbackHost('[::ffff:c000:201]')).toBe(false);
      expect(isLoopbackHost('notlocalhost')).toBe(false);
    });
  });

  describe('the declared name', () => {
    it('strips control and bidirectional characters', () => {
      // U+202E RIGHT-TO-LEFT OVERRIDE would show "Bank" + "lpp.liave" reversed.
      expect(display(dynamicClient({ name: 'Bank\u202Eevil.app\u202C' })).declaredName).toBe(
        'Bankevil.app'
      );
      expect(declaredText('\u2066Notes\u2069\u200B\u200D\u200E\u200F\u061C\uFEFF Helper', 64)).toBe(
        'Notes Helper'
      );
      expect(declaredText('Notes\u0000\u0007\u001B[31m\u007F\u009B', 64)).toBe('Notes[31m');
      expect(declaredText('Notes\uE000\uDB80', 64)).toBe('Notes');
    });

    it('turns line breaks into one space and trims', () => {
      expect(declaredText('  Notes\n\nHelper\u2028v2\t ', 64)).toBe('Notes Helper v2');
      expect(declaredText('Notes\u00A0\u3000\u2003Helper', 64)).toBe('Notes Helper');
    });

    it('removes markup brackets and Hangul fillers, and returns nothing for a blank name', () => {
      expect(declaredText('<b>Notes</b>', 64)).toBe('bNotes/b');
      expect(declaredText('\u3164\u115F\u1160\uFFA0', 64)).toBeUndefined();
      expect(display(dynamicClient({ name: '\u202E\u200B ' }))).not.toHaveProperty('declaredName');
    });

    it('cuts a name over the cap, at a grapheme boundary', () => {
      const long = `Notes ${'x'.repeat(100)}`;
      const name = display(dynamicClient({ name: long })).declaredName ?? '';
      expect([...name]).toHaveLength(DECLARED_NAME_MAX_LENGTH);
      expect(name.endsWith('\u2026')).toBe(true);
      expect(long.startsWith(name.slice(0, -1))).toBe(true);

      // A letter with two combining marks that have no precomposed form is one
      // grapheme of three code points; the cut never splits it.
      const marked = 'x\u0301\u0302';
      expect(declaredText(`${'a'.repeat(61)}${marked}b`, 64)).toBe(`${'a'.repeat(61)}\u2026`);
      expect(declaredText(`${'a'.repeat(60)}${marked}b`, 64)).toBe(`${'a'.repeat(60)}${marked}b`);

      // A zero-width joiner is a format character, so an emoji sequence
      // comes out as its separate emoji.
      expect(declaredText('\u{1F468}\u200D\u{1F469}', 64)).toBe('\u{1F468}\u{1F469}');

      // A name exactly at the cap stays whole.
      expect(declaredText('n'.repeat(64), 64)).toBe('n'.repeat(64));
    });

    it('keeps at most four combining marks on a character, and none before the first', () => {
      // A stack of marks draws over the lines above the name.
      const stacked = `G\u0300\u0301\u0302\u0303\u0304\u0305\u0306\u0307\u0308\u0309\u030A\u030B\u030C\u030D\u030E\u030F\u0310\u0311\u0312\u0313\u0314\u0315\u0316\u0317\u0318\u0319\u031A\u031B\u031C\u031D\u031E\u031F\u0320\u0321\u0322\u0323\u0324\u0325\u0326\u0327\u0328\u0329\u032A\u032B\u032C\u032D\u032E\u032F\u0330\u0331\u0332\u0333\u0334\u0335\u0336\u0337\u0338\u0339\u033A\u033B\u033C\u033Do`;
      const kept = declaredText(stacked, 64) ?? '';
      // NFC puts the marks in canonical order first; four of them stay.
      expect([...kept]).toHaveLength(6);
      expect(kept.startsWith('G') && kept.endsWith('o')).toBe(true);
      expect([...kept.slice(1, -1)].every((char) => /\p{M}/u.test(char))).toBe(true);
      // Natural text keeps its marks: a Devanagari conjunct with a virama and a vowel sign.
      expect(declaredText('\u0915\u094D\u0937\u093F', 64)).toBe('\u0915\u094D\u0937\u093F');
      expect(declaredText('\u0336\u0301Notes', 64)).toBe('Notes');
    });

    it('removes the blank braille pattern, which renders as nothing', () => {
      expect(declaredText('\u2800\u2800\u2800', 64)).toBeUndefined();
      expect(declaredText('Notes\u2800Helper', 64)).toBe('NotesHelper');
    });

    it('puts the name in NFC', () => {
      expect(declaredText('Cafe\u0301', 64)).toBe('Caf\u00E9');
    });

    it('is always marked as declared and never comes first', () => {
      expect(contractClientDisplay.properties['declaredName']['x-qauth-display']).toBe('declared');
      for (const result of [
        display(cimdClient('https://notes.example.com/c'), 'https://notes.example.com/cb'),
        display(adminClient(), 'http://localhost/cb'),
        display(dynamicClient(), 'https://notes-helper.example.net/cb'),
        display(developerClient()),
      ]) {
        const keys = Object.keys(result);
        expect(keys[0]).toBe('kind');
        expect(keys).toContain('declaredName');
        for (const verified of ['verifiedDomain', 'federation', 'redirect']) {
          if (keys.includes(verified)) {
            expect(keys.indexOf('declaredName')).toBeGreaterThan(keys.indexOf(verified));
          }
        }
      }
    });
  });

  it('never returns a logo URL a client supplied', () => {
    const clients = [
      cimdClient('https://notes.example.com/c'),
      dynamicClient(),
      developerClient({ metadata: { logo_uri: CLIENT_LOGO, logoUri: CLIENT_LOGO } }),
      adminClient(),
    ];
    for (const client of clients) {
      const result = display(client, 'https://notes.example.com/cb');
      expect(result).not.toHaveProperty('logo');
      expect(JSON.stringify(result)).not.toContain('cdn.example.net');
    }
  });

  it('keeps its limits equal to the contract', () => {
    const properties = contractClientDisplay.properties;
    expect(properties['declaredName']['maxLength']).toBe(DECLARED_NAME_MAX_LENGTH);
    const verifiedDomain = properties['verifiedDomain'] as {
      properties: Record<string, { pattern: string }>;
    };
    expect(verifiedDomain.properties['host'].pattern).toBe(DISPLAY_HOST_PATTERN);
    const redirect = properties['redirect'] as {
      properties: Record<string, { pattern: string; maxLength: number }>;
    };
    expect(redirect.properties['host'].pattern).toBe(DISPLAY_HOST_PATTERN);
    expect(redirect.properties['scheme'].pattern).toBe(DISPLAY_SCHEME_PATTERN);
    expect(redirect.properties['host']['maxLength']).toBe(DISPLAY_HOST_MAX_LENGTH);
    expect(redirect.properties['scheme']['maxLength']).toBe(DISPLAY_SCHEME_MAX_LENGTH);
  });
});
