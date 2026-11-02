import { describe, expect, it } from 'vitest';

import {
  ACCOUNT_API_AUDIENCE,
  ACT_CHAIN_RULES,
  FRESH_AUTHENTICATION_MAX_AGE_SECONDS,
  FRESH_AUTHENTICATION_RULES,
} from './identifiers';
import { ACCOUNT_OPENAPI, ACCOUNT_SECURITY, tokenSentence } from './openapi';
import { ACCOUNT_OPERATIONS, operationCodes, operationNamed } from './operations';

/**
 * The acceptance criterion "each operation names its token audience, whether
 * it needs fresh authentication, and whether it refuses an act-chain token",
 * and the rules of ADR-019 Decision 7 and ADR-017 Decision 8 behind the
 * answers.
 */

const paths = (ACCOUNT_OPENAPI as { paths: Record<string, Record<string, Operation>> }).paths;

interface Operation {
  operationId: string;
  description: string;
  security: unknown;
  parameters?: Array<{ name: string; in: string; required: boolean }>;
  requestBody?: { content: Record<string, unknown> };
  responses: Record<
    string,
    { headers?: Record<string, unknown>; 'x-qauth-problem-codes'?: string[] }
  >;
  'x-qauth-audience': string;
  'x-qauth-fresh-authentication': string;
  'x-qauth-act-chain': string;
  'x-qauth-class': string;
  'x-qauth-permission': string;
}

const published = Object.values(paths).flatMap((item) => Object.values(item));
const publishedNamed = (id: string) => {
  const operation = published.find((candidate) => candidate.operationId === id);
  if (operation === undefined) throw new Error(`no published ${id}`);
  return operation;
};

/**
 * What each operation asks of the token: `[fresh authentication, act-chain]`.
 * Written out, so a change to either is a visible change to this table.
 *
 * ADR-019 Decision 7: an act-chain token is refused on every operation that
 * changes a credential (password, passkeys, TOTP, recovery codes), an
 * identifier or the contact address (the address change), or a linked
 * account, and on deletion. The security log's "this wasn't me" refuses one
 * too: only the person may disown a sign-in, and the report forces a new
 * password at the next sign-in. ADR-017 Decision 8: the same changes need
 * fresh authentication with the strongest factor; the rebind after a lost
 * second factor (removing it, binding a new authenticator app) also takes a
 * recovery-code sign-in. Renaming a passkey changes no credential, so it
 * needs no fresh authentication (ADR-020 §3), but its record is still the
 * person's to change. Ending sessions and revoking a consent only take access
 * away, so they need neither.
 */
const EXPECTED: Record<string, readonly [string, string]> = {
  'account.profile.get': ['none', 'accepted'],
  'account.profile.update': ['none', 'accepted'],
  'account.signInMethods.get': ['none', 'accepted'],
  'account.password.change': ['strongest-factor', 'refused'],
  'account.passkeys.list': ['none', 'accepted'],
  'account.passkeys.get': ['none', 'accepted'],
  'account.passkeys.update': ['none', 'refused'],
  'account.passkeys.delete': ['strongest-factor-or-recovery-code', 'refused'],
  'account.totp.enrollment.create': ['strongest-factor-or-recovery-code', 'refused'],
  'account.totp.enrollment.confirm': ['strongest-factor-or-recovery-code', 'refused'],
  'account.totp.delete': ['strongest-factor-or-recovery-code', 'refused'],
  'account.recoveryCodes.get': ['none', 'accepted'],
  'account.recoveryCodes.regenerate': ['strongest-factor', 'refused'],
  'account.sessions.list': ['none', 'accepted'],
  'account.sessions.delete': ['none', 'accepted'],
  'account.sessions.endAll': ['none', 'accepted'],
  'account.securityLog.list': ['none', 'accepted'],
  'account.securityLog.report': ['none', 'refused'],
  'account.addresses.get': ['none', 'accepted'],
  'account.addressChange.create': ['strongest-factor', 'refused'],
  'account.addressChange.confirm': ['strongest-factor', 'refused'],
  'account.consents.list': ['none', 'accepted'],
  'account.consents.delete': ['none', 'accepted'],
  'account.deletion.get': ['none', 'accepted'],
  'account.deletion.create': ['strongest-factor', 'refused'],
  'account.notificationPreferences.get': ['none', 'accepted'],
};

describe('the operations', () => {
  it('cover the resources of the issue, one table entry each', () => {
    expect(ACCOUNT_OPERATIONS.map((operation) => operation.id).sort()).toEqual(
      Object.keys(EXPECTED).sort()
    );
    const tags = new Set(ACCOUNT_OPERATIONS.map((operation) => operation.tag));
    expect([...tags].sort()).toEqual(
      [
        'Account',
        'Addresses',
        'Connected apps',
        'Notifications',
        'Profile',
        'Security log',
        'Sessions',
        'Sign-in methods',
      ].sort()
    );
  });

  it.each(Object.entries(EXPECTED))('%s asks %j of the token', (id, [fresh, act]) => {
    const operation = operationNamed(id);
    expect([operation.freshAuthentication, operation.actChain]).toEqual([fresh, act]);
  });

  it.each(ACCOUNT_OPERATIONS.map((operation) => [operation.id] as const))(
    '%s names its audience, fresh authentication and act-chain rule in the document',
    (id) => {
      const operation = publishedNamed(id);
      expect(operation['x-qauth-audience']).toBe(ACCOUNT_API_AUDIENCE);
      expect(FRESH_AUTHENTICATION_RULES).toContain(operation['x-qauth-fresh-authentication']);
      expect(ACT_CHAIN_RULES).toContain(operation['x-qauth-act-chain']);
      expect(operation['x-qauth-fresh-authentication']).toBe(EXPECTED[id]?.[0]);
      expect(operation['x-qauth-act-chain']).toBe(EXPECTED[id]?.[1]);
      expect(operation.description.endsWith(tokenSentence(operationNamed(id)))).toBe(true);
      expect(operation.security).toEqual(ACCOUNT_SECURITY);
    }
  );

  it('refuses an act-chain token wherever fresh authentication is needed', () => {
    for (const operation of ACCOUNT_OPERATIONS) {
      if (operation.freshAuthentication !== 'none') {
        expect(operation.actChain, operation.id).toBe('refused');
      }
    }
  });

  it('asks nothing of a read beyond the token', () => {
    for (const operation of ACCOUNT_OPERATIONS.filter((entry) => entry.method === 'get')) {
      expect(
        [operation.class, operation.freshAuthentication, operation.actChain],
        operation.id
      ).toEqual(['read', 'none', 'accepted']);
    }
  });

  it('answers the fresh-authentication challenge exactly where it is needed, with its header', () => {
    for (const operation of ACCOUNT_OPERATIONS) {
      const codes = operationCodes(operation);
      expect(codes.includes('insufficient_user_authentication'), operation.id).toBe(
        operation.freshAuthentication !== 'none'
      );
      expect(codes.includes('delegated_token_refused'), operation.id).toBe(
        operation.actChain === 'refused'
      );
      // The document offers DPoP-bound tokens, so every operation may refuse a proof.
      expect(codes, operation.id).toContain('invalid_dpop_proof');
      const unauthorized = publishedNamed(operation.id).responses['401'];
      expect(unauthorized?.headers?.['WWW-Authenticate'], operation.id).toEqual({
        $ref: '#/components/headers/Challenge',
      });
    }
    expect(FRESH_AUTHENTICATION_MAX_AGE_SECONDS).toBe(300);
    // RFC 6750 §3: a 401 always carries its challenge.
    const headers = (
      ACCOUNT_OPENAPI as { components: { headers: Record<string, { required?: boolean }> } }
    ).components.headers;
    expect(headers['Challenge']?.required).toBe(true);
  });

  it('pages every list by cursor and conditions every update on If-Match', () => {
    for (const operation of ACCOUNT_OPERATIONS) {
      const names = (publishedNamed(operation.id).parameters ?? []).map(
        (parameter) => `${parameter.in}:${parameter.name}`
      );
      expect(names.includes('query:cursor'), operation.id).toBe(operation.list !== undefined);
      expect(names.includes('header:If-Match'), operation.id).toBe(operation.method === 'patch');
      expect(Boolean(operation.conditional), operation.id).toBe(operation.method === 'patch');
      if (operation.method === 'patch') {
        expect(operation.body?.mediaType, operation.id).toBe('application/merge-patch+json');
      }
    }
  });

  it('keeps the served consent operations where they are', () => {
    expect(paths['/account/v1-rc.0/consents']?.['get']?.operationId).toBe('account.consents.list');
    expect(paths['/account/v1-rc.0/consents/{consentId}']?.['delete']?.operationId).toBe(
      'account.consents.delete'
    );
    expect(operationNamed('account.consents.list').permission).toBe('consents.read');
    expect(operationNamed('account.consents.delete').permission).toBe('consents.write');
  });

  it('gives each write a permission of its own resource, and each read a .read one', () => {
    for (const operation of ACCOUNT_OPERATIONS) {
      if (operation.class === 'read') expect(operation.permission, operation.id).toMatch(/\.read$/);
      else expect(operation.permission, operation.id).not.toMatch(/\.read$/);
    }
  });
});
