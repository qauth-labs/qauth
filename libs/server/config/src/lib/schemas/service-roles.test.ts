import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { jwtEnvSchema } from './jwt';
import { parseServiceRoles, SERVICE_ROLE_NAMES, serviceRolesEnvSchema } from './service-roles';

/** The role switch (issue #495). */

describe('parseServiceRoles', () => {
  it('holds every role when unset, blank or all', () => {
    for (const value of [undefined, '', '  ', 'all', ' all ']) {
      expect(parseServiceRoles(value)).toEqual({ roles: SERVICE_ROLE_NAMES });
    }
  });

  it('reads a list in the canonical order, ignoring spaces and repeats', () => {
    expect(parseServiceRoles('delivery, api,web,api')).toEqual({
      roles: ['web', 'api', 'delivery'],
    });
    expect(parseServiceRoles('signer')).toEqual({ roles: ['signer'] });
  });

  it('refuses an unknown role and names it', () => {
    const parsed = parseServiceRoles('api,browser');
    expect(parsed).toEqual({ problem: expect.stringContaining('"browser"') });
  });

  it('refuses all beside other roles', () => {
    expect(parseServiceRoles('all,api')).toEqual({
      problem: expect.stringContaining('"all" already holds every role'),
    });
  });

  it('refuses an empty entry', () => {
    for (const value of ['api,', ',api', 'api,,web']) {
      expect(parseServiceRoles(value)).toEqual({
        problem: expect.stringContaining('empty entry'),
      });
    }
  });

  it('is case-sensitive, as every other enumerated key', () => {
    expect('problem' in parseServiceRoles('API')).toBe(true);
  });
});

describe('serviceRolesEnvSchema', () => {
  it('defaults to every role and no signer settings', () => {
    expect(serviceRolesEnvSchema.parse({})).toEqual({
      SERVICE_ROLES: SERVICE_ROLE_NAMES,
    });
  });

  it('reports a bad SERVICE_ROLES under its own name', () => {
    const result = serviceRolesEnvSchema.safeParse({ SERVICE_ROLES: 'api,frontend' });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.path).toEqual(['SERVICE_ROLES']);
  });

  it('takes an https SIGNER_URL and refuses any other', () => {
    expect(
      serviceRolesEnvSchema.parse({ SIGNER_URL: 'https://signer.internal:3443' }).SIGNER_URL
    ).toBe('https://signer.internal:3443');
    for (const value of ['http://signer.internal', 'signer.internal']) {
      const result = serviceRolesEnvSchema.safeParse({ SIGNER_URL: value });
      expect(result.success, value).toBe(false);
      expect(result.error?.issues[0]?.path).toEqual(['SIGNER_URL']);
    }
  });

  it('reads a blank signer setting as unset', () => {
    expect(
      serviceRolesEnvSchema.parse({
        SIGNER_URL: ' ',
        INTERNAL_TLS_CERT_PATH: '',
        INTERNAL_TLS_KEY_PATH: '',
        INTERNAL_TLS_CA_PATH: '',
      })
    ).toEqual({ SERVICE_ROLES: SERVICE_ROLE_NAMES });
  });
});

describe('jwtEnvSchema under the role switch', () => {
  const issuer = { JWT_ISSUER: 'https://auth.example.com' };
  const privateKey = generateKeyPairSync('ed25519')
    .privateKey.export({ type: 'pkcs8', format: 'pem' })
    .toString();

  it('requires the private key where the signer runs, by default too', () => {
    for (const roles of [undefined, 'all', 'api,signer']) {
      const result = jwtEnvSchema.safeParse({ ...issuer, SERVICE_ROLES: roles });
      expect(result.success, roles).toBe(false);
      expect(result.error?.issues[0]?.path).toEqual(['JWT_PRIVATE_KEY']);
    }
  });

  it('does not require it on a process without the signer', () => {
    const parsed = jwtEnvSchema.parse({ ...issuer, SERVICE_ROLES: 'api,web' });
    expect(parsed.JWT_PRIVATE_KEY).toBeUndefined();
  });

  it('still reads a private key it is given, for the boot to refuse by name', () => {
    const parsed = jwtEnvSchema.parse({
      ...issuer,
      SERVICE_ROLES: 'api',
      JWT_PRIVATE_KEY: privateKey,
    });
    expect(parsed.JWT_PRIVATE_KEY).toBe(privateKey.trim());
  });
});
