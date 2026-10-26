import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { KekWarning } from '@qauth-labs/server-keys/custody';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { afterAll, describe, expect, it } from 'vitest';

import { createSecretFiles } from '../testing/double-provider';
import { readVaultSettings } from './settings';

const files = createSecretFiles();
const dir = mkdtempSync(join(tmpdir(), 'qauth-vault-settings-'));
afterAll(() => {
  files.cleanup();
  rmSync(dir, { recursive: true, force: true });
});

const TOKEN = 'hvs.CAESIExampleTokenValue0123456789';
const tokenFile = files.write(TOKEN);

const BASE = {
  KEK_VAULT_ADDR: 'https://vault.internal:8200',
  KEK_VAULT_TRANSIT_KEY: 'qauth-kek',
  KEK_VAULT_TOKEN_FILE: tokenFile,
};

function read(env: Record<string, string>, warnings: KekWarning[] = []) {
  return readVaultSettings(env, (warning) => warnings.push(warning));
}

function refusal(env: Record<string, string>): InvalidConfigurationError {
  try {
    read(env);
  } catch (error) {
    expect(error).toBeInstanceOf(InvalidConfigurationError);
    return error as InvalidConfigurationError;
  }
  throw new Error('expected the settings to be refused');
}

describe('the Vault settings', () => {
  it('reads the address, the key and a token file, with the default mount and no namespace', () => {
    expect(read(BASE)).toEqual({
      address: 'https://vault.internal:8200',
      transitMount: 'transit',
      keyName: 'qauth-kek',
      namespace: undefined,
      caCertificates: undefined,
      auth: { method: 'token', tokenFile },
    });
  });

  it('reads AppRole with its default mount, and a mount, a namespace and an address without a port', () => {
    const secretIdFile = files.write('9f2c1c7e-secret');
    const settings = read({
      KEK_VAULT_ADDR: 'https://vault.internal/',
      KEK_VAULT_TRANSIT_KEY: 'qauth-kek',
      KEK_VAULT_TRANSIT_MOUNT: '/kek/transit/',
      KEK_VAULT_NAMESPACE: 'org/team-a/',
      KEK_VAULT_ROLE_ID: 'b1a2c3d4-role',
      KEK_VAULT_SECRET_ID_FILE: secretIdFile,
    });

    expect(settings).toMatchObject({
      address: 'https://vault.internal',
      transitMount: 'kek/transit',
      namespace: 'org/team-a',
      auth: { method: 'approle', roleId: 'b1a2c3d4-role', secretIdFile, mount: 'approle' },
    });
    expect(
      read({
        ...BASE,
        KEK_VAULT_TOKEN_FILE: '',
        KEK_VAULT_ROLE_ID: 'role',
        KEK_VAULT_SECRET_ID_FILE: secretIdFile,
        KEK_VAULT_APPROLE_MOUNT: 'machines/approle',
      }).auth
    ).toMatchObject({ method: 'approle', mount: 'machines/approle' });
  });

  it.each([
    [
      'KEK_VAULT_ADDR is missing',
      { KEK_VAULT_ADDR: '' },
      /^KEK_PROVIDER=vault needs KEK_VAULT_ADDR: /,
    ],
    [
      'KEK_VAULT_TRANSIT_KEY is missing',
      { KEK_VAULT_TRANSIT_KEY: ' ' },
      /^KEK_PROVIDER=vault needs KEK_VAULT_TRANSIT_KEY: /,
    ],
    [
      'the address is plain http',
      { KEK_VAULT_ADDR: 'http://vault.internal:8200' },
      /must use https:\/\//,
    ],
    [
      'the address is not a URL',
      { KEK_VAULT_ADDR: 'vault.internal:8200' },
      /must use https:\/\/|must be the https:\/\//,
    ],
    ['the address has a path', { KEK_VAULT_ADDR: 'https://vault.internal:8200/v1' }, /origin only/],
    [
      'the address has a query',
      { KEK_VAULT_ADDR: 'https://vault.internal:8200?x=1' },
      /origin only/,
    ],
    ['the key name has a slash', { KEK_VAULT_TRANSIT_KEY: 'a/b' }, /Transit key name/],
    ['the key name has a #', { KEK_VAULT_TRANSIT_KEY: 'a#v1' }, /Transit key name/],
    [
      'the mount has a dot segment',
      { KEK_VAULT_TRANSIT_MOUNT: 'transit/../sys' },
      /KEK_VAULT_TRANSIT_MOUNT must be/,
    ],
    ['the namespace has a space', { KEK_VAULT_NAMESPACE: 'team a' }, /KEK_VAULT_NAMESPACE must be/],
  ])('stops the boot when %s', (_what, env, message) => {
    expect(refusal({ ...BASE, ...env }).message).toMatch(message);
  });

  it('refuses an address with credentials without echoing them', () => {
    const error = refusal({ ...BASE, KEK_VAULT_ADDR: 'https://user:hunter2@vault.internal:8200' });

    expect(error.message).toMatch(/must not hold a user name or password/);
    expect(JSON.stringify(error) + error.message).not.toContain('hunter2');
  });

  it.each([
    ['KEK_VAULT_TOKEN', 'KEK_VAULT_TOKEN_FILE'],
    ['KEK_VAULT_SECRET_ID', 'KEK_VAULT_SECRET_ID_FILE'],
  ])('refuses a credential in %s, pointing to %s, without its value', (variable, instead) => {
    const error = refusal({ ...BASE, [variable]: 'hvs.secret-value-in-env' });

    expect(error.message).toContain(instead);
    expect(error.message).toMatch(/never reads a Vault credential from a variable/);
    expect(JSON.stringify(error) + error.message).not.toContain('secret-value-in-env');
  });

  it('refuses any other KEK_VAULT_* variable, naming it', () => {
    const error = refusal({ ...BASE, KEK_VAULT_SKIP_VERIFY: 'true', KEK_VAULT_ADDRESS: 'x' });

    expect(error.details).toEqual({ variables: ['KEK_VAULT_ADDRESS', 'KEK_VAULT_SKIP_VERIFY'] });
  });

  it.each([
    ['no way to log in', { KEK_VAULT_TOKEN_FILE: '' }, /needs a way to log in/],
    ['both a token file and AppRole', { KEK_VAULT_ROLE_ID: 'role' }, /logs in one way/],
    [
      'a role ID without a secret ID file',
      { KEK_VAULT_TOKEN_FILE: '', KEK_VAULT_ROLE_ID: 'role' },
      /KEK_VAULT_SECRET_ID_FILE is not set/,
    ],
    [
      'an AppRole mount with a token file',
      { KEK_VAULT_APPROLE_MOUNT: 'approle' },
      /logs in one way/,
    ],
  ])('stops the boot with %s', (_what, env, message) => {
    expect(refusal({ ...BASE, ...env }).message).toMatch(message);
  });

  it('stops the boot when the token file is missing, empty or holds more than one value, without its content', () => {
    expect(refusal({ ...BASE, KEK_VAULT_TOKEN_FILE: join(dir, 'absent') }).message).toBe(
      'The file KEK_VAULT_TOKEN_FILE names does not exist.'
    );
    expect(refusal({ ...BASE, KEK_VAULT_TOKEN_FILE: files.write('   ') }).message).toBe(
      'The file KEK_VAULT_TOKEN_FILE names is empty.'
    );
    const twoLines = refusal({ ...BASE, KEK_VAULT_TOKEN_FILE: files.write('hvs.one\nhvs.two') });
    expect(twoLines.message).toMatch(/must hold one value/);
    expect(JSON.stringify(twoLines)).not.toContain('hvs.one');
    expect(refusal({ ...BASE, KEK_VAULT_TOKEN_FILE: dir }).message).toMatch(/regular file/);
  });

  it('warns when group or others can read the token or secret ID file', () => {
    const warnings: KekWarning[] = [];

    read({ ...BASE, KEK_VAULT_TOKEN_FILE: files.write(TOKEN, 0o644) }, warnings);
    read(
      {
        ...BASE,
        KEK_VAULT_TOKEN_FILE: '',
        KEK_VAULT_ROLE_ID: 'role',
        KEK_VAULT_SECRET_ID_FILE: files.write('secret', 0o640),
      },
      warnings
    );

    expect(warnings.map((warning) => warning.variable)).toEqual([
      'KEK_VAULT_TOKEN_FILE',
      'KEK_VAULT_SECRET_ID_FILE',
    ]);
    expect(warnings[0].message).toMatch(/mode 644/);
    expect(JSON.stringify(warnings)).not.toContain(TOKEN);
  });

  it('warns about each variable of the default provider, which it ignores', () => {
    const warnings: KekWarning[] = [];

    read({ ...BASE, KEK: 'x', KEK_PREVIOUS_PATH: '/k' }, warnings);

    expect(warnings.map((warning) => warning.variable)).toEqual(['KEK', 'KEK_PREVIOUS_PATH']);
  });

  it('reads a CA file of PEM certificates, and refuses one with none or one that does not parse', () => {
    const ca = join(dir, 'ca.pem');
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-keyout',
        join(dir, 'ca.key'),
        '-out',
        ca,
        '-days',
        '1',
        '-subj',
        '/CN=qauth-test-ca',
      ],
      { stdio: 'ignore' }
    );

    expect(read({ ...BASE, KEK_VAULT_CA_CERT_FILE: ca }).caCertificates).toMatch(
      /^-----BEGIN CERTIFICATE-----/
    );
    const empty = join(dir, 'empty.pem');
    writeFileSync(empty, 'not a certificate');
    expect(refusal({ ...BASE, KEK_VAULT_CA_CERT_FILE: empty }).message).toMatch(
      /holds no PEM certificate/
    );
    const broken = join(dir, 'broken.pem');
    writeFileSync(broken, '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n');
    expect(refusal({ ...BASE, KEK_VAULT_CA_CERT_FILE: broken }).message).toMatch(/does not parse/);
    expect(refusal({ ...BASE, KEK_VAULT_CA_CERT_FILE: join(dir, 'absent.pem') }).message).toMatch(
      /could not be read/
    );
  });
});
