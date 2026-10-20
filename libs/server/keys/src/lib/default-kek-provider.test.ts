import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';

import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { afterAll, describe, expect, it } from 'vitest';

import { KEK_A, KEK_B, localProvider, testKek } from '../testing/keks';
import { KEY_AAD_VERSION, type KeyAad } from './aad';
import { createLocalKekProvider, LOCAL_KEK_PROVIDER } from './default-kek-provider';
import { UnknownKekRefError } from './errors';
import type { KekEnv, KekWarning } from './kek-provider';
import { computeKekRef, DEV_KEK_DEFAULT } from './kek-sources';

const AAD: KeyAad = {
  realmId: 'realm-a',
  purpose: 'token_signing',
  scopeId: null,
  kid: 'kid-1',
  algorithm: 'EdDSA',
  version: KEY_AAD_VERSION,
};

const dir = mkdtempSync(join(tmpdir(), 'qauth-kek-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

let files = 0;
/** Write `content` to a fresh file with `mode`, and return its path. */
function kekFile(content: string, mode = 0o600): string {
  const path = join(dir, `kek-${++files}`);
  writeFileSync(path, content);
  chmodSync(path, mode);
  return path;
}

/** The kekRef a provider wraps under, read from its health. */
async function refOf(env: KekEnv, warnings?: KekWarning[]): Promise<string | undefined> {
  return (await localProvider(env, warnings).health()).kekRef;
}

/** What creating a provider over `env` throws. */
function failure(env: KekEnv): InvalidConfigurationError {
  try {
    localProvider(env);
  } catch (error) {
    expect(error).toBeInstanceOf(InvalidConfigurationError);
    return error as InvalidConfigurationError;
  }
  throw new Error('expected the provider to be refused');
}

describe('computeKekRef', () => {
  it('is the first 8 bytes of the SHA-256 of the KEK, in hex', () => {
    const kek = Buffer.from(KEK_A, 'base64');
    const expected = createHash('sha256').update(kek).digest('hex').slice(0, 16);

    expect(computeKekRef(kek)).toBe(expected);
    expect(computeKekRef(kek)).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('the default KEK provider reads its KEK', () => {
  it('from KEK, as base64 of 32 bytes, and names it by its fingerprint', async () => {
    expect(await refOf({ KEK: KEK_A })).toBe(computeKekRef(Buffer.from(KEK_A, 'base64')));
  });

  it('from the file KEK_PATH names, trimmed', async () => {
    expect(await refOf({ KEK_PATH: kekFile(`${KEK_A}\n`) })).toBe(
      computeKekRef(Buffer.from(KEK_A, 'base64'))
    );
  });

  it('from the file when both KEK_PATH and KEK are set', async () => {
    expect(await refOf({ KEK: KEK_B, KEK_PATH: kekFile(KEK_A) })).toBe(await refOf({ KEK: KEK_A }));
  });

  it('from KEK when KEK_PATH is blank, as Docker Compose passes an unset variable', async () => {
    expect(await refOf({ KEK: KEK_A, KEK_PATH: '' })).toBe(await refOf({ KEK: KEK_A }));
  });

  it('without padding as well as with it', async () => {
    expect(await refOf({ KEK: KEK_A.replace(/=+$/, '') })).toBe(await refOf({ KEK: KEK_A }));
  });
});

describe('the default KEK provider refuses', () => {
  it.each([
    ['31 bytes', Buffer.alloc(31, 1).toString('base64')],
    ['33 bytes', Buffer.alloc(33, 1).toString('base64')],
    ['16 bytes', Buffer.alloc(16, 1).toString('base64')],
  ])('a KEK of %s, naming the variable and the length', (_what, kek) => {
    const error = failure({ KEK: kek });

    expect(error.message).toContain('KEK must decode to exactly 32 bytes');
    expect(error.details).toEqual({ variable: 'KEK', bytes: Buffer.from(kek, 'base64').length });
  });

  it('a 31-byte KEK in a file', () => {
    const error = failure({ KEK_PATH: kekFile(Buffer.alloc(31, 1).toString('base64')) });

    expect(error.message).toContain('KEK_PATH must decode to exactly 32 bytes');
  });

  it.each([
    ['base64url characters', testKek(0xfb).replace(/\+/g, '-').replace(/\//g, '_')],
    ['a character outside base64', `${KEK_A.slice(0, 10)}!${KEK_A.slice(11)}`],
    ['32 raw characters', 'qauth-dev-kek-never-in-prod-0001'],
    ['a stray character Node would skip', `${KEK_A.slice(0, 8)}=${KEK_A.slice(8)}`],
  ])('a KEK that is not base64: %s', (_what, kek) => {
    expect(failure({ KEK: kek }).message).toContain('KEK must be the base64 encoding of 32');
  });

  it('a hex KEK, whose 64 characters decode as base64 to 48 bytes', () => {
    expect(failure({ KEK: Buffer.alloc(32, 0xa1).toString('hex') }).details).toEqual({
      variable: 'KEK',
      bytes: 48,
    });
  });

  it('a KEK_PATH that does not exist', () => {
    const error = failure({ KEK_PATH: join(dir, 'missing') });

    expect(error.message).toBe('The file KEK_PATH names does not exist.');
    expect(error.details).toMatchObject({ variable: 'KEK_PATH', code: 'ENOENT' });
  });

  it('a KEK_PATH it cannot read, without falling back to KEK', () => {
    const error = failure({ KEK: KEK_A, KEK_PATH: join(dir, 'missing') });

    expect(error.details).toMatchObject({ variable: 'KEK_PATH', code: 'ENOENT' });
  });

  it('a KEK_PREVIOUS_PATH it cannot read, without falling back to KEK_PREVIOUS', () => {
    const error = failure({
      KEK: KEK_A,
      KEK_PREVIOUS: KEK_B,
      KEK_PREVIOUS_PATH: join(dir, 'missing'),
    });

    expect(error.details).toMatchObject({ variable: 'KEK_PREVIOUS_PATH', code: 'ENOENT' });
  });

  it('a KEK_PATH that names a malformed KEK, without falling back to KEK', () => {
    const error = failure({ KEK: KEK_A, KEK_PATH: kekFile('not a key') });

    expect(error.message).toContain('KEK_PATH must be the base64 encoding of 32');
  });

  it('a KEK_PATH that names an empty file', () => {
    expect(failure({ KEK_PATH: kekFile('\n') }).message).toBe('The file KEK_PATH names is empty.');
  });

  it('a KEK_PATH that names a directory', () => {
    const path = join(dir, 'a-directory');
    mkdirSync(path);

    expect(failure({ KEK_PATH: path }).message).toBe('KEK_PATH must name a regular file.');
  });

  it('a malformed KEK_PREVIOUS', () => {
    expect(failure({ KEK: KEK_A, KEK_PREVIOUS: 'short' }).message).toContain('KEK_PREVIOUS');
  });
});

describe('the KEK file permissions', () => {
  it.skipIf(process.platform === 'win32').each([0o644, 0o640, 0o604, 0o620, 0o602])(
    'give a warning when group or others can read or write the file (mode %o)',
    async (mode) => {
      const warnings: KekWarning[] = [];

      await refOf({ KEK_PATH: kekFile(KEK_A, mode) }, warnings);

      expect(warnings).toEqual([
        {
          variable: 'KEK_PATH',
          message: expect.stringContaining(
            `group or others can read or write (mode ${mode.toString(8)})`
          ),
        },
      ]);
    }
  );

  it.skipIf(process.platform === 'win32')('warn about KEK_PREVIOUS_PATH the same way', async () => {
    const warnings: KekWarning[] = [];

    await refOf({ KEK: KEK_A, KEK_PREVIOUS_PATH: kekFile(KEK_B, 0o644) }, warnings);

    expect(warnings.map((warning) => warning.variable)).toEqual(['KEK_PREVIOUS_PATH']);
  });

  it.each([0o600, 0o400])(
    'give no warning for a file only its owner can read (mode %o)',
    async (mode) => {
      const warnings: KekWarning[] = [];

      await refOf({ KEK_PATH: kekFile(KEK_A, mode) }, warnings);

      expect(warnings).toEqual([]);
    }
  );
});

describe('the development KEK', () => {
  it('is used, with a warning, when KEK and KEK_PATH are unset outside production', async () => {
    const warnings: KekWarning[] = [];

    expect(await refOf({ NODE_ENV: 'development' }, warnings)).toBe(
      computeKekRef(Buffer.from(DEV_KEK_DEFAULT, 'base64'))
    );
    expect(warnings).toEqual([
      { variable: 'KEK', message: expect.stringContaining('published development KEK') },
    ]);
  });

  it('is 32 bytes of base64', () => {
    expect(Buffer.from(DEV_KEK_DEFAULT, 'base64')).toHaveLength(32);
  });

  it('is refused in production when no KEK is set', () => {
    const error = failure({ NODE_ENV: 'production' });

    expect(error.message).toContain('KEK or KEK_PATH must be set when NODE_ENV=production');
  });

  it('is refused when NODE_ENV is production with stray whitespace', () => {
    expect(failure({ NODE_ENV: ' production ' }).message).toContain(
      'KEK or KEK_PATH must be set when NODE_ENV=production'
    );
  });

  it.each([
    ['KEK', { KEK: DEV_KEK_DEFAULT }],
    ['KEK_PATH', { KEK_PATH: kekFile(DEV_KEK_DEFAULT) }],
    ['KEK_PREVIOUS', { KEK: KEK_A, KEK_PREVIOUS: DEV_KEK_DEFAULT }],
    ['KEK_PREVIOUS_PATH', { KEK: KEK_A, KEK_PREVIOUS_PATH: kekFile(DEV_KEK_DEFAULT) }],
  ])('is refused in production as %s', (variable, env) => {
    const error = failure({ NODE_ENV: 'production', ...env });

    expect(error.message).toBe(
      `${variable} holds the published development KEK, which NODE_ENV=production does not allow. Generate a KEK with \`openssl rand -base64 32\`.`
    );
    expect(error.details).toEqual({ variable });
  });

  it('is accepted outside production when set explicitly, without a warning', async () => {
    const warnings: KekWarning[] = [];

    await refOf({ NODE_ENV: 'development', KEK: DEV_KEK_DEFAULT }, warnings);

    expect(warnings).toEqual([]);
  });

  it('does not stop production from using a real KEK', async () => {
    const warnings: KekWarning[] = [];

    expect(await refOf({ NODE_ENV: 'production', KEK: KEK_A }, warnings)).toBe(
      await refOf({ KEK: KEK_A })
    );
    expect(warnings).toEqual([]);
  });
});

describe('a KEK rotation with KEK_PREVIOUS', () => {
  async function wrapUnder(kek: string) {
    const dek = randomBytes(32);
    const { wrapped, kekRef } = await localProvider({ KEK: kek }).wrap(Buffer.from(dek), AAD);
    return { dek, wrapped, kekRef };
  }

  it('unwraps data wrapped under the previous kekRef', async () => {
    const old = await wrapUnder(KEK_A);
    const rotated = localProvider({ KEK: KEK_B, KEK_PREVIOUS: KEK_A });

    expect(Buffer.from(await rotated.unwrap(old.wrapped, AAD, old.kekRef))).toEqual(old.dek);
  });

  it('reads the previous KEK from KEK_PREVIOUS_PATH, which wins over KEK_PREVIOUS', async () => {
    const old = await wrapUnder(KEK_A);
    const rotated = localProvider({
      KEK: KEK_B,
      KEK_PREVIOUS: testKek(0xc3),
      KEK_PREVIOUS_PATH: kekFile(KEK_A),
    });

    expect(Buffer.from(await rotated.unwrap(old.wrapped, AAD, old.kekRef))).toEqual(old.dek);
  });

  it('wraps every new data key under the current KEK', async () => {
    const rotated = localProvider({ KEK: KEK_B, KEK_PREVIOUS: KEK_A });
    const { kekRef } = await rotated.wrap(randomBytes(32), AAD);

    expect(kekRef).toBe(await refOf({ KEK: KEK_B }));
    expect((await rotated.health()).kekRef).toBe(kekRef);
  });

  it('refuses the old kekRef once KEK_PREVIOUS is removed', async () => {
    const old = await wrapUnder(KEK_A);

    await expect(
      localProvider({ KEK: KEK_B }).unwrap(old.wrapped, AAD, old.kekRef)
    ).rejects.toThrow(UnknownKekRefError);
  });

  it('warns when KEK_PREVIOUS is the KEK already in use', async () => {
    const warnings: KekWarning[] = [];

    await refOf({ KEK: KEK_A, KEK_PREVIOUS: KEK_A }, warnings);

    expect(warnings).toEqual([
      { variable: 'KEK_PREVIOUS', message: expect.stringContaining('same KEK as the current one') },
    ]);
  });
});

describe('the default KEK provider never shows a KEK', () => {
  const kekBytes = Buffer.from(KEK_A, 'base64');
  const forms = [KEK_A, KEK_A.replace(/=+$/, ''), kekBytes.toString('hex')];

  function expectNoKek(text: string): void {
    for (const form of forms) expect(text).not.toContain(form);
  }

  it('in its properties, its JSON or its inspected form', async () => {
    const provider = localProvider({ KEK: KEK_A, KEK_PREVIOUS: KEK_B });

    expect(provider.name).toBe(LOCAL_KEK_PROVIDER);
    expect(Object.keys(provider).sort()).toEqual(['health', 'name', 'unwrap', 'wrap']);
    expectNoKek(JSON.stringify(provider));
    expectNoKek(inspect(provider, { depth: Infinity, showHidden: true }));
    expectNoKek(JSON.stringify(await provider.health()));
  });

  it('in an error about the KEK or a warning about its file', () => {
    const warnings: KekWarning[] = [];
    const tooLong = Buffer.concat([kekBytes, Buffer.from([1])]).toString('base64');
    let message = '';
    try {
      createLocalKekProvider({ env: { KEK: tooLong }, warn: (w) => warnings.push(w) });
    } catch (error) {
      message = `${String(error)} ${JSON.stringify((error as InvalidConfigurationError).details)}`;
    }
    localProvider({ KEK_PATH: kekFile(KEK_A, 0o644) }, warnings);

    expect(message).toContain('KEK must decode to exactly 32 bytes');
    expect(message).not.toContain(tooLong);
    expectNoKek(message);
    expectNoKek(JSON.stringify(warnings));
  });
});
