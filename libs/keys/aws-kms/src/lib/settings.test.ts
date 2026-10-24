import type { KekWarning } from '@qauth-labs/server-keys/custody';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { readAwsKmsSettings } from './settings';

const ARN = 'arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';

function read(env: Record<string, string>, warnings: KekWarning[] = []) {
  return readAwsKmsSettings(env, (warning) => warnings.push(warning));
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

describe('readAwsKmsSettings', () => {
  it('reads the key ARN and takes the region from it', () => {
    expect(read({ KEK_AWS_KMS_KEY_ID: ARN })).toEqual({ keyArn: ARN, region: 'eu-central-1' });
    expect(read({ KEK_AWS_KMS_KEY_ID: ` ${ARN} `, KEK_AWS_REGION: 'eu-central-1' })).toEqual({
      keyArn: ARN,
      region: 'eu-central-1',
    });
  });

  it.each([
    [
      'a multi-Region key',
      'arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab',
    ],
    [
      'another partition',
      'arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    ],
  ])('accepts the key ARN of %s', (_what, keyArn) => {
    expect(read({ KEK_AWS_KMS_KEY_ID: keyArn }).keyArn).toBe(keyArn);
  });

  it.each<Record<string, string>>([{}, { KEK_AWS_KMS_KEY_ID: '' }, { KEK_AWS_KMS_KEY_ID: '   ' }])(
    'stops with a message naming KEK_AWS_KMS_KEY_ID when it is missing (%j)',
    (env) => {
      const error = refusal(env);

      expect(error.message).toContain('KEK_PROVIDER=aws-kms needs KEK_AWS_KMS_KEY_ID');
      expect(error.message).toContain('key ARN of the symmetric encryption KMS key');
      expect(error.details).toEqual({ variable: 'KEK_AWS_KMS_KEY_ID' });
    }
  );

  it.each([
    ['an alias name', 'alias/qauth-kek'],
    ['an alias ARN', 'arn:aws:kms:eu-central-1:111122223333:alias/qauth-kek'],
  ])('refuses %s, which can be moved to another key', (_what, value) => {
    const error = refusal({ KEK_AWS_KMS_KEY_ID: value });

    expect(error.message).toContain('names a KMS alias');
    expect(error.details).toEqual({ variable: 'KEK_AWS_KMS_KEY_ID', value });
  });

  it.each([
    ['a bare key ID', '0987dcba-09ba-87dc-65fe-0987654321ba'],
    ['the ARN of another service', 'arn:aws:s3:::bucket'],
    ['a key ARN with a malformed key ID', 'arn:aws:kms:eu-central-1:111122223333:key/not-a-key'],
    [
      'a key ARN with a short account',
      'arn:aws:kms:eu-central-1:1111:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    ],
  ])('refuses %s', (_what, value) => {
    const error = refusal({ KEK_AWS_KMS_KEY_ID: value });

    expect(error.message).toContain('must be the key ARN of a KMS key');
    expect(error.message).not.toContain(value);
  });

  it('refuses a KEK_AWS_REGION that is not the region of the key ARN', () => {
    const error = refusal({ KEK_AWS_KMS_KEY_ID: ARN, KEK_AWS_REGION: 'us-east-1' });

    expect(error.message).toContain('names another region than the key ARN');
    expect(error.details).toEqual({
      variable: 'KEK_AWS_REGION',
      value: 'us-east-1',
      keyArnRegion: 'eu-central-1',
    });
  });

  it('refuses a KEK_AWS_REGION that is not a region code', () => {
    expect(refusal({ KEK_AWS_KMS_KEY_ID: ARN, KEK_AWS_REGION: 'Frankfurt' }).details).toEqual({
      variable: 'KEK_AWS_REGION',
      value: 'Frankfurt',
    });
  });

  it('refuses static credentials in a QAuth setting, naming the variables and never their values', () => {
    const error = refusal({
      KEK_AWS_KMS_KEY_ID: ARN,
      KEK_AWS_ACCESS_KEY_ID: 'AKIAEXAMPLEEXAMPLE00',
      KEK_AWS_SECRET_ACCESS_KEY: 'secret-value-never-in-an-error',
      KEK_AWS_UNUSED: '',
    });

    expect(error.message).toContain('default AWS credential chain');
    expect(error.details).toEqual({
      variables: ['KEK_AWS_ACCESS_KEY_ID', 'KEK_AWS_SECRET_ACCESS_KEY'],
    });
    expect(JSON.stringify(error.details)).not.toContain('secret-value');
    expect(error.message).not.toContain('secret-value');
  });

  it("warns about each of the default provider's variables, which it does not read", () => {
    const warnings: KekWarning[] = [];

    read(
      {
        KEK_AWS_KMS_KEY_ID: ARN,
        KEK: 'a-kek',
        KEK_PREVIOUS_PATH: '/run/secrets/old',
        KEK_PATH: '',
      },
      warnings
    );

    expect(warnings.map((warning) => warning.variable)).toEqual(['KEK', 'KEK_PREVIOUS_PATH']);
    expect(warnings[0].message).toContain('KEK_PROVIDER=aws-kms does not read it');
    expect(warnings.map((warning) => warning.message).join('\n')).not.toContain('a-kek');
  });
});
