import type { KekEnv, KekWarning } from '@qauth-labs/server-keys/custody';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

/**
 * The settings of the AWS KMS KEK provider (ADR-019 Decision 9, #577).
 *
 * Two variables, read from the provider context's environment:
 *
 * - `KEK_AWS_KMS_KEY_ID`, required: the key ARN of a symmetric encryption KMS
 *   key. A key ID, an alias name or an alias ARN is refused: an alias can be
 *   moved to another key, which would change the KEK without a change here,
 *   and only the ARN tells the provider, without a call to KMS, which key a
 *   stored `kekRef` names.
 * - `KEK_AWS_REGION`, optional: the region of that key. The ARN names it, so
 *   when set it must agree.
 *
 * Credentials never come from a QAuth setting. The KMS client uses the default
 * AWS credential chain (environment, shared files, web identity, the container
 * or instance role), so any other `KEK_AWS_*` variable, such as an attempt at
 * `KEK_AWS_SECRET_ACCESS_KEY`, is refused, without its value in the error.
 */

/** The `KEK_PROVIDER` value that selects this provider. */
export const AWS_KMS_KEK_PROVIDER = 'aws-kms';

/** The variables this provider reads. */
export const KEY_ID_VARIABLE = 'KEK_AWS_KMS_KEY_ID';
export const REGION_VARIABLE = 'KEK_AWS_REGION';
const SETTINGS: readonly string[] = [KEY_ID_VARIABLE, REGION_VARIABLE];
const PREFIX = 'KEK_AWS_';

/** The variables of the default provider, which this one does not read. */
const LOCAL_KEK_VARIABLES = ['KEK', 'KEK_PATH', 'KEK_PREVIOUS', 'KEK_PREVIOUS_PATH'];

/** What {@link readAwsKmsSettings} returns. */
export interface AwsKmsSettings {
  /** The key ARN from `KEK_AWS_KMS_KEY_ID`. */
  readonly keyArn: string;
  /** The key's region: `KEK_AWS_REGION`, or the region the ARN names. */
  readonly region: string;
}

/** A region code, such as `eu-central-1`. */
const REGION = /^[a-z]{2,}(-[a-z]+)+-\d+$/;

/**
 * A KMS key ARN: a partition, a region, a 12-digit account and the key ID, a
 * UUID or, for a multi-Region key, `mrk-` and 32 hex digits.
 */
const KEY_ARN =
  /^arn:aws[a-z-]*:kms:([a-z0-9-]+):\d{12}:key\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$/;

const ALIAS = /^(alias\/|arn:aws[a-z-]*:kms:[^:]*:[^:]*:alias\/)/;

const EXAMPLE_ARN =
  'arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';

/** A blank value counts as unset, since Docker Compose passes an absent variable as `''`. */
function setting(env: KekEnv, variable: string): string | undefined {
  const value = env[variable]?.trim();
  return value ? value : undefined;
}

/**
 * Read and check the provider's settings.
 *
 * @param warn - receives a warning for each variable of the default provider
 *   that is set, since this provider ignores it
 * @throws InvalidConfigurationError naming the variable at fault
 */
export function readAwsKmsSettings(
  env: KekEnv,
  warn: (warning: KekWarning) => void
): AwsKmsSettings {
  const unknown = Object.keys(env)
    .filter(
      (name) =>
        name.startsWith(PREFIX) && !SETTINGS.includes(name) && setting(env, name) !== undefined
    )
    .sort();
  if (unknown.length > 0) {
    throw new InvalidConfigurationError(
      `KEK_PROVIDER=${AWS_KMS_KEK_PROVIDER} reads only ${KEY_ID_VARIABLE} and ${REGION_VARIABLE}. It takes credentials from the default AWS credential chain (an instance or container role, web identity, AWS_PROFILE or the AWS_* variables), never from a QAuth setting. Remove the variables this error's "details" names.`,
      { variables: unknown }
    );
  }

  const keyArn = setting(env, KEY_ID_VARIABLE);
  if (keyArn === undefined) {
    throw new InvalidConfigurationError(
      `KEK_PROVIDER=${AWS_KMS_KEK_PROVIDER} needs ${KEY_ID_VARIABLE}: the key ARN of the symmetric encryption KMS key that wraps every stored key, for example ${EXAMPLE_ARN}.`,
      { variable: KEY_ID_VARIABLE }
    );
  }
  const match = KEY_ARN.exec(keyArn);
  if (match === null) {
    throw new InvalidConfigurationError(
      ALIAS.test(keyArn)
        ? `${KEY_ID_VARIABLE} names a KMS alias. Give the key ARN instead: an alias can be moved to another key, which would change the KEK without a configuration change. See this error's "details" for the value.`
        : `${KEY_ID_VARIABLE} must be the key ARN of a KMS key, for example ${EXAMPLE_ARN}; a key ID or alias is not enough. See this error's "details" for the value.`,
      { variable: KEY_ID_VARIABLE, value: keyArn }
    );
  }
  const arnRegion = match[1];

  const region = setting(env, REGION_VARIABLE);
  if (region !== undefined && !REGION.test(region)) {
    throw new InvalidConfigurationError(
      `${REGION_VARIABLE} must be a region code, such as eu-central-1. See this error's "details" for the value.`,
      { variable: REGION_VARIABLE, value: region }
    );
  }
  if (region !== undefined && region !== arnRegion) {
    throw new InvalidConfigurationError(
      `${REGION_VARIABLE} names another region than the key ARN in ${KEY_ID_VARIABLE}. A KMS key lives in one region: unset ${REGION_VARIABLE}, or set it to the region of the ARN. See this error's "details" for both.`,
      { variable: REGION_VARIABLE, value: region, keyArnRegion: arnRegion }
    );
  }

  for (const variable of LOCAL_KEK_VARIABLES) {
    if (setting(env, variable) !== undefined) {
      warn({
        variable,
        message: `${variable} is set, but KEK_PROVIDER=${AWS_KMS_KEK_PROVIDER} does not read it: keys are wrapped and unwrapped by the KMS key in ${KEY_ID_VARIABLE}. Keys wrapped under the local KEK do not open with this provider. Remove ${variable}.`,
      });
    }
  }

  return Object.freeze({ keyArn, region: region ?? arnRegion });
}
