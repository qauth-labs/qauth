import {
  DecryptCommand,
  type DecryptCommandInput,
  type DecryptCommandOutput,
  EncryptCommand,
  type EncryptCommandInput,
  type EncryptCommandOutput,
  KMSClient,
  type KMSClientConfig,
} from '@aws-sdk/client-kms';

/**
 * The two KMS operations the provider calls (ADR-019 Decision 9, #577).
 *
 * A port rather than the SDK client itself, so the tests run the provider
 * against a KMS test double and only `kms-client.test.ts` needs a KMS
 * endpoint.
 */
export interface KmsOperations {
  encrypt(input: EncryptCommandInput): Promise<EncryptCommandOutput>;
  decrypt(input: DecryptCommandInput): Promise<DecryptCommandOutput>;
}

/** Every KMS call is tried at most this many times, the first attempt included. */
export const KMS_MAX_ATTEMPTS = 3;

/** The longest a connection to KMS may take to open, in ms. */
export const KMS_CONNECTION_TIMEOUT_MS = 2_000;

/** The longest one KMS request may take once connected, in ms. */
export const KMS_REQUEST_TIMEOUT_MS = 3_000;

/**
 * The KMS client's configuration for a key in `region`.
 *
 * - No `credentials`: the SDK's default credential chain supplies them, and
 *   QAuth settings hold none.
 * - The SDK's standard retry mode, with an explicit attempt limit that
 *   `AWS_MAX_ATTEMPTS` cannot raise. It retries throttling, timeouts and
 *   server faults with exponential backoff and jitter, never a refusal.
 * - Connection and request timeouts, so a KMS endpoint that stops answering
 *   fails the call instead of holding the signer. The SDK sets neither by
 *   default, and a request timeout only throws with `throwOnRequestTimeout`.
 *   The worst case for one call is about `KMS_MAX_ATTEMPTS` times the two
 *   timeouts, plus the backoff.
 */
export function kmsClientConfig(region: string): KMSClientConfig {
  return {
    region,
    maxAttempts: KMS_MAX_ATTEMPTS,
    retryMode: 'standard',
    requestHandler: {
      connectionTimeout: KMS_CONNECTION_TIMEOUT_MS,
      requestTimeout: KMS_REQUEST_TIMEOUT_MS,
      throwOnRequestTimeout: true,
    },
  };
}

/** The {@link KmsOperations} of an SDK client. */
export function kmsOperationsOf(client: KMSClient): KmsOperations {
  return {
    encrypt: (input) => client.send(new EncryptCommand(input)),
    decrypt: (input) => client.send(new DecryptCommand(input)),
  };
}

/** A KMS client for a key in `region`, configured by {@link kmsClientConfig}. */
export function createKmsClient(region: string): KMSClient {
  return new KMSClient(kmsClientConfig(region));
}
