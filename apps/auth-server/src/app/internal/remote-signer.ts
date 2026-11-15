import {
  createRemoteSigner,
  DEFAULT_REMOTE_SIGNER_ATTEMPT_TIMEOUT_MS,
  type RemoteSignerEvent,
  type RemoteSignerOptions,
  SIGNER_MAX_ANSWER_BYTES,
  type SignerTransport,
} from '@qauth-labs/fastify-plugin-signer';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

import { createInternalClient } from './client';
import {
  describeCertificate,
  type InternalTlsFiles,
  type InternalTlsMaterial,
  watchInternalTlsFiles,
} from './tls-files';

/**
 * THE REMOTE SIGNER OF A PROCESS WITHOUT THE SIGNER ROLE (ADR-019 Decision 9,
 * issue #497).
 *
 * The signer plugin's remote signer (`createRemoteSigner`) over the internal
 * client (`./client.ts`): every key operation is a call to the signer service
 * at SIGNER_URL, over mutual TLS with this process's certificate, to a server
 * whose certificate holds `serverSan` (SIGNER_SAN, or the URL's host name).
 * The public reads stay local: the realm's verification keys and JWKS come
 * from `realm_public_keys`, so a signer outage stops neither token
 * verification nor the JWKS.
 *
 * The internal TLS files are read again every few seconds, as the internal
 * listener reads them, and a rotated certificate is used for the next calls
 * with no restart. `main.ts` reads the files at boot and the app builds this
 * once its database plugin is registered; it closes with the app.
 */

/** The TLS files of the signer client, as `main.ts` read them at boot. */
export interface RemoteSignerTls {
  readonly files: InternalTlsFiles;
  /** The files' contents, read and checked at boot (`readInternalTlsFiles`). */
  readonly material: InternalTlsMaterial;
  /** How often the files are read again; the default of `tls-files.ts` unless set. */
  readonly reloadIntervalMs?: number;
}

/** Where the signer service is and how this process reaches it. */
export interface RemoteSignerSettings {
  /** SIGNER_URL. */
  readonly url: string;
  /** The SAN the signer's certificate must hold (`signerServerSan`). */
  readonly serverSan: string;
  readonly tls: RemoteSignerTls;
  /**
   * The remote signer's deadline, retry pause and circuit breaker; its
   * defaults unless set, which only a test does, to see the circuit close
   * within the test's time.
   */
  readonly limits?: Pick<
    RemoteSignerOptions,
    'attemptTimeoutMs' | 'retryDelayMs' | 'failureThreshold' | 'openMs'
  >;
}

/** The remote signer and how to stop it. */
export interface AppRemoteSigner {
  readonly signer: FastifyInstance['signer'];
  /** Stop reading the TLS files and close every connection. */
  close(): void;
}

/** What the operator reads in the log about each kind of failed call. */
const FAILURE_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  unreachable: 'A call to the signer service got no answer',
  signer_failed: 'The signer service could not do its work',
  malformed_answer: 'The signer service gave an answer of another shape',
  not_served:
    'The signer service serves no route for this operation: run the same QAuth version on the signer and on the processes that call it',
  peer_refused:
    "The signer service's listener refused this process's certificate: map its SAN to the process's role in the signer's INTERNAL_PEER_ROLES",
  role_refused:
    "The signer service refused the call for the role this process's certificate maps to: either that role may not make it (SIGNER_POLICY), or the certificate maps to another role than the process serves (map its SAN to the process's role in the signer's INTERNAL_PEER_ROLES, and give each role a process and a certificate of its own)",
  rate_limited: 'The signer service refused a call for the rate of this peer',
});

/** Write what the remote signer reports to `log`: never a value of a request. */
export function logRemoteSignerEvent(log: FastifyBaseLogger, event: RemoteSignerEvent): void {
  switch (event.type) {
    case 'circuit_opened':
      log.error(
        { failures: event.failures, openMs: event.openMs },
        'The signer service failed calls in a row: calls to it answer 503 at once until one gets through'
      );
      return;
    case 'circuit_closed':
      log.info('The signer service answers again');
      return;
    case 'call_failed': {
      const fields = {
        operation: event.operation,
        reason: event.reason,
        ...(event.status === undefined ? {} : { status: event.status }),
        ...(event.code === undefined ? {} : { code: event.code }),
      };
      // One line per call while the circuit is open would flood the log.
      if (event.reason === 'circuit_open') {
        log.debug(fields, 'A signer call answered 503 at once: the circuit is open');
        return;
      }
      log.warn(fields, FAILURE_MESSAGES[event.reason] ?? 'A call to the signer service failed');
      return;
    }
  }
}

/**
 * Build the remote signer over `settings`, reading the realms' public keys
 * through `publishedKeys`.
 *
 * @throws TypeError when the settings do not make an internal client (a URL
 *   that is not `https`, a SAN that does not parse, a key that is not the
 *   certificate's own)
 */
export function createAppRemoteSigner(
  settings: RemoteSignerSettings,
  dependencies: {
    readonly publishedKeys: RemoteSignerOptions['publishedKeys'];
    readonly log: FastifyBaseLogger;
  }
): AppRemoteSigner {
  const { log } = dependencies;
  const client = createInternalClient({
    url: settings.url,
    cert: settings.tls.material.cert,
    key: settings.tls.material.key,
    ca: settings.tls.material.ca,
    expectedServerSan: settings.serverSan,
    // The remote signer aborts each attempt at its own deadline; the
    // client's is the same, so neither waits past it.
    timeoutMs: settings.limits?.attemptTimeoutMs ?? DEFAULT_REMOTE_SIGNER_ATTEMPT_TIMEOUT_MS,
    maxResponseBytes: SIGNER_MAX_ANSWER_BYTES,
  });
  const transport: SignerTransport = {
    async send({ path, body, signal }) {
      const response = await client.request({
        method: 'POST',
        path,
        headers: { 'content-type': 'application/json' },
        body,
        signal,
      });
      return { status: response.status, body: response.body };
    },
  };
  const signer = createRemoteSigner({
    ...settings.limits,
    transport,
    publishedKeys: dependencies.publishedKeys,
    onEvent: (event) => logRemoteSignerEvent(log, event),
  });
  const watcher = watchInternalTlsFiles(
    settings.tls.files,
    settings.tls.material,
    (material) => {
      // Throws for a key that is not the certificate's own: the watcher
      // keeps the credentials in use and reports it below.
      client.reloadCredentials(material);
      log.info(
        { certificate: describeCertificate(material.cert) },
        "Reloaded the signer client's internal TLS files"
      );
    },
    {
      ...(settings.tls.reloadIntervalMs === undefined
        ? {}
        : { intervalMs: settings.tls.reloadIntervalMs }),
      onError: (error) => {
        log.warn(
          { err: { message: error.message } },
          'The internal TLS files changed but cannot be used yet; the signer client keeps the files it uses'
        );
      },
      onWarning: (message) => log.warn(message),
    }
  );
  return {
    signer,
    close(): void {
      watcher.stop();
      client.close();
    },
  };
}
