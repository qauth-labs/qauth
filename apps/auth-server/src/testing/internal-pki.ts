import { X509Certificate } from 'node:crypto';
import { mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect, type ConnectionOptions } from 'node:tls';

import type { InternalTlsFiles } from '../app/internal/tls-files';
import { createTestCertificate, type TestCertificate, toPkcs8Pem } from './x509-der';

/**
 * TEST SUPPORT — the internal listener's PKI (#496): a CA, and certificates
 * it issues with DNS and URI SANs, written to files as a mesh or a SPIFFE
 * agent would write them, and the probes that open TLS connections to an
 * internal listener. Built on the app's one X.509 encoder (`x509-der.ts`).
 */

/** A certificate and its key, as the PEM text of INTERNAL_TLS_CERT_PATH and INTERNAL_TLS_KEY_PATH. */
export interface IssuedCredentials {
  readonly cert: string;
  readonly key: string;
  readonly certificate: TestCertificate;
}

/** A test CA. */
export interface InternalPki {
  readonly ca: TestCertificate;
  /** INTERNAL_TLS_CA_PATH's text. */
  readonly caPem: string;
  /** A certificate this CA issues, with these SANs. */
  issue(options: {
    readonly subject?: string;
    readonly dnsNames?: readonly string[];
    readonly uris?: readonly string[];
    readonly notBefore?: Date;
    readonly notAfter?: Date;
  }): IssuedCredentials;
}

/** A fresh CA named `name`. */
export function createInternalPki(name = 'QAuth internal test CA'): InternalPki {
  const ca = createTestCertificate({
    subject: name,
    ca: true,
    keyUsage: ['keyCertSign', 'cRLSign'],
  });
  return {
    ca,
    caPem: ca.pem,
    issue(options) {
      const certificate = createTestCertificate({
        subject: options.subject ?? options.dnsNames?.[0] ?? options.uris?.[0] ?? 'peer',
        issuer: ca,
        ...(options.dnsNames === undefined ? {} : { dnsNames: options.dnsNames }),
        ...(options.uris === undefined ? {} : { uris: options.uris }),
        ...(options.notBefore === undefined ? {} : { notBefore: options.notBefore }),
        ...(options.notAfter === undefined ? {} : { notAfter: options.notAfter }),
      });
      return { cert: certificate.pem, key: toPkcs8Pem(certificate.privateKey), certificate };
    },
  };
}

/** A directory holding one process's internal TLS files. */
export interface TlsFileDirectory {
  readonly files: InternalTlsFiles;
  /**
   * Replace the files' contents as a rotation does: each written to a new
   * file, then renamed over the old one.
   */
  replace(credentials: IssuedCredentials, caPem: string): void;
  /** Write one file only, as a rotation half-way through. */
  writeOne(which: keyof InternalTlsFiles, text: string): void;
  remove(): void;
}

/** Write `credentials` and `caPem` to a new temporary directory. */
export function writeTlsFiles(credentials: IssuedCredentials, caPem: string): TlsFileDirectory {
  const directory = mkdtempSync(join(tmpdir(), 'qauth-internal-tls-'));
  const files: InternalTlsFiles = {
    certPath: join(directory, 'internal.crt'),
    keyPath: join(directory, 'internal.key'),
    caPath: join(directory, 'internal-ca.crt'),
  };
  const writeOne = (which: keyof InternalTlsFiles, text: string): void => {
    const staged = `${files[which]}.next`;
    writeFileSync(staged, text);
    renameSync(staged, files[which]);
  };
  const replace = (next: IssuedCredentials, ca: string): void => {
    writeOne('keyPath', next.key);
    writeOne('certPath', next.cert);
    writeOne('caPath', ca);
  };
  replace(credentials, caPem);
  return {
    files,
    replace,
    writeOne,
    remove: () => rmSync(directory, { recursive: true, force: true }),
  };
}

/** Where a test reaches an internal listener. */
export interface ListenerAddress {
  readonly host: string;
  readonly port: number;
}

/**
 * Open a TLS connection with `options` and send one HTTP request on it
 * (`GET path`): what came back, if anything, and the error that ended it.
 * The server's identity is not checked: these probes test the listener's side.
 */
export function tlsExchange(
  target: ListenerAddress,
  options: ConnectionOptions,
  path = '/internal/probe'
): Promise<{ readonly error?: NodeJS.ErrnoException; readonly received: string }> {
  return new Promise((resolve) => {
    let received = '';
    let error: NodeJS.ErrnoException | undefined;
    const socket = connect({
      host: target.host,
      port: target.port,
      checkServerIdentity: () => undefined,
      ...options,
    });
    socket.on('secureConnect', () => {
      socket.write(`GET ${path} HTTP/1.1\r\nHost: internal\r\nConnection: close\r\n\r\n`);
    });
    socket.on('data', (chunk: Buffer) => {
      received += chunk.toString('latin1');
    });
    socket.on('error', (cause: NodeJS.ErrnoException) => {
      error = cause;
    });
    socket.on('close', () => resolve({ ...(error === undefined ? {} : { error }), received }));
  });
}

/** The fingerprint of the certificate the listener serves to a new connection. */
export function servedFingerprint(
  target: ListenerAddress,
  credentials: Pick<IssuedCredentials, 'cert' | 'key'>,
  ca: readonly string[]
): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect({
      host: target.host,
      port: target.port,
      cert: credentials.cert,
      key: credentials.key,
      ca: [...ca],
      checkServerIdentity: () => undefined,
    });
    socket.on('secureConnect', () => {
      const fingerprint = socket.getPeerCertificate().fingerprint256;
      socket.end();
      resolve(fingerprint);
    });
    socket.on('error', reject);
  });
}

/** The SHA-256 fingerprint of a PEM certificate, as `servedFingerprint` gives it. */
export function fingerprintOf(cert: string): string {
  return new X509Certificate(cert).fingerprint256;
}

/** Wait until `check` holds, reading again every `intervalMs`, for `timeoutMs` at most. */
export async function eventually(
  check: () => boolean | Promise<boolean>,
  timeoutMs = 5_000,
  intervalMs = 25
): Promise<void> {
  const started = Date.now();
  while (!(await check())) {
    if (Date.now() - started > timeoutMs) throw new Error('eventually: timed out');
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}
