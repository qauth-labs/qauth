import { mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { InternalTlsFiles } from '../app/internal/tls-files';
import { createTestCertificate, type TestCertificate, toPkcs8Pem } from './x509-der';

/**
 * TEST SUPPORT — the internal listener's PKI (#496): a CA, and certificates
 * it issues with DNS and URI SANs, written to files as a mesh or a SPIFFE
 * agent would write them. Built on the app's one X.509 encoder
 * (`x509-der.ts`).
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
