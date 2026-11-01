import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createSecureContext, type SecureContextOptions } from 'node:tls';

/**
 * THE INTERNAL TLS FILES (ADR-019 Decision 8, issue #496).
 *
 * `INTERNAL_TLS_CERT_PATH`, `INTERNAL_TLS_KEY_PATH` and `INTERNAL_TLS_CA_PATH`
 * name PEM files: this process's certificate (with any intermediates after
 * it), its private key, and the CA certificates that issue every internal
 * peer's certificate. A mesh or a SPIFFE agent writes such files and rotates
 * them in place, so the internal listener reads them again when they change,
 * with no restart ({@link watchInternalTlsFiles}).
 *
 * Internal traffic is TLS 1.3 only (RFC 8446): both ends are QAuth's own, so
 * no older peer needs a fallback.
 */

/** The three files, by path. */
export interface InternalTlsFiles {
  /** INTERNAL_TLS_CERT_PATH. */
  readonly certPath: string;
  /** INTERNAL_TLS_KEY_PATH. */
  readonly keyPath: string;
  /** INTERNAL_TLS_CA_PATH. */
  readonly caPath: string;
}

/** The three files' contents. */
export interface InternalTlsMaterial {
  readonly cert: Buffer;
  readonly key: Buffer;
  readonly ca: Buffer;
}

/** The variable that names each file, for the messages. */
const VARIABLES = {
  certPath: 'INTERNAL_TLS_CERT_PATH',
  keyPath: 'INTERNAL_TLS_KEY_PATH',
  caPath: 'INTERNAL_TLS_CA_PATH',
} as const satisfies Record<keyof InternalTlsFiles, string>;

/** The only TLS version of internal traffic. */
export const INTERNAL_TLS_VERSION = 'TLSv1.3';

/** How often the listener reads the files again, when nothing else is asked. */
export const DEFAULT_TLS_RELOAD_INTERVAL_MS = 5_000;

/** A TLS file that cannot be read, or files that do not make a usable identity. */
export class InternalTlsFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InternalTlsFileError';
  }
}

/** The secure context options of internal traffic: the material, TLS 1.3 only. */
export function internalSecureContextOptions(material: InternalTlsMaterial): SecureContextOptions {
  return {
    cert: material.cert,
    key: material.key,
    ca: material.ca,
    minVersion: INTERNAL_TLS_VERSION,
    maxVersion: INTERNAL_TLS_VERSION,
  };
}

/**
 * Check that `material` makes a usable identity: the certificate and the CA
 * file parse, and the private key belongs to the certificate. The message
 * names the files, never their contents.
 *
 * @throws InternalTlsFileError
 */
export function checkInternalTlsMaterial(material: InternalTlsMaterial): void {
  try {
    new X509Certificate(material.cert);
  } catch {
    throw new InternalTlsFileError(
      `${VARIABLES.certPath} does not hold a PEM certificate: the internal listener and the internal client present it`
    );
  }
  try {
    new X509Certificate(material.ca);
  } catch {
    throw new InternalTlsFileError(
      `${VARIABLES.caPath} does not hold a PEM CA certificate: it issues every internal peer's certificate`
    );
  }
  try {
    createSecureContext(internalSecureContextOptions(material));
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new InternalTlsFileError(
      `${VARIABLES.keyPath} and ${VARIABLES.certPath} do not make a TLS identity (${reason}): the key must be the certificate's own`
    );
  }
}

/**
 * Read the three files and check them ({@link checkInternalTlsMaterial}).
 * Synchronous: it runs once, at boot, before the listener exists.
 *
 * @throws InternalTlsFileError naming the variable of a file that cannot be read
 */
export function readInternalTlsFiles(files: InternalTlsFiles): InternalTlsMaterial {
  const read = (name: keyof InternalTlsFiles): Buffer => {
    try {
      return readFileSync(files[name]);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? 'unreadable';
      throw new InternalTlsFileError(
        `${VARIABLES[name]} names ${files[name]}, which cannot be read (${code})`
      );
    }
  };
  const material = { cert: read('certPath'), key: read('keyPath'), ca: read('caPath') };
  checkInternalTlsMaterial(material);
  return material;
}

/** What a log line says about a certificate: never its key, nor the whole PEM. */
export function describeCertificate(cert: Buffer): Record<string, string> {
  try {
    const parsed = new X509Certificate(cert);
    return {
      serialNumber: parsed.serialNumber,
      validTo: parsed.validTo,
      fingerprint256: parsed.fingerprint256,
    };
  } catch {
    return {};
  }
}

/** Options for {@link watchInternalTlsFiles}. */
export interface InternalTlsWatchOptions {
  /** How often the files are read again. {@link DEFAULT_TLS_RELOAD_INTERVAL_MS} unless set. */
  readonly intervalMs?: number;
  /**
   * Called when the files changed but cannot be used yet, such as a key
   * written before its certificate: the material in use stays. Called once
   * per distinct set of contents, not on every read.
   */
  readonly onError?: (error: InternalTlsFileError) => void;
}

/** A running watch; {@link stop} ends it. */
export interface InternalTlsWatcher {
  stop(): void;
}

function sameMaterial(a: InternalTlsMaterial, b: InternalTlsMaterial): boolean {
  return a.cert.equals(b.cert) && a.key.equals(b.key) && a.ca.equals(b.ca);
}

/**
 * Read the files every `intervalMs` and hand each new, usable set of contents
 * to `onChange`. A rotation that writes the certificate and the key one after
 * the other leaves the material in use until both match, and a file that
 * cannot be read for a moment changes nothing. Contents are compared, not
 * modification times, so a file swapped through a symbolic link (as a
 * Kubernetes secret volume does) or rewritten within one second is seen.
 *
 * The timer does not keep the process alive.
 */
export function watchInternalTlsFiles(
  files: InternalTlsFiles,
  initial: InternalTlsMaterial,
  onChange: (material: InternalTlsMaterial) => void,
  options: InternalTlsWatchOptions = {}
): InternalTlsWatcher {
  let current = initial;
  let refused: InternalTlsMaterial | undefined;
  let reading = false;
  let stopped = false;

  const check = async (): Promise<void> => {
    let next: InternalTlsMaterial;
    try {
      const [cert, key, ca] = await Promise.all([
        readFile(files.certPath),
        readFile(files.keyPath),
        readFile(files.caPath),
      ]);
      next = { cert, key, ca };
    } catch {
      // Mid-rotation, a file may be missing for a moment: read again later.
      return;
    }
    if (stopped || sameMaterial(next, current)) return;
    if (refused !== undefined && sameMaterial(next, refused)) return;
    try {
      checkInternalTlsMaterial(next);
    } catch (error) {
      refused = next;
      options.onError?.(error as InternalTlsFileError);
      return;
    }
    try {
      onChange(next);
    } catch (error) {
      refused = next;
      const reason = error instanceof Error ? error.message : String(error);
      options.onError?.(
        new InternalTlsFileError(`The new internal TLS files were not applied: ${reason}`)
      );
      return;
    }
    refused = undefined;
    current = next;
  };

  const timer = setInterval(() => {
    if (reading) return;
    reading = true;
    void check().finally(() => {
      reading = false;
    });
  }, options.intervalMs ?? DEFAULT_TLS_RELOAD_INTERVAL_MS);
  timer.unref();

  return {
    stop(): void {
      stopped = true;
      clearInterval(timer);
    },
  };
}
