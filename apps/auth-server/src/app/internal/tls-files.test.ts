import { chmodSync, writeFileSync } from 'node:fs';
import { rootCertificates } from 'node:tls';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createInternalPki,
  type TlsFileDirectory,
  writeTlsFiles,
} from '../../testing/internal-pki';
import {
  checkInternalTlsMaterial,
  describeCertificate,
  internalSecureContextOptions,
  InternalTlsFileError,
  readInternalTlsFiles,
  watchInternalTlsFiles,
} from './tls-files';

/** The internal TLS files: read, checked, and read again when they change (#496). */

const directories: TlsFileDirectory[] = [];

function files() {
  const pki = createInternalPki();
  const directory = writeTlsFiles(pki.issue({ dnsNames: ['signer.qauth.internal'] }), pki.caPem);
  directories.push(directory);
  return { pki, directory };
}

afterEach(() => {
  for (const directory of directories.splice(0)) directory.remove();
});

/** Wait until `check` holds, every 10 ms, for 3 s at most. */
async function eventually(check: () => boolean): Promise<void> {
  const started = Date.now();
  while (!check()) {
    if (Date.now() - started > 3_000) throw new Error('eventually: timed out');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe('readInternalTlsFiles', () => {
  it('reads the three files', () => {
    const { directory } = files();
    const material = readInternalTlsFiles(directory.files);
    expect(material.cert.toString()).toContain('BEGIN CERTIFICATE');
    expect(material.key.toString()).toContain('BEGIN PRIVATE KEY');
    expect(material.ca.toString()).toContain('BEGIN CERTIFICATE');
  });

  it('names the variable of a file that cannot be read', () => {
    const { directory } = files();
    for (const [name, variable] of [
      ['certPath', 'INTERNAL_TLS_CERT_PATH'],
      ['keyPath', 'INTERNAL_TLS_KEY_PATH'],
      ['caPath', 'INTERNAL_TLS_CA_PATH'],
    ] as const) {
      const missing = { ...directory.files, [name]: `${directory.files[name]}.missing` };
      expect(() => readInternalTlsFiles(missing)).toThrow(InternalTlsFileError);
      expect(() => readInternalTlsFiles(missing)).toThrow(
        new RegExp(`^${variable} names .* which cannot be read \\(ENOENT\\)$`)
      );
    }
  });

  it("refuses a key that is not the certificate's own, and says nothing of either", () => {
    const { pki, directory } = files();
    const other = pki.issue({ dnsNames: ['other.qauth.internal'] });
    writeFileSync(directory.files.keyPath, other.key);
    let message = '';
    try {
      readInternalTlsFiles(directory.files);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain(
      'INTERNAL_TLS_KEY_PATH and INTERNAL_TLS_CERT_PATH do not make a TLS identity'
    );
    expect(message).not.toContain('PRIVATE KEY');
  });

  it('refuses an expired certificate, and lets one through that starts a moment from now', () => {
    const { pki, directory } = files();
    const expired = pki.issue({
      dnsNames: ['signer.qauth.internal'],
      notBefore: new Date(Date.now() - 2 * 86_400_000),
      notAfter: new Date(Date.now() - 86_400_000),
    });
    directory.replace(expired, pki.caPem);
    expect(() => readInternalTlsFiles(directory.files)).toThrow(
      /^INTERNAL_TLS_CERT_PATH holds a certificate that expired on /
    );
    const early = pki.issue({
      dnsNames: ['signer.qauth.internal'],
      notBefore: new Date(Date.now() + 30_000),
    });
    directory.replace(early, pki.caPem);
    expect(() => readInternalTlsFiles(directory.files)).not.toThrow();
  });

  it('refuses a CA file that holds a public root CA, as a system bundle does', () => {
    const { pki, directory } = files();
    writeFileSync(directory.files.caPath, `${pki.caPem}\n${rootCertificates[0]}\n`);
    expect(() => readInternalTlsFiles(directory.files)).toThrow(
      /^INTERNAL_TLS_CA_PATH holds a public root CA \(.+\): it must hold only the CA that issues QAuth's internal peers, never a system bundle/
    );
    writeFileSync(directory.files.caPath, rootCertificates.join('\n'));
    expect(() => readInternalTlsFiles(directory.files)).toThrow('holds a public root CA');
  });

  it('reads every certificate of the CA file, and refuses one that does not parse', () => {
    const { pki, directory } = files();
    const other = createInternalPki('Another CA');
    writeFileSync(directory.files.caPath, `${other.caPem}\n${pki.caPem}\n`);
    expect(() => readInternalTlsFiles(directory.files)).not.toThrow();
    writeFileSync(
      directory.files.caPath,
      `${pki.caPem}\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n`
    );
    expect(() => readInternalTlsFiles(directory.files)).toThrow(
      'INTERNAL_TLS_CA_PATH does not hold'
    );
  });

  it('warns of a CA file with no certificate marked as a CA', () => {
    const { pki, directory } = files();
    chmodSync(directory.files.keyPath, 0o600);
    const onWarning = vi.fn();
    readInternalTlsFiles(directory.files, { onWarning });
    expect(onWarning).not.toHaveBeenCalled();

    writeFileSync(directory.files.caPath, pki.issue({ dnsNames: ['leaf.qauth.internal'] }).cert);
    readInternalTlsFiles(directory.files, { onWarning });
    expect(onWarning).toHaveBeenCalledTimes(1);
    expect(onWarning.mock.calls[0]?.[0]).toContain(
      'INTERNAL_TLS_CA_PATH holds no CA certificate (none has basicConstraints CA:TRUE)'
    );
  });

  it('warns of a key file its group or others may read, and still reads it', () => {
    const { directory } = files();
    const onWarning = vi.fn();
    for (const mode of [0o600, 0o400]) {
      chmodSync(directory.files.keyPath, mode);
      readInternalTlsFiles(directory.files, { onWarning });
    }
    expect(onWarning).not.toHaveBeenCalled();
    for (const mode of [0o644, 0o640, 0o604]) {
      chmodSync(directory.files.keyPath, mode);
      expect(readInternalTlsFiles(directory.files, { onWarning }).key.length).toBeGreaterThan(0);
    }
    expect(onWarning.mock.calls.map(([message]) => String(message))).toEqual([
      expect.stringMatching(
        /^INTERNAL_TLS_KEY_PATH names .* which its group or others may read \(mode 0644\)/
      ),
      expect.stringContaining('(mode 0640)'),
      expect.stringContaining('(mode 0604)'),
    ]);
  });

  it('refuses files that hold no PEM certificate', () => {
    const { directory } = files();
    writeFileSync(directory.files.caPath, 'not a certificate');
    expect(() => readInternalTlsFiles(directory.files)).toThrow(
      'INTERNAL_TLS_CA_PATH does not hold'
    );
    writeFileSync(directory.files.certPath, 'not a certificate');
    expect(() => readInternalTlsFiles(directory.files)).toThrow(
      'INTERNAL_TLS_CERT_PATH does not hold'
    );
  });
});

describe('internalSecureContextOptions', () => {
  it('allows TLS 1.3 only', () => {
    const { directory } = files();
    const options = internalSecureContextOptions(readInternalTlsFiles(directory.files));
    expect(options.minVersion).toBe('TLSv1.3');
    expect(options.maxVersion).toBe('TLSv1.3');
    expect(() => checkInternalTlsMaterial(readInternalTlsFiles(directory.files))).not.toThrow();
  });
});

describe('describeCertificate', () => {
  it('names the certificate without its contents', () => {
    const { directory } = files();
    const described = describeCertificate(readInternalTlsFiles(directory.files).cert);
    expect(Object.keys(described).sort()).toEqual(['fingerprint256', 'serialNumber', 'validTo']);
    expect(describeCertificate(Buffer.from('junk'))).toEqual({});
  });
});

describe('watchInternalTlsFiles', () => {
  it('hands over each new usable set of files, and nothing while they do not change', async () => {
    const { pki, directory } = files();
    const initial = readInternalTlsFiles(directory.files);
    const onChange = vi.fn();
    const watcher = watchInternalTlsFiles(directory.files, initial, onChange, { intervalMs: 10 });
    try {
      await new Promise((resolve) => setTimeout(resolve, 60));
      expect(onChange).not.toHaveBeenCalled();
      const next = pki.issue({ dnsNames: ['signer.qauth.internal'] });
      directory.replace(next, pki.caPem);
      await eventually(() => onChange.mock.calls.length === 1);
      expect(onChange.mock.calls[0]?.[0].cert.toString()).toBe(next.cert);
      await new Promise((resolve) => setTimeout(resolve, 60));
      expect(onChange).toHaveBeenCalledTimes(1);
    } finally {
      watcher.stop();
    }
  });

  it('waits out a rotation half-way, reporting it once, and a file missing for a moment', async () => {
    const { pki, directory } = files();
    const initial = readInternalTlsFiles(directory.files);
    const onChange = vi.fn();
    const onError = vi.fn();
    const watcher = watchInternalTlsFiles(directory.files, initial, onChange, {
      intervalMs: 10,
      onError,
    });
    try {
      const next = pki.issue({ dnsNames: ['signer.qauth.internal'] });
      directory.writeOne('certPath', next.cert);
      await eventually(() => onError.mock.calls.length === 1);
      await new Promise((resolve) => setTimeout(resolve, 60));
      expect(onError).toHaveBeenCalledTimes(1);
      expect(onChange).not.toHaveBeenCalled();
      directory.writeOne('keyPath', next.key);
      await eventually(() => onChange.mock.calls.length === 1);
    } finally {
      watcher.stop();
    }
  });

  it('reports a context the listener cannot apply, and keeps the old one', async () => {
    const { pki, directory } = files();
    const initial = readInternalTlsFiles(directory.files);
    const onError = vi.fn();
    const watcher = watchInternalTlsFiles(
      directory.files,
      initial,
      () => {
        throw new Error('refused');
      },
      { intervalMs: 10, onError }
    );
    try {
      directory.replace(pki.issue({ dnsNames: ['signer.qauth.internal'] }), pki.caPem);
      await eventually(() => onError.mock.calls.length === 1);
      expect(String(onError.mock.calls[0]?.[0].message)).toContain('were not applied: refused');
    } finally {
      watcher.stop();
    }
  });

  it('warns of what new files it hands over hold that is likely a mistake', async () => {
    const { pki, directory } = files();
    const initial = readInternalTlsFiles(directory.files);
    const onChange = vi.fn();
    const onWarning = vi.fn();
    const watcher = watchInternalTlsFiles(directory.files, initial, onChange, {
      intervalMs: 10,
      onWarning,
    });
    try {
      writeFileSync(directory.files.caPath, pki.issue({ dnsNames: ['leaf.qauth.internal'] }).cert);
      await eventually(() => onChange.mock.calls.length === 1);
      expect(onWarning).toHaveBeenCalledWith(expect.stringContaining('holds no CA certificate'));
    } finally {
      watcher.stop();
    }
  });

  it('stops reading once stopped', async () => {
    const { pki, directory } = files();
    const onChange = vi.fn();
    const watcher = watchInternalTlsFiles(
      directory.files,
      readInternalTlsFiles(directory.files),
      onChange,
      { intervalMs: 10 }
    );
    watcher.stop();
    directory.replace(pki.issue({ dnsNames: ['signer.qauth.internal'] }), pki.caPem);
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(onChange).not.toHaveBeenCalled();
  });
});
