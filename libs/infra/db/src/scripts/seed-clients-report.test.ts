import { describe, expect, it, vi } from 'vitest';

import type { Issued } from './seed-clients';
import { reportClients } from './seed-clients-report';

/** What the report prints for these results, line by line. */
function printed(issued: Issued[]): string[] {
  const lines: string[] = [];
  const capture = (...args: unknown[]) => {
    lines.push(...args.map(String).join(' ').split('\n'));
  };
  const log = vi.spyOn(console, 'log').mockImplementation(capture);
  const error = vi.spyOn(console, 'error').mockImplementation(capture);
  try {
    reportClients('default', issued);
  } finally {
    log.mockRestore();
    error.mockRestore();
  }
  return lines;
}

describe('the seed report (#1138)', () => {
  const SECRET = 'f'.repeat(64);

  it('prints no secret or fingerprint line for an entry without a secret', () => {
    const lines = printed([
      { clientId: 'notes-worker', action: 'created', authenticatesWith: 'private_key_jwt' },
      { clientId: 'notes-spa', action: 'rotated', authenticatesWith: 'none' },
    ]);

    expect(lines.filter((line) => /^\s*(secret|fingerprint):/.test(line))).toEqual([]);
    expect(lines.some((line) => line.startsWith('Store these plaintext secrets'))).toBe(false);
    expect(lines).toContain(
      '  notes-worker: created, no secret (authenticates with private_key_jwt)'
    );
    expect(lines).toContain('  notes-spa: rotated, no secret (authenticates with none)');
    // A client without a secret never has an id line of its own, which a
    // reader of the secret block would match.
    expect(lines).not.toContain('  notes-worker');
    expect(lines).not.toContain('  notes-spa');
  });

  it('prints the secret block only for the entries that carry a secret', () => {
    const lines = printed([
      { clientId: 'notes-worker', action: 'created', authenticatesWith: 'private_key_jwt' },
      { clientId: 'notes-service', action: 'created', secret: SECRET },
    ]);

    const secrets = lines.filter((line) => /^\s*secret:/.test(line));
    expect(secrets).toEqual([`    secret:      ${SECRET}`]);
    const at = lines.indexOf('  notes-service');
    expect(lines.slice(at, at + 4)).toEqual([
      '  notes-service',
      `    secret:      ${SECRET}`,
      expect.stringMatching(/^ {4}fingerprint: [0-9a-f]{8}$/),
      '    action:      created',
    ]);
    // The secret block comes first, and the client without one after it.
    const secretless = lines.indexOf(
      '  notes-worker: created, no secret (authenticates with private_key_jwt)'
    );
    expect(secretless).toBeGreaterThan(at);
  });

  it('says a rotation replaced the hash of a secret an earlier release printed', () => {
    const rotated = printed([
      { clientId: 'notes-worker', action: 'rotated', authenticatesWith: 'private_key_jwt' },
    ]);
    const created = printed([
      { clientId: 'notes-worker', action: 'created', authenticatesWith: 'private_key_jwt' },
    ]);

    const note = 'replaced the hash of any secret an earlier release printed';
    expect(rotated.some((line) => line.includes(note))).toBe(true);
    expect(created.some((line) => line.includes(note))).toBe(false);
  });

  // #522: a service account's client is the service-accounts command's.
  it("names a refused service account's client on its own, not as a first-party refusal", () => {
    const exitCode = process.exitCode;
    try {
      const lines = printed([{ clientId: 'ci', action: 'refused', refusal: 'service_account' }]);

      expect(lines.some((line) => line.includes("service accounts' clients"))).toBe(true);
      expect(lines).toContain('  ci');
      expect(lines.some((line) => line.includes('first_party_profile'))).toBe(false);
      expect(process.exitCode).toBe(1);
    } finally {
      process.exitCode = exitCode;
    }
  });

  it('prints nothing about secrets for a run that skipped every entry', () => {
    const lines = printed([{ clientId: 'notes-service', action: 'skipped' }]);

    expect(lines.filter((line) => /secret:|fingerprint:|no secret \(/.test(line))).toEqual([]);
  });
});
