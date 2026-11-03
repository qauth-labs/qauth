import { describe, expect, it, vi } from 'vitest';

import { parseVerifiedDomainArgs, setClientVerifiedDomain } from './client-verified-domain';

/**
 * Arguments and the domain check of the verified-domain tool (#914). The
 * database half is covered against real Postgres in
 * `client-verified-domain.integration.test.ts`.
 */
describe('parseVerifiedDomainArgs', () => {
  const argv = (...args: string[]) => ['node', 'set-client-verified-domain.ts', ...args];

  it('sets the domain given', () => {
    expect(
      parseVerifiedDomainArgs(
        argv('--realm=master', '--client-id=notes', '--domain=Notes.Example.com')
      )
    ).toEqual({ realm: 'master', clientId: 'notes', domain: 'Notes.Example.com' });
  });

  it('clears with --clear', () => {
    expect(parseVerifiedDomainArgs(argv('--clear', '--realm=master', '--client-id=notes'))).toEqual(
      { realm: 'master', clientId: 'notes', domain: null }
    );
  });

  it.each([
    [[]],
    [['--realm=master', '--client-id=notes']],
    [['--realm=master', '--domain=notes.example.com']],
    [['--client-id=notes', '--domain=notes.example.com']],
    [['--realm=', '--client-id=notes', '--domain=notes.example.com']],
    [['--realm=master', '--client-id=notes', '--domain=']],
    [['--realm=master', '--client-id=notes', '--domain=notes.example.com', '--clear']],
    [['--realm=master', '--client-id=notes', '--domain=notes.example.com', '--rotate']],
    [['--realm=master', '--client-id=notes', 'notes.example.com']],
  ])('refuses %j instead of guessing', (args) => {
    expect(parseVerifiedDomainArgs(argv(...args))).toBeNull();
  });
});

describe('setClientVerifiedDomain', () => {
  /** A database that fails the test if the tool reads or writes it. */
  const untouched = () => {
    const transaction = vi.fn(() => {
      throw new Error('the database was used');
    });
    return { db: { transaction } as never, transaction };
  };

  it.each([
    ['co.uk', 'public_suffix'],
    ['eu.org', 'public_suffix'],
    ['localhost', 'single_label'],
    ['192.0.2.1', 'ip_literal'],
    ['notes.example.com:443', 'malformed'],
    ['https://notes.example.com', 'malformed'],
    ['*.example.com', 'malformed'],
    ['my_app.example.com', 'malformed'],
  ])('refuses %s (%s) before it touches the database', async (domain, reason) => {
    const { db, transaction } = untouched();
    await expect(
      setClientVerifiedDomain(db, { realm: 'master', clientId: 'notes', domain })
    ).resolves.toEqual({ status: 'invalid_domain', reason });
    expect(transaction).not.toHaveBeenCalled();
  });
});
