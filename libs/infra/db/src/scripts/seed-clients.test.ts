import { describe, expect, it } from 'vitest';

import { buildInsert, buildUpdate } from './seed-clients';
import { type ClientSpec, clientSpecSchema } from './seed-manifest';

/**
 * The row the seeder writes for a manifest entry. Against real Postgres, the
 * seeder is covered by `seed-clients.integration.test.ts`.
 */
describe('client_credentials_scopes rows (#891)', () => {
  const spec = (overrides: Record<string, unknown> = {}): ClientSpec =>
    clientSpecSchema.parse({
      client_id: 'notes-app',
      name: 'Notes',
      grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      redirect_uris: ['https://notes.example.com/callback'],
      scopes: ['openid', 'notes:read', 'ssf:stream'],
      ...overrides,
    });

  it('writes the list once per scope, on a new client and on a rotation', () => {
    const entry = spec({ client_credentials_scopes: ['ssf:stream', 'ssf:stream'] });
    expect(buildInsert('realm-id', entry, 'hash').clientCredentialsScopes).toEqual(['ssf:stream']);
    expect(buildUpdate(entry, 'hash').clientCredentialsScopes).toEqual(['ssf:stream']);
  });

  it('writes NULL for an entry without one, so a rotation clears a list the manifest dropped', () => {
    expect(buildInsert('realm-id', spec(), 'hash').clientCredentialsScopes).toBeNull();
    expect(buildUpdate(spec(), 'hash').clientCredentialsScopes).toBeNull();
  });
});
