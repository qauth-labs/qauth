import { describe, expect, it } from 'vitest';

import { isCimdClientIdShape, manifestSchema } from './seed-manifest';

/**
 * Validation of the seed manifest, and of its `cimd_clients` section (#770).
 * What an entry writes is covered against real Postgres in
 * `cimd-client-grants.integration.test.ts`.
 */
describe('manifestSchema', () => {
  const machineClient = {
    client_id: 'memory-mcp-demo',
    name: 'memory-mcp demo',
    grant_types: ['client_credentials'],
    scopes: ['mcp:read'],
    audience: ['http://localhost:8088'],
    token_endpoint_auth_method: 'client_secret_basic',
  };
  const cimdClient = {
    client_id: 'https://client.example.com/oauth/metadata.json',
    scopes: ['mcp:read', 'offline_access'],
    audience: ['https://mcp.example.com/mcp'],
  };

  it('accepts a manifest written before cimd_clients existed, unchanged', () => {
    const manifest = { realm: 'master', clients: [machineClient] };
    expect(manifestSchema.parse(manifest)).toEqual(manifest);
  });

  it('accepts a manifest with only CIMD entries, or with both kinds', () => {
    expect(manifestSchema.safeParse({ realm: 'master', cimd_clients: [cimdClient] }).success).toBe(
      true
    );
    expect(
      manifestSchema.safeParse({
        realm: 'master',
        clients: [machineClient],
        cimd_clients: [cimdClient, { client_id: 'https://other.example.com/c', scopes: [] }],
      }).success
    ).toBe(true);
  });

  it.each([
    [{ realm: 'master' }],
    [{ realm: 'master', clients: [] }],
    [{ realm: 'master', clients: [], cimd_clients: [] }],
  ])('refuses a manifest with no client: %j', (manifest) => {
    expect(manifestSchema.safeParse(manifest).success).toBe(false);
  });

  it('refuses a client_id listed under both clients and cimd_clients', () => {
    const result = manifestSchema.safeParse({
      realm: 'master',
      clients: [{ ...machineClient, client_id: cimdClient.client_id }],
      cimd_clients: [cimdClient],
    });
    expect(result.success).toBe(false);
  });

  it('refuses the same CIMD client_id twice', () => {
    const result = manifestSchema.safeParse({
      realm: 'master',
      cimd_clients: [cimdClient, { ...cimdClient, scopes: [] }],
    });
    expect(result.success).toBe(false);
  });

  it.each([
    ['a field the document owns', { name: 'Example' }],
    ['a redirect URI', { redirect_uris: ['https://client.example.com/cb'] }],
    ['a secret', { client_secret: 'x' }],
  ])('refuses a CIMD entry carrying %s', (_label, extra) => {
    const result = manifestSchema.safeParse({
      realm: 'master',
      cimd_clients: [{ ...cimdClient, ...extra }],
    });
    expect(result.success).toBe(false);
  });

  it('requires a CIMD entry to state its scopes', () => {
    const withoutScopes = { client_id: cimdClient.client_id, audience: cimdClient.audience };
    expect(
      manifestSchema.safeParse({ realm: 'master', cimd_clients: [withoutScopes] }).success
    ).toBe(false);
  });

  it('refuses a CIMD client_id that is not a CIMD client_id', () => {
    const result = manifestSchema.safeParse({
      realm: 'master',
      cimd_clients: [{ ...cimdClient, client_id: 'http://client.example.com/oauth/metadata.json' }],
    });
    expect(result.success).toBe(false);
  });
});

describe('isCimdClientIdShape', () => {
  it.each([
    'https://client.example.com/oauth/metadata.json',
    'https://client.example.com/c',
    'https://client.example.com:8443/c?v=1',
  ])('accepts %s', (value) => {
    expect(isCimdClientIdShape(value)).toBe(true);
  });

  it.each([
    ['http, not https', 'http://client.example.com/c'],
    ['no path', 'https://client.example.com'],
    ['the root path', 'https://client.example.com/'],
    ['a fragment', 'https://client.example.com/c#x'],
    ['a non-ASCII host', 'https://client.exämple.com/c'],
    ['a space', 'https://client.example.com/a b'],
    ['not a URL', 'memory-mcp-demo'],
  ])('refuses %s', (_label, value) => {
    expect(isCimdClientIdShape(value)).toBe(false);
  });
});
