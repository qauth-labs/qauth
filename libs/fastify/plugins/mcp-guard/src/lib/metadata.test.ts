import { describe, expect, it } from 'vitest';

import {
  buildProtectedResourceMetadata,
  metadataPathForResource,
  metadataUrlForResource,
  PRM_WELL_KNOWN_PREFIX,
} from './metadata';

describe('buildProtectedResourceMetadata', () => {
  it('produces an RFC 9728 document pointing at the AS', () => {
    const doc = buildProtectedResourceMetadata({
      resource: 'https://mcp.example.com',
      authorizationServer: 'https://auth.example.com',
    });
    expect(doc).toEqual({
      resource: 'https://mcp.example.com',
      authorization_servers: ['https://auth.example.com'],
      bearer_methods_supported: ['header'],
    });
  });

  it('normalises trailing slashes on resource and AS', () => {
    const doc = buildProtectedResourceMetadata({
      resource: 'https://mcp.example.com/',
      authorizationServer: 'https://auth.example.com/',
    });
    expect(doc.resource).toBe('https://mcp.example.com');
    expect(doc.authorization_servers[0]).toBe('https://auth.example.com');
  });

  it('advertises supported scopes when provided', () => {
    const doc = buildProtectedResourceMetadata({
      resource: 'https://mcp.example.com',
      authorizationServer: 'https://auth.example.com',
      scopesSupported: ['mcp:read', 'mcp:write'],
    });
    expect(doc.scopes_supported).toEqual(['mcp:read', 'mcp:write']);
  });

  it('omits scopes_supported when the list is empty', () => {
    const doc = buildProtectedResourceMetadata({
      resource: 'https://mcp.example.com',
      authorizationServer: 'https://auth.example.com',
      scopesSupported: [],
    });
    expect(doc.scopes_supported).toBeUndefined();
  });
});

describe('metadataPathForResource (RFC 9728 §3.1)', () => {
  it('uses the bare well-known prefix for a path-less resource', () => {
    expect(metadataPathForResource('https://mcp.example.com')).toBe(PRM_WELL_KNOWN_PREFIX);
    expect(metadataPathForResource('https://mcp.example.com/')).toBe(PRM_WELL_KNOWN_PREFIX);
  });

  it('inserts the resource path after the well-known prefix', () => {
    expect(metadataPathForResource('https://host.example.com/mcp/memory')).toBe(
      '/.well-known/oauth-protected-resource/mcp/memory'
    );
  });

  it('strips a trailing slash on the resource path', () => {
    expect(metadataPathForResource('https://host.example.com/mcp/')).toBe(
      '/.well-known/oauth-protected-resource/mcp'
    );
  });

  it('falls back to the bare prefix for a non-URL resource', () => {
    expect(metadataPathForResource('urn:example:resource')).toBe(PRM_WELL_KNOWN_PREFIX);
  });
});

describe('metadataUrlForResource', () => {
  it('builds an absolute URL on the resource origin', () => {
    expect(metadataUrlForResource('https://mcp.example.com')).toBe(
      'https://mcp.example.com/.well-known/oauth-protected-resource'
    );
  });

  it('keeps the resource path segment in the URL', () => {
    expect(metadataUrlForResource('https://host.example.com/mcp/memory')).toBe(
      'https://host.example.com/.well-known/oauth-protected-resource/mcp/memory'
    );
  });
});
