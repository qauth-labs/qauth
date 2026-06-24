import { describe, expect, it } from 'vitest';

import { buildWwwAuthenticate, challengeForError } from './challenge';
import { InsufficientScopeError, InvalidTokenError, MissingTokenError } from './errors';

const META = 'https://mcp.example.com/.well-known/oauth-protected-resource';

describe('buildWwwAuthenticate', () => {
  it('emits a bare challenge with only resource_metadata when no error', () => {
    expect(buildWwwAuthenticate({ resourceMetadataUrl: META })).toBe(
      `Bearer resource_metadata="${META}"`
    );
  });

  it('includes error, description and resource_metadata', () => {
    const header = buildWwwAuthenticate({
      resourceMetadataUrl: META,
      error: 'invalid_token',
      errorDescription: 'token expired',
    });
    expect(header).toBe(
      `Bearer error="invalid_token", error_description="token expired", resource_metadata="${META}"`
    );
  });

  it('includes a space-joined scope challenge', () => {
    const header = buildWwwAuthenticate({
      resourceMetadataUrl: META,
      error: 'insufficient_scope',
      scope: ['mcp:read', 'mcp:write'],
    });
    expect(header).toContain('error="insufficient_scope"');
    expect(header).toContain('scope="mcp:read mcp:write"');
  });

  it('escapes quotes/backslashes in values', () => {
    const header = buildWwwAuthenticate({
      resourceMetadataUrl: META,
      errorDescription: 'a "weird" \\ value',
    });
    expect(header).toContain('error_description="a \\"weird\\" \\\\ value"');
  });
});

describe('challengeForError', () => {
  it('maps MissingTokenError to a bare Bearer challenge (no error code)', () => {
    const header = challengeForError(new MissingTokenError(), META);
    expect(header).toBe(`Bearer resource_metadata="${META}"`);
  });

  it('maps InvalidTokenError to error="invalid_token" with the reason', () => {
    const header = challengeForError(new InvalidTokenError('token expired'), META);
    expect(header).toContain('error="invalid_token"');
    expect(header).toContain('error_description="token expired"');
  });

  it('maps InsufficientScopeError to error="insufficient_scope" with the full required set', () => {
    const header = challengeForError(
      new InsufficientScopeError(['mcp:read', 'mcp:admin'], ['mcp:admin']),
      META
    );
    expect(header).toContain('error="insufficient_scope"');
    // The challenge advertises the FULL required set so the client can request
    // a single sufficient authorization.
    expect(header).toContain('scope="mcp:read mcp:admin"');
  });
});
