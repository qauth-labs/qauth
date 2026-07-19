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
    // #284 must not disturb the 403 step-up wire shape.
    expect(header).toBe(
      `Bearer error="insufficient_scope", scope="mcp:read mcp:admin", resource_metadata="${META}"`
    );
  });

  // #284 — MCP Authorization ("Scope Selection Strategy"): the 401 advertises
  // what the route needs so a client authorizes correctly on its first attempt.
  it('advertises the route required scopes on the credential-absent 401', () => {
    const header = challengeForError(new MissingTokenError(['mcp:read', 'mcp:write']), META);
    expect(header).toBe(`Bearer scope="mcp:read mcp:write", resource_metadata="${META}"`);
    // RFC 6750 §3.1: `error` is omitted when no credentials were presented.
    expect(header).not.toContain('error=');
  });

  it('omits scope entirely when the route requires no scopes', () => {
    // Not `scope=""` — an empty challenge value would tell a client to request
    // an empty authorization rather than "nothing specific is required".
    expect(challengeForError(new MissingTokenError([]), META)).toBe(
      `Bearer resource_metadata="${META}"`
    );
  });

  it('never advertises offline_access, which is not a resource requirement', () => {
    const bare = challengeForError(new MissingTokenError(['mcp:read', 'offline_access']), META);
    expect(bare).toBe(`Bearer scope="mcp:read", resource_metadata="${META}"`);

    const stepUp = challengeForError(
      new InsufficientScopeError(['mcp:read', 'offline_access'], ['offline_access']),
      META
    );
    expect(stepUp).not.toContain('offline_access');
  });

  it('drops scope when offline_access was the only required scope', () => {
    expect(challengeForError(new MissingTokenError(['offline_access']), META)).toBe(
      `Bearer resource_metadata="${META}"`
    );
  });

  it('does not advertise scope on an invalid_token 401 (remedy is re-auth, not consent)', () => {
    const header = challengeForError(new InvalidTokenError('token expired'), META);
    expect(header).not.toContain('scope=');
  });
});
