import { Argon2QueueFullError } from '@qauth-labs/fastify-plugin-password';
import {
  InvalidClientError,
  InvalidScopeError,
  TemporarilyUnavailableError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

// client-auth → client-resolution → cimd pulls in the env module; stub it so
// the real env-schema parse (which needs DB/EMAIL vars) does not run in tests.
vi.mock('../../config/env', () => ({
  env: {
    CIMD_ENABLED: true,
    CIMD_TRUST_POLICY: 'accept-any-https',
    CIMD_TRUSTED_DOMAINS: [],
    CIMD_CACHE_DEFAULT_TTL: 300,
    CIMD_CACHE_MAX_TTL: 3600,
    CIMD_MAX_DOCUMENT_BYTES: 65536,
    CIMD_FETCH_TIMEOUT_MS: 5000,
    CIMD_ALLOW_PRIVATE_ADDRESSES: false,
  },
}));

import { CLIENT_ASSERTION_TYPE_JWT_BEARER } from '../schemas/oauth';
import {
  authenticateClient,
  authenticateClientRequest,
  classifyClientAuthentication,
  enforceAgentScopeCap,
  extractClientCredentials,
  type OAuthClientLike,
  resolveAudience,
  SHED_CLIENT_SECRET_RETRY_AFTER_SECONDS,
  toAgentScopeContext,
  unlistedReservedAudiences,
  validateScopes,
} from './client-auth';

function requestWith(authHeader: string | undefined): FastifyRequest {
  return {
    headers: authHeader === undefined ? {} : { authorization: authHeader },
  } as unknown as FastifyRequest;
}

describe('extractClientCredentials', () => {
  it('extracts client_secret_post credentials from the body', () => {
    const creds = extractClientCredentials(requestWith(undefined), 'cid', 'csecret');
    expect(creds).toEqual({
      clientId: 'cid',
      clientSecret: 'csecret',
      method: 'client_secret_post',
    });
  });

  it('decodes client_secret_basic credentials from the Authorization header', () => {
    const basic = Buffer.from('cid:csecret', 'utf8').toString('base64');
    const creds = extractClientCredentials(requestWith(`Basic ${basic}`), undefined, undefined);
    expect(creds).toEqual({
      clientId: 'cid',
      clientSecret: 'csecret',
      method: 'client_secret_basic',
    });
  });

  it('URL-decodes Basic credentials (RFC 6749 §2.3.1 form-urlencoding)', () => {
    // `+` represents a space in application/x-www-form-urlencoded.
    const raw = 'user+name:p%40ss%3Aword';
    const basic = Buffer.from(raw, 'utf8').toString('base64');
    const creds = extractClientCredentials(requestWith(`Basic ${basic}`), undefined, undefined);
    expect(creds.clientId).toBe('user name');
    expect(creds.clientSecret).toBe('p@ss:word');
  });

  it('throws InvalidClientError for malformed base64 in Basic header', () => {
    expect(() =>
      extractClientCredentials(requestWith('Basic !!!not-base64!!!'), undefined, undefined)
    ).toThrow(InvalidClientError);
  });

  it('throws InvalidClientError when Basic payload has no colon separator', () => {
    const basic = Buffer.from('no-colon', 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${basic}`), undefined, undefined)
    ).toThrow(InvalidClientError);
  });

  it('throws InvalidClientError when Basic credentials have empty clientId or secret', () => {
    const emptyId = Buffer.from(':secret', 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${emptyId}`), undefined, undefined)
    ).toThrow(InvalidClientError);

    const emptySecret = Buffer.from('cid:', 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${emptySecret}`), undefined, undefined)
    ).toThrow(InvalidClientError);
  });

  it('rejects requests that mix Basic and body client_secret (RFC 6749 §2.3)', () => {
    const basic = Buffer.from('cid:csecret', 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${basic}`), undefined, 'body-secret')
    ).toThrow(InvalidClientError);
  });

  it('rejects requests where Basic clientId disagrees with body client_id', () => {
    const basic = Buffer.from('cid-a:csecret', 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${basic}`), 'cid-b', undefined)
    ).toThrow(InvalidClientError);
  });

  it('accepts Basic when body client_id matches and no body secret is present', () => {
    const basic = Buffer.from('cid-a:csecret', 'utf8').toString('base64');
    const creds = extractClientCredentials(requestWith(`Basic ${basic}`), 'cid-a', undefined);
    expect(creds.method).toBe('client_secret_basic');
    expect(creds.clientId).toBe('cid-a');
  });

  it('throws InvalidClientError when no credentials are supplied', () => {
    expect(() => extractClientCredentials(requestWith(undefined), undefined, undefined)).toThrow(
      InvalidClientError
    );
  });

  it('does not throw URIError on malformed percent-encoding (I-e regression)', () => {
    // Base64-encode a string that will decode fine but contains an invalid
    // percent sequence — decodeURIComponent would throw URIError if not caught.
    const raw = 'foo%ZZ:bar';
    const basic = Buffer.from(raw, 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${basic}`), undefined, undefined)
    ).toThrow(InvalidClientError);
  });
});

describe('authenticateClient', () => {
  function makeFastifyStub(
    client: OAuthClientLike | null,
    passwordValid: boolean
  ): FastifyInstance {
    return {
      repositories: {
        oauthClients: {
          findByClientId: vi.fn().mockResolvedValue(client),
        },
      },
      passwordHasher: {
        verifyPassword: vi.fn().mockResolvedValue(passwordValid),
      },
    } as unknown as FastifyInstance;
  }

  const baseClient: OAuthClientLike = {
    id: 'cuid',
    clientId: 'cid',
    clientSecretHash: 'hash',
    enabled: true,
    grantTypes: ['client_credentials'],
    scopes: [],
    audience: null,
  };

  it('returns the client when credentials are valid', async () => {
    const fastify = makeFastifyStub(baseClient, true);
    const out = await authenticateClient(fastify, 'realm', {
      clientId: 'cid',
      clientSecret: 'secret',
      method: 'client_secret_post',
    });
    expect(out).toBe(baseClient);
  });

  it('throws InvalidClientError for unknown client', async () => {
    const fastify = makeFastifyStub(null, true);
    await expect(
      authenticateClient(fastify, 'realm', {
        clientId: 'missing',
        clientSecret: 'secret',
        method: 'client_secret_post',
      })
    ).rejects.toThrow(InvalidClientError);
  });

  // ANT-2026-DR5XI3LV: an operator's suspension refuses a client exactly as a
  // disable does, whatever the owner's `enabled` says.
  it('throws InvalidClientError for an operator-suspended client, before the secret check', async () => {
    const fastify = makeFastifyStub({ ...baseClient, enabled: true, suspended: true }, true);
    await expect(
      authenticateClient(fastify, 'realm', {
        clientId: 'cid',
        clientSecret: 'secret',
        method: 'client_secret_post',
      })
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });

  it('throws InvalidClientError for disabled client', async () => {
    const fastify = makeFastifyStub({ ...baseClient, enabled: false }, true);
    await expect(
      authenticateClient(fastify, 'realm', {
        clientId: 'cid',
        clientSecret: 'secret',
        method: 'client_secret_post',
      })
    ).rejects.toThrow(InvalidClientError);
    // Must not reach password verification for a disabled client.
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });

  it('throws InvalidClientError for wrong secret', async () => {
    const fastify = makeFastifyStub(baseClient, false);
    await expect(
      authenticateClient(fastify, 'realm', {
        clientId: 'cid',
        clientSecret: 'wrong',
        method: 'client_secret_post',
      })
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledWith('hash', 'wrong', {
      shedWhenQueueFull: true,
    });
  });

  describe('with the Argon2 queue full (#751)', () => {
    function makeShedStub(client: OAuthClientLike | null): {
      fastify: FastifyInstance;
      shed: Mock;
    } {
      const shed = vi.fn();
      const fastify = {
        repositories: {
          oauthClients: { findByClientId: vi.fn().mockResolvedValue(client) },
        },
        passwordHasher: {
          verifyPassword: vi.fn().mockRejectedValue(new Argon2QueueFullError(32, 32)),
        },
        metrics: { clientSecretChecksShed: { inc: shed } },
      } as unknown as FastifyInstance;
      return { fastify, shed };
    }

    const creds = {
      clientId: 'cid',
      clientSecret: 'secret',
      method: 'client_secret_post',
    } as const;

    it('refuses with 503 and a retry delay, and counts the shed check', async () => {
      const { fastify, shed } = makeShedStub(baseClient);

      const refusal = authenticateClient(fastify, 'realm-1', creds);

      await expect(refusal).rejects.toBeInstanceOf(TemporarilyUnavailableError);
      await expect(refusal).rejects.toMatchObject({
        statusCode: 503,
        retryAfterSeconds: SHED_CLIENT_SECRET_RETRY_AFTER_SECONDS,
        details: {
          reason: 'argon2_queue_full',
          realmId: 'realm-1',
          clientId: 'cid',
          queued: 32,
          queueLimit: 32,
        },
      });
      expect(shed).toHaveBeenCalledTimes(1);
    });

    it('still answers invalid_client, uncounted, for a client it never checks a secret for', async () => {
      // Unknown, disabled and non-secret clients are refused before the hash,
      // so a full queue changes nothing for them.
      for (const client of [
        null,
        { ...baseClient, enabled: false },
        { ...baseClient, tokenEndpointAuthMethod: 'private_key_jwt' },
      ]) {
        const { fastify, shed } = makeShedStub(client);
        await expect(authenticateClient(fastify, 'realm', creds)).rejects.toThrow(
          InvalidClientError
        );
        expect(shed).not.toHaveBeenCalled();
      }
    });

    it('lets any other hasher failure through unchanged', async () => {
      const { fastify, shed } = makeShedStub(baseClient);
      const failure = new Error('hasher exploded');
      vi.mocked(fastify.passwordHasher.verifyPassword).mockRejectedValueOnce(failure);

      await expect(authenticateClient(fastify, 'realm', creds)).rejects.toBe(failure);
      expect(shed).not.toHaveBeenCalled();
    });
  });

  it('accepts a client whose auth method is unset (confidential by default)', async () => {
    const fastify = makeFastifyStub({ ...baseClient, tokenEndpointAuthMethod: undefined }, true);
    await expect(
      authenticateClient(fastify, 'realm', {
        clientId: 'cid',
        clientSecret: 'secret',
        method: 'client_secret_post',
      })
    ).resolves.toBeDefined();
  });

  it.each(['client_secret_basic', 'client_secret_post'])(
    'accepts a %s client presenting a secret',
    async (method) => {
      const fastify = makeFastifyStub({ ...baseClient, tokenEndpointAuthMethod: method }, true);
      await expect(
        authenticateClient(fastify, 'realm', {
          clientId: 'cid',
          clientSecret: 'secret',
          method: 'client_secret_post',
        })
      ).resolves.toBeDefined();
    }
  );

  it('rejects a private_key_jwt client presenting a secret, without checking the hash', async () => {
    // Every row carries a real client_secret_hash regardless of method (the
    // seed script generates one unconditionally), so this pairing check — not
    // the hash — is what makes the stronger method a requirement rather than a
    // suggestion.
    const fastify = makeFastifyStub(
      { ...baseClient, tokenEndpointAuthMethod: 'private_key_jwt' },
      true
    );
    await expect(
      authenticateClient(fastify, 'realm', {
        clientId: 'cid',
        clientSecret: 'secret',
        method: 'client_secret_post',
      })
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });

  it('rejects a public client presenting a secret', async () => {
    const fastify = makeFastifyStub({ ...baseClient, tokenEndpointAuthMethod: 'none' }, true);
    await expect(
      authenticateClient(fastify, 'realm', {
        clientId: 'cid',
        clientSecret: 'secret',
        method: 'client_secret_post',
      })
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });
});

describe('classifyClientAuthentication (RFC 6749 §2.3 — one mechanism only)', () => {
  const basic = `Basic ${Buffer.from('cid:secret', 'utf8').toString('base64')}`;

  it('classifies a body secret as the secret mechanism', () => {
    expect(
      classifyClientAuthentication(requestWith(undefined), {
        client_id: 'cid',
        client_secret: 's',
      })
    ).toBe('secret');
  });

  it('classifies a Basic header as the secret mechanism', () => {
    expect(classifyClientAuthentication(requestWith(basic), {})).toBe('secret');
  });

  it('classifies a complete assertion pair as private_key_jwt', () => {
    expect(
      classifyClientAuthentication(requestWith(undefined), {
        client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER,
        client_assertion: 'a.b.c',
      })
    ).toBe('private_key_jwt');
  });

  it('classifies a bare client_id as no credential', () => {
    expect(classifyClientAuthentication(requestWith(undefined), { client_id: 'cid' })).toBe('none');
  });

  it('rejects an assertion presented together with a body client_secret', () => {
    expect(() =>
      classifyClientAuthentication(requestWith(undefined), {
        client_id: 'cid',
        client_secret: 's',
        client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER,
        client_assertion: 'a.b.c',
      })
    ).toThrow(InvalidClientError);
  });

  it('rejects an assertion presented together with a Basic header', () => {
    expect(() =>
      classifyClientAuthentication(requestWith(basic), {
        client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER,
        client_assertion: 'a.b.c',
      })
    ).toThrow(InvalidClientError);
  });

  it('rejects a client_assertion with no client_assertion_type', () => {
    expect(() =>
      classifyClientAuthentication(requestWith(undefined), { client_assertion: 'a.b.c' })
    ).toThrow(InvalidClientError);
  });

  it('rejects a client_assertion_type with no client_assertion', () => {
    expect(() =>
      classifyClientAuthentication(requestWith(undefined), {
        client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER,
      })
    ).toThrow(InvalidClientError);
  });
});

describe('authenticateClientRequest', () => {
  function stub(client: OAuthClientLike | null, passwordValid = true) {
    return {
      repositories: {
        oauthClients: { findByClientId: vi.fn().mockResolvedValue(client) },
      },
      passwordHasher: { verifyPassword: vi.fn().mockResolvedValue(passwordValid) },
      redis: { get: vi.fn(), set: vi.fn() },
      jwtUtils: { getIssuer: () => 'https://auth.example.com' },
    } as unknown as FastifyInstance;
  }

  const confidential: OAuthClientLike = {
    id: 'cuid',
    clientId: 'cid',
    clientSecretHash: 'hash',
    enabled: true,
    grantTypes: ['client_credentials'],
    scopes: [],
    audience: null,
    tokenEndpointAuthMethod: 'client_secret_post',
  };

  it('authenticates a confidential client by secret', async () => {
    const fastify = stub(confidential);
    await expect(
      authenticateClientRequest(
        fastify,
        'realm',
        requestWith(undefined),
        { client_id: 'cid', client_secret: 'secret' },
        { allowPublic: false }
      )
    ).resolves.toMatchObject({ clientId: 'cid' });
  });

  it('refuses an operator-suspended PUBLIC client on the client_id-only path (ANT-2026-DR5XI3LV)', async () => {
    const publicClient: OAuthClientLike = {
      ...confidential,
      tokenEndpointAuthMethod: 'none',
      grantTypes: ['authorization_code', 'refresh_token'],
    };
    await expect(
      authenticateClientRequest(
        stub(publicClient),
        'realm',
        requestWith(undefined),
        { client_id: 'cid' },
        { allowPublic: true }
      )
    ).resolves.toMatchObject({ clientId: 'cid' });
    await expect(
      authenticateClientRequest(
        stub({ ...publicClient, suspended: true }),
        'realm',
        requestWith(undefined),
        { client_id: 'cid' },
        { allowPublic: true }
      )
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects a credential-free request on a grant that forbids public clients', async () => {
    const fastify = stub(confidential);
    await expect(
      authenticateClientRequest(
        fastify,
        'realm',
        requestWith(undefined),
        { client_id: 'cid' },
        { allowPublic: false }
      )
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.repositories.oauthClients.findByClientId).not.toHaveBeenCalled();
  });

  it('routes an assertion to the private_key_jwt path and rejects a secret-registered client', async () => {
    const fastify = stub(confidential);
    await expect(
      authenticateClientRequest(
        fastify,
        'realm',
        requestWith(undefined),
        {
          client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER,
          client_assertion: 'not-a-jwt',
        },
        { allowPublic: false }
      )
    ).rejects.toThrow(InvalidClientError);
    // Never falls back to the secret path.
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });

  it('rejects a request mixing a secret and an assertion before any lookup', async () => {
    const fastify = stub(confidential);
    await expect(
      authenticateClientRequest(
        fastify,
        'realm',
        requestWith(undefined),
        {
          client_id: 'cid',
          client_secret: 'secret',
          client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER,
          client_assertion: 'a.b.c',
        },
        { allowPublic: false }
      )
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.repositories.oauthClients.findByClientId).not.toHaveBeenCalled();
  });
});

describe('validateScopes', () => {
  it('returns an empty array when requested scope is missing or blank', () => {
    expect(validateScopes(undefined, ['read'])).toEqual([]);
    expect(validateScopes('', ['read'])).toEqual([]);
    expect(validateScopes('   ', ['read'])).toEqual([]);
  });

  it('returns the requested scopes when all are in the allowlist', () => {
    expect(validateScopes('read write', ['read', 'write', 'delete'])).toEqual(['read', 'write']);
  });

  it('throws InvalidScopeError when any requested scope is outside the allowlist', () => {
    expect(() => validateScopes('read admin', ['read'])).toThrow(InvalidScopeError);
  });

  it('denies every requested scope when the allowlist is empty', () => {
    expect(() => validateScopes('read', [])).toThrow(InvalidScopeError);
  });

  it('collapses runs of whitespace between scopes', () => {
    expect(validateScopes('read    write', ['read', 'write'])).toEqual(['read', 'write']);
  });

  it('grants a repeated scope once', () => {
    // A repeated scope used to be granted as many times as it was sent and
    // checked against the allowlist once per repeat (an n × m scan).
    expect(validateScopes('read read write read', ['read', 'write'])).toEqual(['read', 'write']);
    expect(validateScopes('read read', ['read', 'read'])).toEqual(['read']);
  });

  it('names each scope it refuses once', () => {
    expect(() => validateScopes('read admin admin', ['read'])).toThrow(
      expect.objectContaining({ errorDescription: 'admin not permitted for this client' })
    );
  });

  // ADR-007 §2 (#184): the optional agent context enforces the scope-mode cap
  // through the SAME validateScopes path the token endpoint already uses.
  describe('agent scope-mode cap (ADR-007 §2)', () => {
    it('permits an in-cap agent-mode scope that is also allowlisted', () => {
      expect(
        validateScopes('agent:readonly', ['agent:readonly', 'agent:admin'], {
          isAgent: true,
          maxAgentMode: 'admin',
        })
      ).toEqual(['agent:readonly']);
    });

    it('rejects an agent-mode scope above the cap even if allowlisted', () => {
      expect(() =>
        validateScopes('agent:exec', ['agent:exec'], { isAgent: true, maxAgentMode: 'admin' })
      ).toThrow(InvalidScopeError);
    });

    it('rejects any agent-mode scope for a non-agent client (untrusted is_agent)', () => {
      expect(() =>
        validateScopes('agent:readonly', ['agent:readonly'], {
          isAgent: false,
          maxAgentMode: 'exec',
        })
      ).toThrow(InvalidScopeError);
    });

    it('rejects any agent-mode scope when the cap is null (default-deny)', () => {
      expect(() =>
        validateScopes('agent:readonly', ['agent:readonly'], { isAgent: true, maxAgentMode: null })
      ).toThrow(InvalidScopeError);
    });

    it('leaves ordinary scopes unaffected when an agent context is supplied', () => {
      expect(
        validateScopes('read write', ['read', 'write'], { isAgent: true, maxAgentMode: 'exec' })
      ).toEqual(['read', 'write']);
    });
  });
});

describe('toAgentScopeContext — fail-closed derivation', () => {
  it('reflects a verified agent with a parsed cap', () => {
    expect(toAgentScopeContext({ isAgent: true, maxAgentMode: 'admin' })).toEqual({
      isAgent: true,
      maxAgentMode: 'admin',
    });
  });

  it('treats a missing / null cap as no cap', () => {
    expect(toAgentScopeContext({ isAgent: true, maxAgentMode: null })).toEqual({
      isAgent: true,
      maxAgentMode: null,
    });
    expect(toAgentScopeContext({ isAgent: true })).toEqual({ isAgent: true, maxAgentMode: null });
  });

  it('fails closed for omitted is_agent and unknown cap values', () => {
    expect(toAgentScopeContext({})).toEqual({ isAgent: false, maxAgentMode: null });
    expect(toAgentScopeContext(null)).toEqual({ isAgent: false, maxAgentMode: null });
    expect(toAgentScopeContext({ isAgent: true, maxAgentMode: 'superuser' })).toEqual({
      isAgent: true,
      maxAgentMode: null,
    });
  });
});

describe('enforceAgentScopeCap', () => {
  it('does not throw when every agent-mode scope is within policy', () => {
    expect(() =>
      enforceAgentScopeCap(['agent:readonly', 'read:foo'], { isAgent: true, maxAgentMode: 'admin' })
    ).not.toThrow();
  });

  it('throws InvalidScopeError listing scopes that exceed the cap', () => {
    expect(() =>
      enforceAgentScopeCap(['agent:exec'], { isAgent: true, maxAgentMode: 'readonly' })
    ).toThrow(InvalidScopeError);
  });

  // #184 cap wiring is now live in routes/oauth/token.ts:
  //   - client_credentials: validateScopes(body.scope, client.scopes,
  //     toAgentScopeContext(client))
  //   - token-exchange: enforceAgentScopeCap(grantedScopes,
  //     toAgentScopeContext(client)) after scope narrowing
  // The end-to-end enforcement is covered by token.test.ts ("agent scope-mode
  // cap" suites); the unit behaviour of the helpers stays covered above.
});

describe('resolveAudience', () => {
  const base: OAuthClientLike = {
    id: 'x',
    clientId: 'cid',
    clientSecretHash: '',
    enabled: true,
    grantTypes: [],
    scopes: [],
    audience: null,
  };

  it('falls back to clientId when audience is null', () => {
    expect(resolveAudience(base)).toBe('cid');
  });

  it('falls back to clientId when audience is an empty array', () => {
    expect(resolveAudience({ ...base, audience: [] })).toBe('cid');
  });

  it('collapses a single-item array to a bare string', () => {
    expect(resolveAudience({ ...base, audience: ['https://api.example.com'] })).toBe(
      'https://api.example.com'
    );
  });

  it('returns the array when multiple audiences are configured', () => {
    expect(
      resolveAudience({ ...base, audience: ['https://a.example', 'https://b.example'] })
    ).toEqual(['https://a.example', 'https://b.example']);
  });

  it('falls back to clientId when audience entries are not strings (I-g guard)', () => {
    // Drizzle's $type<string[] | null> hints the shape but raw JSONB can store
    // anything; the helper must defend against malformed rows.
    const malformed = [null as unknown as string, 42 as unknown as string];
    expect(resolveAudience({ ...base, audience: malformed })).toBe('cid');
  });

  it('falls back to clientId when audience exceeds the entry cap', () => {
    const tooMany = Array.from({ length: 25 }, (_, i) => `aud-${i}`);
    expect(resolveAudience({ ...base, audience: tooMany })).toBe('cid');
  });

  it('falls back to clientId when an audience entry is oversized', () => {
    const oversized = ['a'.repeat(257)];
    expect(resolveAudience({ ...base, audience: oversized })).toBe('cid');
  });
});

describe('unlistedReservedAudiences (#509)', () => {
  const ADMIN = 'urn:qauth:aud:admin:v1-rc.0';
  const ACCOUNT = 'urn:qauth:aud:account:v1-rc.0';

  it('returns the reserved audiences the client does not list', () => {
    expect(unlistedReservedAudiences({ audience: null }, ADMIN)).toEqual([ADMIN]);
    expect(unlistedReservedAudiences({ audience: [ADMIN] }, [ADMIN, ACCOUNT])).toEqual([ACCOUNT]);
    expect(
      unlistedReservedAudiences({ audience: [ADMIN] }, ['URN:QAUTH:AUD:admin:v1-rc.0'])
    ).toEqual(['URN:QAUTH:AUD:admin:v1-rc.0']);
  });

  it('returns nothing for listed or ordinary audiences', () => {
    expect(unlistedReservedAudiences({ audience: [ADMIN, ACCOUNT] }, [ADMIN, ACCOUNT])).toEqual([]);
    expect(
      unlistedReservedAudiences({ audience: null }, ['https://api.example.com', 'client-1'])
    ).toEqual([]);
  });

  it('lists nothing from a malformed stored audience', () => {
    expect(unlistedReservedAudiences({ audience: ADMIN as unknown as string[] }, [ADMIN])).toEqual([
      ADMIN,
    ]);
  });
});
