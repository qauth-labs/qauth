/**
 * Runnable example — a minimal MCP-style resource server protected by
 * `@qauth-labs/mcp-guard` against a self-hosted QAuth authorization server.
 *
 * This doubles as the T1 quickstart (ADR-007): it is the resource-server half
 * of the Claude Code → QAuth → MCP handshake. Point Claude Code (or any MCP
 * client) at this server's URL; on a 401 the client reads the RFC 9728
 * Protected Resource Metadata, discovers the QAuth AS, runs
 * authorization_code + PKCE against it, and retries with a bearer token that
 * `mcp-guard` validates here.
 *
 * Run (from the lib directory):
 *   QAUTH_ISSUER=https://localhost:3000 \
 *   MCP_RESOURCE=http://localhost:8088 \
 *   npx tsx examples/memory-mcp/server.ts
 *
 * Then:
 *   # discovery — no auth required:
 *   curl -s http://localhost:8088/.well-known/oauth-protected-resource | jq
 *
 *   # protected call without a token → 401 + WWW-Authenticate challenge:
 *   curl -i http://localhost:8088/mcp/memory
 *
 *   # with a QAuth-issued, audience-bound token:
 *   curl -s http://localhost:8088/mcp/memory \
 *     -H "Authorization: Bearer $ACCESS_TOKEN" | jq
 */

import Fastify from 'fastify';

import { mcpGuardPlugin } from '../../src';

const ISSUER = process.env['QAUTH_ISSUER'] ?? 'http://localhost:3000';
const RESOURCE = process.env['MCP_RESOURCE'] ?? 'http://localhost:8088';
const PORT = Number(process.env['PORT'] ?? 8088);

async function main(): Promise<void> {
  const app = Fastify({ logger: true });

  // Register the guard. In `jwt` mode (default) it verifies tokens locally
  // against the QAuth JWKS — no per-request call to the AS. Switch to
  // `introspection` mode (with `introspectionClient` credentials) if you need
  // near-real-time revocation.
  await app.register(mcpGuardPlugin, {
    resource: RESOURCE,
    authorizationServer: ISSUER,
    // Any read of the memory store needs `mcp:read`; writes additionally
    // need `mcp:write` (enforced per-route below via step-up).
    requiredScopes: ['mcp:read'],
    validationMode: 'jwt',
    // jwksUri defaults to `${ISSUER}/.well-known/jwks.json` (QAuth contract).
  });

  // --- A trivial in-memory "MCP" resource ------------------------------------
  const store = new Map<string, string>();

  // Read: requires a valid, audience-bound token carrying `mcp:read`.
  app.get('/mcp/memory', { preHandler: app.requireBearer }, async (request) => {
    return {
      subject: request.tokenClaims?.sub,
      client: request.tokenClaims?.clientId,
      items: Object.fromEntries(store),
    };
  });

  // Write: step-up — the same token must additionally carry `mcp:write`.
  // A token with only `mcp:read` gets a 403 `insufficient_scope` challenge
  // advertising `scope="mcp:read mcp:write"`, prompting incremental consent.
  app.put<{ Params: { key: string }; Body: { value: string } }>(
    '/mcp/memory/:key',
    { preHandler: app.requireScopes('mcp:write') },
    async (request) => {
      store.set(request.params.key, request.body.value);
      return { ok: true, key: request.params.key };
    }
  );

  await app.listen({ port: PORT, host: '0.0.0.0' });
  app.log.info(
    { resource: RESOURCE, authorizationServer: ISSUER },
    'memory-mcp resource server listening; PRM at %s',
    app.mcpGuard.getMetadataUrl()
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
