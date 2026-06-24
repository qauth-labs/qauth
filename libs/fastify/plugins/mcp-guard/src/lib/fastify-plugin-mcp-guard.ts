/**
 * Fastify adapter for `mcp-guard`.
 *
 * Registering this plugin:
 *
 * 1. serves the RFC 9728 Protected Resource Metadata document at the
 *    resource's well-known path (and, for a path-bearing resource, also at the
 *    bare `/.well-known/oauth-protected-resource` for discovery convenience);
 * 2. decorates the instance with `mcpGuard` (the core), a `requireBearer`
 *    preHandler, and a `requireScopes(...)` preHandler factory for step-up;
 * 3. converts `McpGuardError`s thrown anywhere in the encapsulation context
 *    into RFC 6750 §3.1 responses with the correct `WWW-Authenticate` header.
 *
 * Because the guard is exposed to parent/sibling contexts, the plugin is
 * wrapped with `fastify-plugin`.
 */

import type {
  FastifyInstance,
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  preHandlerHookHandler,
} from 'fastify';
import fp from 'fastify-plugin';

import type { McpGuardConfig, ValidatedToken } from '../types';
import { McpGuard } from './core';
import { InsufficientScopeError, McpGuardError, MissingTokenError } from './errors';
import { PRM_WELL_KNOWN_PREFIX } from './metadata';

declare module 'fastify' {
  interface FastifyInstance {
    /** The framework-agnostic guard core. */
    mcpGuard: McpGuard;
    /**
     * preHandler that requires a valid, audience-bound bearer carrying the
     * guard's default `requiredScopes`. On success, `request.tokenClaims` is
     * populated. Use as a route `preHandler`.
     */
    requireBearer: preHandlerHookHandler;
    /**
     * Build a preHandler that additionally requires the given scopes — the
     * step-up surface for privileged operations (MCP 2025-11-25 incremental
     * consent). Failures emit a 403 `insufficient_scope` challenge.
     */
    requireScopes: (...scopes: string[]) => preHandlerHookHandler;
  }

  interface FastifyRequest {
    /** Claims of the validated bearer, set by `requireBearer`/`requireScopes`. */
    tokenClaims?: ValidatedToken;
  }
}

/**
 * Configuration for the Fastify plugin. Extends the core config with route
 * options.
 */
export interface McpGuardPluginOptions extends McpGuardConfig {
  /**
   * `Cache-Control` for the PRM document. RFC 9728 documents are highly
   * cacheable. Defaults to `public, max-age=3600`.
   */
  metadataCacheControl?: string;
}

const PLUGIN_NAME = '@qauth-labs/mcp-guard';

/**
 * Send the RFC 6750 §3.1 response for a guard error, including the
 * `WWW-Authenticate` challenge with the `resource_metadata` pointer.
 */
function sendChallenge(guard: McpGuard, reply: FastifyReply, error: McpGuardError): FastifyReply {
  const body: Record<string, unknown> = { error: error.bearerError ?? 'invalid_request' };
  if (error instanceof InsufficientScopeError) {
    body['error_description'] = error.message;
    body['scope'] = error.requiredScopes.join(' ');
  } else if (error.bearerError === 'invalid_token' && 'reason' in error) {
    body['error_description'] = (error as { reason: string }).reason;
  }
  return reply
    .code(error.statusCode)
    .header('WWW-Authenticate', guard.challengeHeader(error))
    .send(error instanceof MissingTokenError ? {} : body);
}

const plugin: FastifyPluginAsync<McpGuardPluginOptions> = async (
  fastify: FastifyInstance,
  options: McpGuardPluginOptions
) => {
  const guard = new McpGuard(options);
  const cacheControl = options.metadataCacheControl ?? 'public, max-age=3600';

  fastify.decorate('mcpGuard', guard);

  // --- RFC 9728 Protected Resource Metadata ---------------------------------
  const metadataHandler = async (_request: FastifyRequest, reply: FastifyReply) => {
    reply
      .header('Cache-Control', cacheControl)
      .header('Content-Type', 'application/json; charset=utf-8');
    return reply.send(guard.getProtectedResourceMetadata());
  };

  const metadataPath = guard.getMetadataPath();
  fastify.get(metadataPath, metadataHandler);
  // For a path-bearing resource the canonical document lives at a nested
  // well-known path; also expose the bare prefix so a client that probes the
  // origin root can still discover the AS.
  if (metadataPath !== PRM_WELL_KNOWN_PREFIX) {
    fastify.get(PRM_WELL_KNOWN_PREFIX, metadataHandler);
  }

  // --- Guard preHandlers ----------------------------------------------------
  // The preHandlers reply with the Bearer challenge directly (returning the
  // reply halts the lifecycle) rather than throwing, so the plugin is fully
  // self-contained and never has to take over the host app's error handler.
  // `McpGuardError`s that still escape into the host's error path (e.g. thrown
  // deep inside a route handler) can be mapped with the exported
  // `mcpGuardErrorHandler` / `sendBearerChallenge` helpers.
  const requireBearer: preHandlerHookHandler = async (request, reply) => {
    try {
      request.tokenClaims = await guard.authenticate(request.headers.authorization);
    } catch (error) {
      if (error instanceof McpGuardError) {
        return sendChallenge(guard, reply, error);
      }
      throw error;
    }
  };
  fastify.decorate('requireBearer', requireBearer);

  const requireScopes = (...scopes: string[]): preHandlerHookHandler => {
    return async (request, reply) => {
      try {
        // Re-use already-validated claims when an earlier preHandler ran, so we
        // do not re-verify the token twice in one request.
        if (request.tokenClaims) {
          guard.assertScopes(request.tokenClaims, scopes);
          return;
        }
        request.tokenClaims = await guard.authenticate(request.headers.authorization, scopes);
      } catch (error) {
        if (error instanceof McpGuardError) {
          return sendChallenge(guard, reply, error);
        }
        throw error;
      }
    };
  };
  fastify.decorate('requireScopes', requireScopes);

  fastify.log.debug('mcp-guard plugin registered (resource=%s)', guard.resource);
};

/**
 * Reply to `reply` with the RFC 6750 §3.1 Bearer challenge for `error`, using
 * `guard`'s `resource_metadata` pointer. Exposed so host apps that throw
 * `McpGuardError` from their own handlers can wire it into their error handler:
 *
 * @example
 * ```ts
 * fastify.setErrorHandler((err, req, reply) => {
 *   if (err instanceof McpGuardError) {
 *     return sendBearerChallenge(fastify.mcpGuard, reply, err);
 *   }
 *   // ...fall through to the app's own handling
 * });
 * ```
 */
export function sendBearerChallenge(
  guard: McpGuard,
  reply: FastifyReply,
  error: McpGuardError
): FastifyReply {
  return sendChallenge(guard, reply, error);
}

/**
 * `@qauth-labs/mcp-guard` Fastify plugin. Wrapped with `fastify-plugin` so the
 * `mcpGuard` decorator and the `requireBearer` / `requireScopes` preHandlers
 * are visible to the parent app and sibling plugins.
 */
export const mcpGuardPlugin = fp(plugin, {
  name: PLUGIN_NAME,
  fastify: '5.x',
});

export default mcpGuardPlugin;
