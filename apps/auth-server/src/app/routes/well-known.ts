import type { FastifyInstance } from 'fastify';

import { buildAuthorizationServerMetadata, buildOpenIdConfiguration } from '../helpers/discovery';

/**
 * RFC 8414 §3.1 and OIDC Discovery 1.0 §4 describe these as highly
 * cacheable documents that change rarely. One hour is a common default
 * used by major IdPs (Google, Okta) and is short enough that clients pick
 * up JWKS rotations without manual intervention.
 */
const DISCOVERY_CACHE_CONTROL = 'public, max-age=3600';

/**
 * Well-known discovery endpoints:
 *
 * - `GET /.well-known/oauth-authorization-server` — RFC 8414 AS metadata.
 * - `GET /.well-known/openid-configuration`       — OIDC Discovery 1.0.
 * - `GET /.well-known/jwks.json`                  — RFC 7517 JWKS.
 *
 * All three are unauthenticated and aggressively cacheable. They MUST NOT
 * be rate-limited as aggressively as auth endpoints: clients hit them
 * during bootstrap and cache responses locally.
 */
export default async function (fastify: FastifyInstance) {
  const buildInput = () => ({ issuer: fastify.jwtUtils.getIssuer() });

  fastify.get(
    '/.well-known/oauth-authorization-server',
    {
      schema: {
        description:
          'OAuth 2.0 Authorization Server Metadata (RFC 8414). Unauthenticated, cacheable.',
        tags: ['Discovery'],
      },
    },
    async (_request, reply) => {
      reply
        .header('Cache-Control', DISCOVERY_CACHE_CONTROL)
        .header('Content-Type', 'application/json; charset=utf-8');
      return reply.send(buildAuthorizationServerMetadata(buildInput()));
    }
  );

  fastify.get(
    '/.well-known/openid-configuration',
    {
      schema: {
        description:
          'OpenID Connect Discovery 1.0 document. Superset of RFC 8414 AS metadata with OIDC-specific fields. Unauthenticated, cacheable.',
        tags: ['Discovery'],
      },
    },
    async (_request, reply) => {
      reply
        .header('Cache-Control', DISCOVERY_CACHE_CONTROL)
        .header('Content-Type', 'application/json; charset=utf-8');
      return reply.send(buildOpenIdConfiguration(buildInput()));
    }
  );

  fastify.get(
    '/.well-known/jwks.json',
    {
      schema: {
        description:
          'JSON Web Key Set (RFC 7517) containing the active EdDSA public signing key(s). Used by clients and resource servers to verify JWT signatures.',
        tags: ['Discovery'],
      },
    },
    async (_request, reply) => {
      // Public keys can be served by any cache; see RFC 7517 §8.5.1.
      // `application/jwk-set+json` is the registered media type.
      reply
        .header('Cache-Control', DISCOVERY_CACHE_CONTROL)
        .header('Content-Type', 'application/jwk-set+json; charset=utf-8');
      const jwks = await fastify.jwtUtils.getJwks();
      return reply.send(jwks);
    }
  );
}
