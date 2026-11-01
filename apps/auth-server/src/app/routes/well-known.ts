import { buildTransmitterMetadata } from '@qauth-labs/fastify-plugin-ssf';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { listEnabledExperimental } from '../../config/experimental-features';
import { JWKS_CACHE_CONTROL } from '../constants';
import { cimdPolicyOf } from '../helpers/cimd-policy';
import {
  buildAuthorizationServerMetadata,
  buildOpenIdConfiguration,
  type DiscoveryMetadataInput,
} from '../helpers/discovery';
import { realmIssuer } from '../helpers/realm-url';
import { type RealmRow, requestRealm } from '../helpers/request-realm';
import { SsfNotFoundError } from '../helpers/ssf-errors';
import { realmRunsTransmitter } from '../helpers/ssf-receiver';

/**
 * RFC 8414 §3.1 and OIDC Discovery 1.0 §4 describe these as highly
 * cacheable documents that change rarely. One hour is a common default
 * for the discovery documents.
 */
const DISCOVERY_CACHE_CONTROL = 'public, max-age=3600';

/**
 * Well-known discovery endpoints:
 *
 * - `GET /.well-known/oauth-authorization-server` — RFC 8414 AS metadata.
 * - `GET /.well-known/openid-configuration`       — OIDC Discovery 1.0.
 * - `GET /.well-known/jwks.json`                  — RFC 7517 JWKS: the token
 *   keys only. The SSF transmitter's SET keys are published apart, at
 *   `/ssf/jwks.json` (d-1026-09).
 *
 * - `GET /.well-known/ssf-configuration`          — SSF 1.0 §7 transmitter
 *   metadata, registered only while SSF_TRANSMITTER_ENABLED is on (#410).
 *
 * All are unauthenticated and aggressively cacheable. They MUST NOT
 * be rate-limited as aggressively as auth endpoints: clients hit them
 * during bootstrap and cache responses locally.
 *
 * Each document belongs to the realm the request's host names (ADR-019
 * Decisions 1 and 9, #494) and is built from the realm's row, its published
 * keys and the deployment's settings, so every node that serves it answers
 * the same bytes for the same realm, once its key list is no older than the
 * last key change (the signer's refresh interval). A host that names no realm
 * never reaches these handlers: the realm resolver answers it 421, with no
 * fallback. An endpoint host of a realm gets the realm's documents unchanged,
 * the realm issuer and its URLs included: endpoint hosts are not advertised.
 */
export default async function (fastify: FastifyInstance) {
  // ADR-018 §5 (#477): the experimental items that are on, read once from the
  // configuration, which does not change while the server runs. Each adds the
  // discovery members its registry entry lists; an item that is off adds none.
  const experimentalItems = listEnabledExperimental();

  /**
   * The input of a realm's discovery documents (#494). The realm decides the
   * issuer, on which every endpoint URL is built (#490), the ID-token
   * signing algorithms, from its published keys (#491), and whether it
   * accepts CIMD clients, from its policies (#534). The rest are deployment
   * switches, the same for every realm: `ID_JAG_ENABLED`, `DPOP_ENABLED` and
   * the experimental items.
   */
  const buildInput = async (realm: RealmRow): Promise<DiscoveryMetadataInput> => ({
    // ADR-019 Decision 1 (#490): the realm's issuer, from its row.
    issuer: realmIssuer(realm),
    // CIMD (MCP 2025-11-25): advertise on BOTH AS metadata and OIDC config,
    // while the realm's policy accepts a URL `client_id` (#534), as its
    // client resolution does: read off the resolver's row, so a change shows
    // here within the resolver's cache time, and a client that cached the
    // document within its own.
    clientIdMetadataDocumentSupported: cimdPolicyOf(fastify, realm).enabled,
    // ADR-011 §4: gates the jwt-bearer grant type and the ID-JAG grant profile.
    // Both are advertised only while the flag is on AND the issuer allowlist is
    // not empty. With an empty list the token endpoint rejects every assertion,
    // so advertising the grant would be a false capability claim.
    idJagEnabled: env.ID_JAG_ENABLED && env.ID_JAG_TRUSTED_ISSUERS.length > 0,
    // #309: advertise exactly the ID-token signing algorithms the realm has
    // active keys for — `['RS256','EdDSA']` when it publishes an active RS256
    // key, else `['EdDSA']` (#491). Read from the realm's published keys, as
    // its JWKS is, never from the process.
    idTokenSigningAlgValuesSupported:
      await fastify.jwtUtils.getIdTokenSigningAlgValuesSupported(realm),
    // RFC 9449 §5.1 (#480): the DPoP proof algorithms, only while DPOP_ENABLED
    // is on (`fastify.dpop` is null otherwise).
    ...(fastify.dpop ? { dpopSigningAlgValuesSupported: fastify.dpop.algorithms } : {}),
    experimentalItems,
  });

  fastify.get(
    '/.well-known/oauth-authorization-server',
    {
      schema: {
        description:
          'OAuth 2.0 Authorization Server Metadata (RFC 8414). Unauthenticated, cacheable.',
        tags: ['Discovery'],
        'x-qauth-stability': 'stable',
      },
      config: { surface: 'meta' },
    },
    async (request, reply) => {
      // Built before the cache header is set, so a failure (a stored policy
      // the schema refuses, #534, or the realm's keys) answers an error no
      // cache keeps for an hour.
      const document = buildAuthorizationServerMetadata(await buildInput(requestRealm(request)));
      reply
        .header('Cache-Control', DISCOVERY_CACHE_CONTROL)
        .header('Content-Type', 'application/json; charset=utf-8');
      return reply.send(document);
    }
  );

  fastify.get(
    '/.well-known/openid-configuration',
    {
      schema: {
        description:
          'OpenID Connect Discovery 1.0 document. Superset of RFC 8414 AS metadata with OIDC-specific fields. Unauthenticated, cacheable.',
        tags: ['Discovery'],
        'x-qauth-stability': 'stable',
      },
      config: { surface: 'meta' },
    },
    async (request, reply) => {
      // As above: the cache header only on a document that was built.
      const document = buildOpenIdConfiguration(await buildInput(requestRealm(request)));
      reply
        .header('Cache-Control', DISCOVERY_CACHE_CONTROL)
        .header('Content-Type', 'application/json; charset=utf-8');
      return reply.send(document);
    }
  );

  fastify.get(
    '/.well-known/jwks.json',
    {
      schema: {
        description:
          'JSON Web Key Set (RFC 7517) of the realm the request host names: its published token signing keys (EdDSA, RS256 and, with hybrid signing, ML-DSA-65), each under its own `kid`. Used by clients and resource servers to verify JWT signatures.',
        tags: ['Discovery'],
        'x-qauth-stability': 'stable',
      },
      config: { surface: 'meta' },
    },
    async (request, reply) => {
      // Public keys can be served by any cache; see RFC 7517 §8.5.1.
      // `application/jwk-set+json` is the registered media type.
      //
      // The published keys of the realm the request's host names (ADR-019
      // Decisions 1 and 9, #491, #494), read from `realm_public_keys`: its
      // active keys, a `next` key from its publication, before it signs, and
      // a retired key until its retention ends, each under its own `kid`. The
      // retention is the key store's to set (#492); this route serves what it
      // marks as published. They are its Ed25519 key (`kty: "OKP"`), its
      // RS256 key when it has one (#309) and, when hybrid signing is enabled,
      // its ML-DSA-65 key as `kty: "AKP"` (with a base64url `pub` member,
      // #246, ADR-005). A classical verifier that does not understand
      // `AKP` simply ignores that entry — mixed-key clients pick the key they
      // need by `kid` and `kty`.
      reply
        .header('Cache-Control', JWKS_CACHE_CONTROL)
        .header('Content-Type', 'application/jwk-set+json; charset=utf-8');
      const jwks = await fastify.jwtUtils.getJwks(requestRealm(request));
      return reply.send(jwks);
    }
  );

  // Shared Signals Framework transmitter metadata (SSF 1.0 §7, #410). No
  // route at all while SSF_TRANSMITTER_ENABLED is off; 404 for a realm whose
  // own switch is off. Every URL comes from the realm's issuer, which is the
  // `iss` of the SETs the realm's signer issues (§7.1).
  if (fastify.ssf) {
    fastify.get(
      '/.well-known/ssf-configuration',
      {
        schema: {
          description:
            'Shared Signals Framework transmitter metadata (SSF 1.0 §7): the stream management endpoints, push delivery, and the transmitter’s own JWKS (`/ssf/jwks.json`), which verifies the realm’s Security Event Tokens. 404 for a realm that does not run the transmitter.',
          tags: ['Discovery', 'Shared Signals'],
          'x-qauth-stability': 'experimental',
          // SSF 1.0 §7 defines no error body: the 404 is the `not_found`
          // problem document (#513).
          'x-qauth-errors': [404],
        },
        config: { surface: 'meta' },
      },
      async (request, reply) => {
        if (!realmRunsTransmitter(request)) throw new SsfNotFoundError();
        reply
          .header('Cache-Control', DISCOVERY_CACHE_CONTROL)
          .header('Content-Type', 'application/json; charset=utf-8');
        // The realm's issuer from its row (ADR-019 Decision 1, #490), as the
        // other discovery documents build their URLs.
        return reply.send(buildTransmitterMetadata(realmIssuer(requestRealm(request))));
      }
    );
  }
}
