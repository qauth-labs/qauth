import { randomBytes, randomUUID } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { validateAndNormalize } from '../../helpers/dynamic-client-registration';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import {
  type DynamicClientRegistrationRequest,
  dynamicClientRegistrationRequestSchema,
  type DynamicClientRegistrationResponse,
  dynamicClientRegistrationResponseSchema,
} from '../../schemas/oauth';

/**
 * POST /oauth/register
 *
 * OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591).
 *
 * Policy: **open** registration. There is no `initial_access_token` gate.
 * Defense-in-depth for this project lives at the consent screen (issue
 * #150) — a dynamically registered client cannot harm a user without a
 * consent-grant on the /oauth/authorize flow. That means this endpoint
 * MUST remain tightly scope-capped and rate-limited, which is what the
 * helper + route config below enforce.
 *
 * Response shape follows RFC 7591 §3.2.1. `client_secret` is omitted
 * entirely for public clients (`token_endpoint_auth_method=none`).
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/register',
    {
      schema: {
        description:
          "OAuth 2.0 Dynamic Client Registration (RFC 7591). Open-mode — no initial_access_token required. Scope requests are capped to the realm's dynamic_registration_allowed_scopes list.",
        tags: ['OAuth', 'Registration'],
        body: dynamicClientRegistrationRequestSchema,
        response: {
          201: dynamicClientRegistrationResponseSchema,
        },
      },
      config: {
        // IP-scoped rate limit, at least as strict as /oauth/token.
        // Registration is append-only and expensive (argon2id hash on
        // confidential clients), so a burst-proof cap is mandatory.
        rateLimit: {
          max: env.REGISTER_CLIENT_RATE_LIMIT,
          timeWindow: env.REGISTER_CLIENT_RATE_WINDOW * 1000,
          keyGenerator: (req) => req.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const body = request.body as DynamicClientRegistrationRequest;

      const realm = await getOrCreateDefaultRealm(fastify);

      // Seed realm's allowlist on first use. We *only* do this when the
      // realm has an empty list — never overwrite an operator's choice.
      // Defaults are intentionally tight (OIDC core scopes).
      let allowedScopes = realm.dynamicRegistrationAllowedScopes ?? [];
      if (allowedScopes.length === 0 && env.DEFAULT_DYNAMIC_REGISTRATION_SCOPES.length > 0) {
        allowedScopes = [...env.DEFAULT_DYNAMIC_REGISTRATION_SCOPES];
        try {
          await fastify.repositories.realms.update(realm.id, {
            dynamicRegistrationAllowedScopes: allowedScopes,
          });
        } catch (err) {
          // Best-effort: if the update races another request, we still have
          // the allowedScopes list in memory for this request.
          fastify.log.warn(
            { err, realmId: realm.id },
            'Failed to persist default dynamic_registration_allowed_scopes'
          );
        }
      }

      // Validate + normalize against realm policy. Throws BadRequestError
      // with RFC 7591 error codes embedded in the message on policy
      // violations; the global error handler maps to HTTP 400.
      const normalized = validateAndNormalize(body, allowedScopes);

      // Generate client_id (UUIDv4 — opaque, guessable-resistant, URL-safe
      // without encoding). We keep it simple rather than inventing a new
      // format — downstream auth code already handles UUID client IDs.
      const clientId = randomUUID();

      // Confidential clients get a 32-byte secret, hashed with argon2id
      // before persistence. Plaintext is returned exactly once in the
      // response body and never logged.
      let plaintextSecret: string | undefined;
      let clientSecretHash: string;
      if (normalized.isPublic) {
        // Public client: no usable secret. DB column is NOT NULL, so we
        // store a non-verifiable sentinel (a random hash of random bytes)
        // so any accidental client_secret_post attempt fails cleanly.
        // Length/format matches a real argon2id hash to avoid leaking
        // client type via length-oracle.
        clientSecretHash = await fastify.passwordHasher.hashPassword(
          randomBytes(32).toString('hex')
        );
      } else {
        plaintextSecret = randomBytes(32).toString('hex');
        clientSecretHash = await fastify.passwordHasher.hashPassword(plaintextSecret);
      }

      const clientName = normalized.clientName ?? `dcr-${clientId.slice(0, 8)}`;

      const created = await fastify.repositories.oauthClients.create({
        realmId: realm.id,
        clientId,
        clientSecretHash,
        name: clientName,
        description: normalized.softwareId
          ? `Dynamically registered (${normalized.softwareId})`
          : 'Dynamically registered client',
        redirectUris: normalized.redirectUris,
        scopes: normalized.scopes,
        grantTypes: normalized.grantTypes,
        responseTypes: normalized.responseTypes,
        tokenEndpointAuthMethod: normalized.tokenEndpointAuthMethod,
        // Public clients MUST use PKCE (OAuth 2.1 §4.1.3 / RFC 9700).
        // Confidential clients SHOULD also use PKCE with authorization_code;
        // we keep the project-wide default of requirePkce=true.
        requirePkce: true,
        enabled: true,
        developerId: null,
        // Stamp the dyn-reg timestamp so the consent screen (issue #150)
        // can surface the "Newly registered" phishing-defense badge
        // within DYNAMIC_CLIENT_BADGE_DAYS of registration.
        dynamicRegisteredAt: Date.now(),
        metadata: {
          registrationType: 'dynamic',
          ...(normalized.softwareId ? { softwareId: normalized.softwareId } : {}),
          ...(normalized.softwareVersion ? { softwareVersion: normalized.softwareVersion } : {}),
          ...(normalized.clientUri ? { clientUri: normalized.clientUri } : {}),
          ...(normalized.logoUri ? { logoUri: normalized.logoUri } : {}),
          ...(normalized.tosUri ? { tosUri: normalized.tosUri } : {}),
          ...(normalized.policyUri ? { policyUri: normalized.policyUri } : {}),
          ...(normalized.contacts ? { contacts: normalized.contacts } : {}),
        },
      });

      await fastify.repositories.auditLogs.create({
        userId: null,
        oauthClientId: created.id,
        event: 'oauth.client.registered',
        eventType: 'client',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: {
          registrationType: 'dynamic',
          clientId,
          isPublic: normalized.isPublic,
          grantTypes: normalized.grantTypes,
          scopes: normalized.scopes,
        },
      });

      const issuedAtSeconds = Math.floor(created.createdAt / 1000);

      const response: DynamicClientRegistrationResponse = {
        client_id: clientId,
        client_id_issued_at: issuedAtSeconds,
        // RFC 7591: omit `client_secret` entirely for public clients.
        ...(plaintextSecret
          ? {
              client_secret: plaintextSecret,
              // 0 = never expires, per RFC 7591 §3.2.1.
              client_secret_expires_at: 0,
            }
          : {}),
        client_name: clientName,
        redirect_uris: normalized.redirectUris,
        grant_types: normalized.grantTypes,
        response_types: normalized.responseTypes,
        token_endpoint_auth_method: normalized.tokenEndpointAuthMethod,
        ...(normalized.scopeString ? { scope: normalized.scopeString } : {}),
        ...(normalized.clientUri ? { client_uri: normalized.clientUri } : {}),
        ...(normalized.logoUri ? { logo_uri: normalized.logoUri } : {}),
        ...(normalized.tosUri ? { tos_uri: normalized.tosUri } : {}),
        ...(normalized.policyUri ? { policy_uri: normalized.policyUri } : {}),
        ...(normalized.contacts ? { contacts: normalized.contacts } : {}),
        ...(normalized.softwareId ? { software_id: normalized.softwareId } : {}),
        ...(normalized.softwareVersion ? { software_version: normalized.softwareVersion } : {}),
      };

      // RFC 7591 §3.2.1: response MUST NOT be cached (contains secret).
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return reply.code(201).send(response);
    }
  );
}
