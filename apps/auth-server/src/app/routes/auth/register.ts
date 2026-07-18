import {
  buildPasswordCredentialData,
  PASSWORD_PROVIDER_TYPE,
} from '@qauth-labs/fastify-plugin-federation';
import { BadRequestError, WeakPasswordError } from '@qauth-labs/shared-errors';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { logAuthEvent } from '../../helpers/auth-events';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { type RegisterRequest, registerResponseSchema, registerSchema } from '../../schemas/auth';

/**
 * Registration route
 * Types are automatically inferred from registerSchema and registerResponseSchema
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/register',
    {
      schema: {
        description:
          'Register a new user account. Creates user, sends verification email, and returns user data. Password must meet strength requirements.',
        tags: ['Auth'],
        body: registerSchema,
        response: {
          201: registerResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.REGISTRATION_RATE_LIMIT,
          timeWindow: env.REGISTRATION_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const { email, password, realmId } = request.body as RegisterRequest;

      // Email is already validated by Zod schema, just normalize it
      const normalizedEmail = normalizeEmail(email);

      // Validate password strength using injected validator
      const passwordStrength = fastify.passwordValidator.validatePasswordStrength(password);
      if (!passwordStrength.valid) {
        throw new WeakPasswordError(
          'Password does not meet strength requirements',
          passwordStrength.feedback
        );
      }

      // Get or create default realm
      let realm;
      if (realmId) {
        realm = await fastify.repositories.realms.findById(realmId);
        if (!realm) {
          throw new BadRequestError(`Invalid realmId: ${realmId}`);
        }
        if (!realm.enabled) {
          throw new BadRequestError(`Realm ${realmId} is disabled`);
        }
      } else {
        realm = await getOrCreateDefaultRealm(fastify);
      }

      // Hash password using injected hasher
      const passwordHash = await fastify.passwordHasher.hashPassword(password);

      // Provider-normalized identity + attributes (ADR-003) — pure, so it
      // runs before the transaction.
      const provider = fastify.providerRegistry.resolve(PASSWORD_PROVIDER_TYPE);
      const identity = await provider.verify({
        email: normalizedEmail,
        passwordHash,
        emailVerified: false,
      });
      const attributes = provider.extractAttributes(identity);

      // Generate verification token pair (token + tokenHash)
      const { token, tokenHash } = fastify.emailVerificationTokenUtils.generateVerificationToken();

      // Calculate expiration time
      const expiresAt = Date.now() + env.EMAIL_VERIFICATION_TOKEN_EXPIRY * 1000;

      // One transaction for the whole identity write set (#228, ADR-002): a
      // users row without its credential row would be unloginable AND block
      // re-registration, so the writes commit together.
      //
      // Ordering: users first because user_credentials.user_id FKs users.id.
      // Since #230 the credentials unique index (realm_id, provider_type,
      // external_sub) is the SOLE duplicate-registration guard — a duplicate
      // surfaces from the credential insert and rolls the anchor back.
      const user = await fastify.db.transaction(async (tx) => {
        // Pure identity anchor (#230): no email or password fields exist on
        // users; credential data lives only in user_credentials.
        const created = await fastify.repositories.users.create(
          {
            realmId: realm.id,
          },
          tx
        );

        const credential = await fastify.repositories.userCredentials.create(
          {
            userId: created.id,
            realmId: realm.id,
            providerType: PASSWORD_PROVIDER_TYPE,
            externalSub: identity.externalSub,
            credentialData: buildPasswordCredentialData(passwordHash, false),
          },
          tx
        );

        await fastify.repositories.userAttributes.upsertMany(
          created.id,
          attributes.map((attr) => ({
            source: attr.source,
            attrKey: attr.attrKey,
            attrValue: attr.attrValue,
            verified: attr.verified,
            expiresAt: attr.expiresAt ? attr.expiresAt.getTime() : null,
          })),
          tx
        );

        // Store tokenHash in database (NOT plain token). The verification
        // targets the password credential (ADR-002); credential_id is the
        // token's only identity link since #230.
        await fastify.repositories.emailVerificationTokens.create(
          {
            credentialId: credential.id,
            tokenHash,
            expiresAt,
            used: false,
          },
          tx
        );

        return created;
      });

      // Send verification email (don't fail registration if this fails)
      try {
        await fastify.emailService.sendVerificationEmail(normalizedEmail, token);
        fastify.log.info({ userId: user.id, email: normalizedEmail }, 'Verification email sent');
      } catch (error) {
        fastify.log.error(
          { err: error, userId: user.id, email: normalizedEmail },
          'Failed to send verification email during registration'
        );
        // Don't throw - registration succeeded, user can request resend
      }

      // Structured log of the successful registration (#124). Email is included
      // on the success path; no password or token is logged.
      logAuthEvent(request, 'user.register.success', true, {
        userId: user.id,
        email: normalizedEmail,
      });

      // Response email is the request-derived normalized address; a fresh
      // registration is always unverified (#261: the vestigial users column
      // this used to surface is dropped — the literal keeps the wire byte-
      // identical).
      return reply.code(201).send({
        id: user.id,
        email: normalizedEmail,
        emailVerified: false,
        realmId: user.realmId,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      });
    }
  );
}
