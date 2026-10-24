import {
  buildPasswordCredentialData,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
} from '@qauth-labs/fastify-plugin-federation';
import {
  BadRequestError,
  UniqueConstraintError,
  WeakPasswordError,
} from '@qauth-labs/shared-errors';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS, REDIS_KEYS, SUCCESS_MESSAGES } from '../../constants';
import { hashEmail, logAuthEvent } from '../../helpers/auth-events';
import { createBackgroundTasks } from '../../helpers/background-tasks';
import { clientAddressKey } from '../../helpers/client-address';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { type RegisterRequest, registerResponseSchema, registerSchema } from '../../schemas/auth';

/**
 * Raised inside the registration transaction when the credential insert finds
 * the address already registered, so the transaction rolls back and the
 * handler can tell this outcome from a real failure.
 *
 * It replaces the repository's `UniqueConstraintError` instead of wrapping it:
 * that error's cause chain carries the insert's parameters, the new password
 * hash among them, so it is neither logged nor kept.
 */
class AddressAlreadyRegistered extends Error {
  constructor() {
    super('address already registered');
    this.name = 'AddressAlreadyRegistered';
  }
}

/**
 * Claim one mail to `address` against the per-address caps that
 * `POST /auth/resend-verification` enforces: at most
 * `RESEND_VERIFICATION_EMAIL_LIMIT` per `RESEND_VERIFICATION_EMAIL_WINDOW`,
 * and none within `RESEND_VERIFICATION_MIN_INTERVAL` of the last. Same Redis
 * keys, so registrations and resends share one allowance per address.
 *
 * Claimed for EVERY registration, before the outcome is known. If only the
 * branch for an existing account claimed it, a resend right after a
 * registration would answer 429 for a registered address and 200 for a free
 * one.
 *
 * @returns whether a mail may go to the address now
 */
async function claimAddressMailSlot(fastify: FastifyInstance, address: string): Promise<boolean> {
  const countKey = REDIS_KEYS.RESEND_RATE_LIMIT(address);
  const count = await fastify.redis.incr(countKey);
  if (count === 1) {
    await fastify.redis.expire(countKey, env.RESEND_VERIFICATION_EMAIL_WINDOW);
  }
  if (count > env.RESEND_VERIFICATION_EMAIL_LIMIT) {
    return false;
  }
  const claimed = await fastify.redis.set(
    REDIS_KEYS.LAST_EMAIL_SENT(address),
    Date.now().toString(),
    'EX',
    env.RESEND_VERIFICATION_MIN_INTERVAL,
    'NX'
  );
  return claimed === 'OK';
}

/**
 * Mail the owner of an address that someone just tried to register again.
 * Runs off the request path, so none of its lookups, writes or deliveries
 * show in the response.
 *
 * - Verified account: the "you already have an account" notice. It has no
 *   link and no token.
 * - Unverified account: its verification link again, with a fresh token, as
 *   `POST /auth/resend-verification` would send it. A notice saying "sign in"
 *   would be a dead end here: an unverified account cannot sign in while
 *   `REQUIRE_VERIFIED_ACCOUNT` is on, and the usual reason to register twice is
 *   a first mail that never arrived. It gives nobody a new power:
 *   `/auth/verify` needs the account's password as well as the token, so a
 *   mailbox owner cannot verify an account someone else registered with their
 *   address, and resend-verification already sends this mail to anyone who
 *   asks.
 * - Disabled account, or unreadable credential data: no mail, as on
 *   resend-verification.
 */
async function mailExistingAccount(
  fastify: FastifyInstance,
  params: { realmId: string; address: string; token: string; tokenHash: string; expiresAt: number }
): Promise<void> {
  const credential = await fastify.repositories.userCredentials.findByRealmProviderSub(
    params.realmId,
    PASSWORD_PROVIDER_TYPE,
    params.address
  );
  if (!credential) {
    return;
  }
  const parsed = passwordCredentialDataSchema.safeParse(credential.credentialData);
  if (!parsed.success) {
    fastify.log.error(
      { credentialId: credential.id },
      'malformed credential_data on password credential'
    );
    return;
  }
  const user = await fastify.repositories.users.findById(credential.userId);
  if (!user?.enabled) {
    return;
  }

  if (parsed.data.email_verified) {
    await fastify.emailService.sendAccountExistsEmail(credential.externalSub);
    return;
  }

  if (env.EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND) {
    await fastify.repositories.emailVerificationTokens.invalidateCredentialTokens(credential.id);
  }
  await fastify.repositories.emailVerificationTokens.create({
    credentialId: credential.id,
    tokenHash: params.tokenHash,
    expiresAt: params.expiresAt,
    used: false,
  });
  await fastify.emailService.sendVerificationEmail(credential.externalSub, params.token);
}

/**
 * Registration route.
 *
 * Answers every address the same way (ANT-2026-SPEMY9GU): `202` with one fixed
 * message, the same headers, and the same work on the request path. A new
 * address gets an account and a verification link. An address that already
 * has a password account in the realm gets no new account; its owner gets a
 * notice, or the verification link again while the account is unverified (see
 * {@link mailExistingAccount}). Which of the two happened reaches only the
 * mailbox.
 *
 * - The password is hashed and the insert transaction attempted on both
 *   paths. The credentials unique index (realm_id, provider_type,
 *   external_sub) is still the only duplicate guard, so a race between two
 *   registrations of one address is answered like any other duplicate.
 * - No mail is awaited by the request (see {@link createBackgroundTasks}): the
 *   floor below only pads up, so a delivery slower than it would show.
 * - `MIN_RESPONSE_TIME_MS.REGISTRATION` pads what is left: the extra inserts
 *   and the commit of a new account.
 *
 * The answer does not depend on the address, but a later login could:
 * registering an address with a password of one's choice and then logging in
 * with it would succeed only for an address that was free. With
 * `REQUIRE_VERIFIED_ACCOUNT` on (the default) the login routes refuse an
 * unverified account exactly as they refuse a wrong password, which closes
 * that too.
 */
export default async function (fastify: FastifyInstance) {
  const background = createBackgroundTasks(fastify);

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/register',
    {
      schema: {
        description:
          'Register a password account. Answers every address with the same 202 and message, whether it was free or already registered; the next step arrives by email (a verification link for a new account, a notice for an existing one). Password must meet strength requirements.',
        tags: ['Auth'],
        'x-qauth-stability': 'stable',
        body: registerSchema,
        response: {
          202: registerResponseSchema,
        },
      },
      config: {
        surface: 'api',
        rateLimit: {
          max: env.REGISTRATION_RATE_LIMIT,
          timeWindow: env.REGISTRATION_RATE_WINDOW * 1000,
          keyGenerator: clientAddressKey,
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const { email, password, realmId } = request.body as RegisterRequest;

      // Email is already validated by Zod schema, just normalize it
      const normalizedEmail = normalizeEmail(email);

      // Validate password strength using injected validator. Independent of
      // whether the address is registered, so it may answer early.
      const passwordStrength = fastify.passwordValidator.validatePasswordStrength(password);
      if (!passwordStrength.valid) {
        throw new WeakPasswordError(
          'Password does not meet strength requirements',
          passwordStrength.feedback
        );
      }

      // Get or create default realm (also independent of the address).
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

      // From here on the address decides the outcome, and the caller must not
      // be able to tell which. Everything up to the transaction runs the same
      // on both paths, the expensive hash included.
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

      // Generate verification token pair (token + tokenHash). A new account
      // stores it below; an unverified existing account may get it instead.
      const { token, tokenHash } = fastify.emailVerificationTokenUtils.generateVerificationToken();

      // Calculate expiration time
      const expiresAt = Date.now() + env.EMAIL_VERIFICATION_TOKEN_EXPIRY * 1000;

      const mayMailExistingAccount = await claimAddressMailSlot(fastify, normalizedEmail);

      // One transaction for the whole identity write set (#228, ADR-002): a
      // users row without its credential row would be unloginable AND block
      // re-registration, so the writes commit together.
      //
      // Ordering: users first because user_credentials.user_id FKs users.id.
      // Since #230 the credentials unique index (realm_id, provider_type,
      // external_sub) is the SOLE duplicate-registration guard — a duplicate
      // surfaces from the credential insert and rolls the anchor back.
      let createdUserId: string | undefined;
      try {
        createdUserId = await fastify.db.transaction(async (tx) => {
          // Pure identity anchor (#230): no email or password fields exist on
          // users; credential data lives only in user_credentials.
          const created = await fastify.repositories.users.create(
            {
              realmId: realm.id,
            },
            tx
          );

          const credential = await fastify.repositories.userCredentials
            .create(
              {
                userId: created.id,
                realmId: realm.id,
                providerType: PASSWORD_PROVIDER_TYPE,
                externalSub: identity.externalSub,
                credentialData: buildPasswordCredentialData(passwordHash, false),
              },
              tx
            )
            .catch((error: unknown) => {
              if (error instanceof UniqueConstraintError) {
                throw new AddressAlreadyRegistered();
              }
              throw error;
            });

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

          return created.id;
        });
      } catch (error) {
        if (!(error instanceof AddressAlreadyRegistered)) {
          throw error;
        }
      }

      if (createdUserId !== undefined) {
        // A new account always gets its verification mail: an address can be
        // registered only once, so this cannot be repeated to flood an inbox.
        background.run(
          () => fastify.emailService.sendVerificationEmail(normalizedEmail, token),
          'Failed to send verification email during registration'
        );
        // Structured log of the successful registration (#124). Email is
        // included on the success path; no password or token is logged.
        logAuthEvent(request, 'user.register.success', true, {
          userId: createdUserId,
          email: normalizedEmail,
        });
      } else {
        if (mayMailExistingAccount) {
          background.run(
            () =>
              mailExistingAccount(fastify, {
                realmId: realm.id,
                address: identity.externalSub,
                token,
                tokenHash,
                expiresAt,
              }),
            'Failed to mail the owner of an already registered address'
          );
        }
        // For operators only: the caller gets the same answer as for a new
        // account. The address is hashed, as on every failure log line.
        logAuthEvent(request, 'user.register.failure', false, {
          emailHash: hashEmail(normalizedEmail),
          reason: mayMailExistingAccount ? 'address_in_use' : 'address_in_use_mail_capped',
        });
      }

      await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.REGISTRATION);

      reply.header('Cache-Control', 'no-store');
      return reply.code(202).send({ message: SUCCESS_MESSAGES.REGISTRATION });
    }
  );
}
