import Fastify from 'fastify';

import { env } from '../../../config/env';
import { testUsers } from '../../../test/fixtures/users';
import { cleanDatabase } from '../../../test/helpers/db';
import { cleanRedis } from '../../../test/helpers/redis';
import { app } from '../../app';

describe('POST /auth/register', () => {
  let fastify: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    fastify = Fastify({
      logger: false,
    });

    await fastify.register(app);

    await fastify.ready();

    // Clean database and Redis before each test
    await cleanDatabase(fastify);
    await cleanRedis(fastify);
  });

  afterEach(async () => {
    // Clean database and Redis after each test
    await cleanDatabase(fastify);
    await cleanRedis(fastify);

    await fastify.close();
  });

  describe('Successful registration', () => {
    it('should register a new user successfully (201)', async () => {
      const testUser = testUsers.createTestUser({
        email: 'newuser@example.com',
        emailNormalized: 'newuser@example.com',
      });

      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: testUser.email,
          password: 'SecurePassword123!',
        },
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body.id).toBeDefined();
      expect(body.email).toBe(testUser.emailNormalized);
      expect(body.emailVerified).toBe(testUser.emailVerified);
      expect(body.realmId).toBeDefined();
      expect(body.passwordHash).toBeUndefined();
    });

    it('should normalize email address', async () => {
      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'User@Example.com',
          password: 'SecurePassword123!',
        },
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body.email).toBe('user@example.com');
    });
  });

  describe('Error cases', () => {
    it('should reject duplicate email (409)', async () => {
      const testUser = testUsers.createTestUser({
        email: 'duplicate@example.com',
        emailNormalized: 'duplicate@example.com',
      });

      // Register first user
      await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: testUser.email,
          password: 'SecurePassword123!',
        },
      });

      // Try to register again with same email
      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: testUser.email,
          password: 'SecurePassword123!',
        },
      });

      expect(response.statusCode).toBe(409);
      const body = JSON.parse(response.body);
      expect(body.error).toBeDefined();
      expect(body.code).toBe('UNIQUE_CONSTRAINT_VIOLATION');
      expect(body.constraint).toBe('idx_users_realm_email_normalized_unique');
    });

    it('should reject weak password (422)', async () => {
      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'weakpass@example.com',
          password: 'password',
        },
      });

      expect(response.statusCode).toBe(422);
      const body = JSON.parse(response.body);
      expect(body.error).toBeDefined();
      expect(body.code).toBe('WEAK_PASSWORD');
      expect(body.feedback).toBeDefined();
    });

    it('should reject invalid email format (400)', async () => {
      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'invalid-email',
          password: 'SecurePassword123!',
        },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.message).toBeDefined();
    });

    it('should reject missing email (400)', async () => {
      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          password: 'SecurePassword123!',
        },
      });

      expect(response.statusCode).toBe(400);
    });

    it('should reject missing password (400)', async () => {
      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'test@example.com',
        },
      });

      expect(response.statusCode).toBe(400);
    });

    it('should reject empty password (422)', async () => {
      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'test@example.com',
          password: '',
        },
      });

      expect(response.statusCode).toBe(422);
      const body = JSON.parse(response.body);
      expect(body.error).toBeDefined();
      expect(body.code).toBe('WEAK_PASSWORD');
      expect(body.feedback).toBeDefined();
    });
  });

  describe('Default realm handling', () => {
    it('should create default realm if not exists', async () => {
      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'realmtest@example.com',
          password: 'SecurePassword123!',
        },
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body.realmId).toBeDefined();

      // Verify realm exists
      const realm = await fastify.repositories.realms.findById(body.realmId);
      expect(realm).toBeDefined();
      expect(realm?.name).toBe(env.DEFAULT_REALM_NAME);
    });

    it('should use provided realmId if valid', async () => {
      // Create a test realm
      const realm = await fastify.repositories.realms.create({
        name: 'test-realm',
        enabled: true,
      });

      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'realmuser@example.com',
          password: 'SecurePassword123!',
          realmId: realm.id,
        },
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body.realmId).toBe(realm.id);
    });

    it('should reject invalid realmId format (400)', async () => {
      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'test@example.com',
          password: 'SecurePassword123!',
          realmId: 'invalid-uuid',
        },
      });

      expect(response.statusCode).toBe(400);
    });

    it('should reject non-existent realmId (400)', async () => {
      // Use a valid UUID format but non-existent realm ID
      const nonExistentRealmId = '00000000-0000-0000-0000-000000000000';

      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'test@example.com',
          password: 'SecurePassword123!',
          realmId: nonExistentRealmId,
        },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.message).toContain(nonExistentRealmId);
    });
  });

  describe('Password hashing', () => {
    it('should hash password before storing', async () => {
      const email = 'hashtest@example.com';
      const password = 'SecurePassword123!';

      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email,
          password,
        },
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);

      // Verify user was created
      const user = await fastify.repositories.users.findByEmail(body.realmId, email);
      expect(user).toBeDefined();
      expect(user?.passwordHash).toBeDefined();
      expect(user?.passwordHash).not.toBe(password);
      expect(user?.passwordHash).toContain('$argon2id$');
    });
  });

  describe('Rate limiting', () => {
    it('should enforce rate limit and return 429 after exceeding limit', async () => {
      const limit = env.REGISTRATION_RATE_LIMIT;
      const email = 'ratelimit@example.com';
      const password = 'SecurePassword123!';

      // Make requests up to the limit (should succeed)
      for (let i = 0; i < limit; i++) {
        const response = await fastify.inject({
          method: 'POST',
          url: '/auth/register',
          payload: {
            email: `ratelimit${i}@example.com`,
            password,
          },
        });
        expect([201, 409]).toContain(response.statusCode); // 409 if duplicate, 201 if new
      }

      // Next request should be rate limited
      const rateLimitedResponse = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email,
          password,
        },
      });

      expect(rateLimitedResponse.statusCode).toBe(429);
      const body = JSON.parse(rateLimitedResponse.body);
      expect(body.message || body.error).toBeDefined();
    });
  });

  describe('Concurrent requests (race conditions)', () => {
    it('should handle concurrent registration attempts with same email', async () => {
      const email = 'concurrent@example.com';
      const password = 'SecurePassword123!';
      const concurrentRequests = 5;

      // Send multiple concurrent requests with the same email
      const promises = Array.from({ length: concurrentRequests }, () =>
        fastify.inject({
          method: 'POST',
          url: '/auth/register',
          payload: {
            email,
            password,
          },
        })
      );

      const responses = await Promise.all(promises);

      // Only one should succeed (201), others should fail with 409
      const successCount = responses.filter((r) => r.statusCode === 201).length;
      const conflictCount = responses.filter((r) => r.statusCode === 409).length;

      expect(successCount).toBe(1);
      expect(conflictCount).toBe(concurrentRequests - 1);

      // Verify only one user was created
      const realm = await fastify.repositories.realms.findByName(env.DEFAULT_REALM_NAME);
      expect(realm).toBeDefined();
      if (realm) {
        const user = await fastify.repositories.users.findByEmail(realm.id, email);
        expect(user).toBeDefined();
      }
    });
  });

  describe('Realm disabled', () => {
    it('should reject registration with disabled realm (400)', async () => {
      // Create a disabled realm
      const disabledRealm = await fastify.repositories.realms.create({
        name: 'disabled-realm',
        enabled: false,
      });

      const response = await fastify.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'disabledrealm@example.com',
          password: 'SecurePassword123!',
          realmId: disabledRealm.id,
        },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.message).toContain('disabled');
      expect(body.message).toContain(disabledRealm.id);
    });
  });
});
