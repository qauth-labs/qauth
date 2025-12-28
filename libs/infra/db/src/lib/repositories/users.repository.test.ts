import { createTestDrizzle, getTestDatabasePool, startTestDatabase } from '@qauth/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { RealmsRepository, UsersRepository } from './index';
import { createRealmsRepository } from './realms.repository';
import { createUsersRepository } from './users.repository';

describe.skip('UsersRepository Integration Tests', () => {
  let usersRepo: UsersRepository;
  let realmsRepo: RealmsRepository;
  let testRealmId: string;

  beforeAll(async () => {
    // Ensure test database is started (migrations run in global setup)
    await startTestDatabase();
    const db = createTestDrizzle();
    const pool = getTestDatabasePool();

    if (!pool) {
      throw new Error('Test database pool not available');
    }

    usersRepo = createUsersRepository(db);
    realmsRepo = createRealmsRepository(db);

    // Create a test realm
    const realm = await realmsRepo.create({
      name: `test-realm-${Date.now()}`,
      enabled: true,
    });
    testRealmId = realm.id;
  });

  afterAll(async () => {
    // Cleanup is handled by global teardown
  });

  describe('create', () => {
    it('should create a new user', async () => {
      const user = await usersRepo.create({
        email: `test-${Date.now()}@example.com`,
        emailNormalized: `test-${Date.now()}@example.com`,
        passwordHash: 'test-hash',
        realmId: testRealmId,
        emailVerified: false,
      });

      expect(user).toBeDefined();
      expect(user.id).toBeDefined();
      expect(user.email).toBeDefined();
      expect(user.realmId).toBe(testRealmId);
    });
  });

  describe('findById', () => {
    it('should find a user by id', async () => {
      const created = await usersRepo.create({
        email: `test-${Date.now()}@example.com`,
        emailNormalized: `test-${Date.now()}@example.com`,
        passwordHash: 'test-hash',
        realmId: testRealmId,
        emailVerified: false,
      });

      const found = await usersRepo.findById(created.id);
      expect(found).toBeDefined();
      expect(found?.id).toBe(created.id);
      expect(found?.email).toBe(created.email);
    });

    it('should return undefined for non-existent user', async () => {
      const found = await usersRepo.findById('non-existent-id');
      expect(found).toBeUndefined();
    });
  });

  describe('findByEmail', () => {
    it('should find a user by email', async () => {
      const email = `test-${Date.now()}@example.com`;
      const created = await usersRepo.create({
        email,
        emailNormalized: email.toLowerCase(),
        passwordHash: 'test-hash',
        realmId: testRealmId,
        emailVerified: false,
      });

      const found = await usersRepo.findByEmail(testRealmId, email);
      expect(found).toBeDefined();
      expect(found?.id).toBe(created.id);
    });
  });
});
