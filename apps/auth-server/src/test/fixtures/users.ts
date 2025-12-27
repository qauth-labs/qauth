/**
 * Test user fixture data structure
 * Note: This is a plain data structure, not tied to any specific library
 */
export interface TestUserData {
  email: string;
  emailNormalized: string;
  passwordHash: string;
  realmId: string;
  emailVerified: boolean;
}

/**
 * Test user fixtures
 */
export const testUsers = {
  /**
   * Create a test user data object
   */
  createTestUser(overrides?: Partial<TestUserData>): TestUserData {
    return {
      email: 'test@example.com',
      emailNormalized: 'test@example.com',
      passwordHash: 'hashed_password_placeholder',
      realmId: 'test-realm-id',
      emailVerified: false,
      ...overrides,
    };
  },

  /**
   * Create multiple test users
   */
  createTestUsers(count: number, realmId: string): TestUserData[] {
    return Array.from({ length: count }, (_, i) =>
      this.createTestUser({
        email: `test${i}@example.com`,
        emailNormalized: `test${i}@example.com`,
        realmId,
      })
    );
  },
};
