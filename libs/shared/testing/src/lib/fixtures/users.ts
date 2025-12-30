/**
 * User test fixtures
 */

export interface UserFixture {
  email: string;
  emailNormalized: string;
  password: string;
  passwordHash?: string;
  realmId?: string;
  emailVerified?: boolean;
}

/**
 * Create a test user fixture
 */
export function createUserFixture(overrides?: Partial<UserFixture>): UserFixture {
  const timestamp = Date.now();
  const email = `test-${timestamp}@example.com`;

  return {
    email,
    emailNormalized: email.toLowerCase(),
    password: 'SecureTestPassword123!',
    emailVerified: false,
    ...overrides,
  };
}

/**
 * Create multiple test user fixtures
 */
export function createUserFixtures(count: number): UserFixture[] {
  return Array.from({ length: count }, (_, i) =>
    createUserFixture({
      email: `test-${i}-${Date.now()}@example.com`,
    })
  );
}
