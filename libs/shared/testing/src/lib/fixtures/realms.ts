/**
 * Realm test fixtures
 */

type RealmFixture = {
  name: string;
  enabled?: boolean;
};

/**
 * Create a test realm fixture
 */
export function createRealmFixture(overrides?: Partial<RealmFixture>): RealmFixture {
  const timestamp = Date.now();
  return {
    name: `test-realm-${timestamp}`,
    enabled: true,
    ...overrides,
  };
}

/**
 * Create multiple test realm fixtures
 */
export function createRealmFixtures(count: number): RealmFixture[] {
  return Array.from({ length: count }, (_, i) =>
    createRealmFixture({
      name: `test-realm-${i}-${Date.now()}`,
    })
  );
}
