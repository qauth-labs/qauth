import type { ZodType } from 'zod';

/**
 * User data type - can be extended by consumers
 */
export interface UserData {
  [key: string]: unknown;
}

/**
 * User utilities interface
 */
export interface UserUtilsInstance {
  setUserData<T extends UserData>(userId: string, data: T, ttl?: number): Promise<void>;
  /**
   * Read cached user data. When `schema` is provided, the parsed value is
   * validated against it; a validation failure (or malformed JSON) is treated
   * as a cache MISS — the method returns `null` and logs a warning rather than
   * returning a mis-typed object or throwing.
   */
  getUserData<T extends UserData>(userId: string, schema?: ZodType<T>): Promise<T | null>;
  deleteUserData(userId: string): Promise<void>;
}
