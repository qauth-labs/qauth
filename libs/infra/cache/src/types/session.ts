import type { ZodType } from 'zod';

/**
 * Session data type - can be extended by consumers
 */
export interface SessionData {
  [key: string]: unknown;
}

/**
 * Session utilities interface
 */
export interface SessionUtilsInstance {
  setSession<T extends SessionData>(sessionId: string, data: T, ttl?: number): Promise<void>;
  /**
   * Read a session. When `schema` is provided, the parsed value is validated
   * against it; a validation failure (or malformed JSON) is treated as a cache
   * MISS — the method returns `null` and logs a warning rather than returning a
   * mis-typed object or throwing.
   */
  getSession<T extends SessionData>(sessionId: string, schema?: ZodType<T>): Promise<T | null>;
  deleteSession(sessionId: string): Promise<void>;
  extendSession(sessionId: string, ttl?: number): Promise<void>;
  hasSession(sessionId: string): Promise<boolean>;
}
