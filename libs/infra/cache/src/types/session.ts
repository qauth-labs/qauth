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
  getSession<T extends SessionData>(sessionId: string): Promise<T | null>;
  deleteSession(sessionId: string): Promise<void>;
  extendSession(sessionId: string, ttl?: number): Promise<void>;
  hasSession(sessionId: string): Promise<boolean>;
}
