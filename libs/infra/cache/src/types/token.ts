/**
 * Token utilities interface
 */
export interface TokenUtilsInstance {
  blacklistToken(token: string, ttl?: number): Promise<void>;
  isTokenBlacklisted(token: string): Promise<boolean>;
  unblacklistToken(token: string): Promise<void>;
}
