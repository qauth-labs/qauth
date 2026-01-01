/**
 * Rate limit result
 */
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
}

/**
 * Rate limit status
 */
export interface RateLimitStatus {
  current: number;
  remaining: number;
  resetTime: number;
}

/**
 * Rate limit utilities interface
 */
export interface RateLimitUtilsInstance {
  checkRateLimit(key: string, limit: number, windowSeconds?: number): Promise<RateLimitResult>;
  resetRateLimit(key: string): Promise<void>;
  getRateLimitStatus(key: string, limit: number): Promise<RateLimitStatus>;
}
