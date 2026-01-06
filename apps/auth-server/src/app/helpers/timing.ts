/**
 * Ensure minimum response time to prevent timing attacks
 * If the elapsed time is less than the minimum, waits for the remaining time
 *
 * @param startTime - Timestamp when the operation started (from Date.now())
 * @param minResponseTime - Minimum response time in milliseconds
 * @returns Promise that resolves after ensuring minimum response time
 *
 * @example
 * ```typescript
 * import { MIN_RESPONSE_TIME_MS } from '../constants';
 * const startTime = Date.now();
 * // ... perform operation ...
 * await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);
 * ```
 */
export async function ensureMinimumResponseTime(
  startTime: number,
  minResponseTime: number
): Promise<void> {
  const elapsed = Date.now() - startTime;
  if (elapsed < minResponseTime) {
    await new Promise((resolve) => setTimeout(resolve, minResponseTime - elapsed));
  }
}
