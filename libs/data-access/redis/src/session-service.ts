// Session management service for QAuth OAuth 2.1/OIDC server
// High-level session operations with business logic

import { SESSION_LIFETIME } from '@qauth/constants';
import type { CreateSessionInput, Session } from '@qauth/types';
import { addSeconds, generateSessionId, now } from '@qauth/utils';

import { getRedis, RedisClient } from './client';

// =============================================================================
// Session Service Class
// =============================================================================

export class SessionService {
  private redis: RedisClient;

  constructor(redis?: RedisClient) {
    this.redis = redis || getRedis();
  }

  // =============================================================================
  // Session Creation and Management
  // =============================================================================

  /**
   * Create a new session for a user and client
   */
  async createSession(input: CreateSessionInput): Promise<Session> {
    const sessionId = generateSessionId();
    const now = new Date();
    const expiresAt = addSeconds(now, SESSION_LIFETIME);

    const session: Session = {
      sessionId,
      userId: input.userId,
      clientId: input.clientId,
      createdAt: now,
      lastAccessedAt: now,
      expiresAt,
    };

    // Store session in Redis with TTL
    await this.redis.setSession(sessionId, session, SESSION_LIFETIME);

    return session;
  }

  /**
   * Get session by session ID
   */
  async getSession(sessionId: string): Promise<Session | null> {
    const session = await this.redis.getSession(sessionId);

    if (!session) {
      return null;
    }

    // Check if session is expired
    if (session.expiresAt && new Date(session.expiresAt) <= now()) {
      // Session expired, clean it up
      await this.deleteSession(sessionId);
      return null;
    }

    return session as Session;
  }

  /**
   * Update session last accessed time
   * Extends TTL to prevent premature expiration
   */
  async updateSessionAccess(sessionId: string): Promise<boolean> {
    const session = await this.getSession(sessionId);

    if (!session) {
      return false;
    }

    // Update last accessed time
    session.lastAccessedAt = now();

    // Store updated session with refreshed TTL
    await this.redis.setSession(sessionId, session, SESSION_LIFETIME);

    return true;
  }

  /**
   * Delete a specific session
   */
  async deleteSession(sessionId: string): Promise<boolean> {
    return this.redis.deleteSession(sessionId);
  }

  /**
   * Delete all sessions for a user
   * Useful for "logout from all devices" functionality
   */
  async deleteUserSessions(userId: string): Promise<number> {
    return this.redis.deleteUserSessions(userId);
  }

  /**
   * Delete all sessions for a user and specific client
   * Useful for client-specific logout
   */
  async deleteUserClientSessions(userId: string, clientId: string): Promise<number> {
    const pattern = `session:*`;
    let cursor = '0';
    let deletedCount = 0;

    try {
      do {
        const result = await this.redis.client.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = result[0];
        const keys = result[1];

        // Filter keys that belong to this user and client
        const targetSessionKeys = [];
        for (const key of keys) {
          const sessionData = await this.redis.client.get(key);
          if (sessionData) {
            try {
              const parsed = JSON.parse(sessionData);
              if (parsed.userId === userId && parsed.clientId === clientId) {
                targetSessionKeys.push(key);
              }
            } catch (parseError) {
              // Skip invalid session data
              console.warn(`Invalid session data in key ${key}`);
            }
          }
        }

        // Delete target sessions
        if (targetSessionKeys.length > 0) {
          const deleted = await this.redis.client.del(...targetSessionKeys);
          deletedCount += deleted;
        }
      } while (cursor !== '0');

      return deletedCount;
    } catch (error) {
      console.error(`Failed to delete sessions for user ${userId} and client ${clientId}:`, error);
      return 0;
    }
  }

  // =============================================================================
  // Session Validation and Security
  // =============================================================================

  /**
   * Validate session exists and is not expired
   */
  async validateSession(sessionId: string): Promise<boolean> {
    const session = await this.getSession(sessionId);
    return session !== null;
  }

  /**
   * Check if user has active sessions
   */
  async hasActiveSessions(userId: string): Promise<boolean> {
    const pattern = `session:*`;
    let cursor = '0';

    try {
      do {
        const result = await this.redis.client.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = result[0];
        const keys = result[1];

        for (const key of keys) {
          const sessionData = await this.redis.client.get(key);
          if (sessionData) {
            try {
              const parsed = JSON.parse(sessionData);
              if (parsed.userId === userId) {
                // Check if session is not expired
                if (parsed.expiresAt && new Date(parsed.expiresAt) > now()) {
                  return true;
                }
              }
            } catch (parseError) {
              // Skip invalid session data
            }
          }
        }
      } while (cursor !== '0');

      return false;
    } catch (error) {
      console.error(`Failed to check active sessions for user ${userId}:`, error);
      return false;
    }
  }

  // =============================================================================
  // Session Analytics and Monitoring
  // =============================================================================

  /**
   * Get session statistics
   */
  async getSessionStats(): Promise<{
    totalSessions: number;
    memoryUsage: string;
    activeUsers: number;
  }> {
    const stats = await this.redis.getSessionStats();

    // Count unique active users
    const pattern = `session:*`;
    let cursor = '0';
    const activeUsers = new Set<string>();

    try {
      do {
        const result = await this.redis.client.scan(cursor, 'MATCH', pattern, 'COUNT', 1000);
        cursor = result[0];
        const keys = result[1];

        for (const key of keys) {
          const sessionData = await this.redis.client.get(key);
          if (sessionData) {
            try {
              const parsed = JSON.parse(sessionData);
              if (parsed.userId && parsed.expiresAt && new Date(parsed.expiresAt) > now()) {
                activeUsers.add(parsed.userId);
              }
            } catch (parseError) {
              // Skip invalid session data
            }
          }
        }
      } while (cursor !== '0');
    } catch (error) {
      console.error('Failed to count active users:', error);
    }

    return {
      totalSessions: stats.totalSessions,
      memoryUsage: stats.memoryUsage,
      activeUsers: activeUsers.size,
    };
  }

  /**
   * Get sessions for a specific user
   */
  async getUserSessions(userId: string): Promise<Session[]> {
    const pattern = `session:*`;
    let cursor = '0';
    const sessions: Session[] = [];

    try {
      do {
        const result = await this.redis.client.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = result[0];
        const keys = result[1];

        for (const key of keys) {
          const sessionData = await this.redis.client.get(key);
          if (sessionData) {
            try {
              const parsed = JSON.parse(sessionData);
              if (
                parsed.userId === userId &&
                parsed.expiresAt &&
                new Date(parsed.expiresAt) > now()
              ) {
                sessions.push(parsed as Session);
              }
            } catch (parseError) {
              // Skip invalid session data
            }
          }
        }
      } while (cursor !== '0');
    } catch (error) {
      console.error(`Failed to get sessions for user ${userId}:`, error);
    }

    return sessions;
  }

  // =============================================================================
  // Maintenance and Cleanup
  // =============================================================================

  /**
   * Clean up expired sessions (should be called periodically)
   * Note: Redis automatically expires keys, but this provides explicit cleanup
   */
  async cleanupExpiredSessions(): Promise<number> {
    const pattern = `session:*`;
    let cursor = '0';
    let cleanedCount = 0;

    try {
      do {
        const result = await this.redis.client.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = result[0];
        const keys = result[1];

        const expiredKeys = [];
        for (const key of keys) {
          const sessionData = await this.redis.client.get(key);
          if (sessionData) {
            try {
              const parsed = JSON.parse(sessionData);
              if (parsed.expiresAt && new Date(parsed.expiresAt) <= now()) {
                expiredKeys.push(key);
              }
            } catch (parseError) {
              // Mark invalid session data for cleanup
              expiredKeys.push(key);
            }
          }
        }

        // Delete expired sessions
        if (expiredKeys.length > 0) {
          const deleted = await this.redis.client.del(...expiredKeys);
          cleanedCount += deleted;
        }
      } while (cursor !== '0');
    } catch (error) {
      console.error('Failed to cleanup expired sessions:', error);
    }

    return cleanedCount;
  }
}

// =============================================================================
// Global Session Service Instance
// =============================================================================

let sessionService: SessionService | null = null;

/**
 * Initialize the global session service
 */
export function initializeSessionService(redis?: RedisClient): SessionService {
  if (sessionService) {
    throw new Error('Session service already initialized');
  }

  sessionService = new SessionService(redis);
  return sessionService;
}

/**
 * Get the global session service
 */
export function getSessionService(): SessionService {
  if (!sessionService) {
    throw new Error('Session service not initialized. Call initializeSessionService() first.');
  }

  return sessionService;
}
