// Database client configuration and connection management
// Production-ready connection pooling and error handling

import { DB_POOL_CONFIG, DB_QUERY_TIMEOUT } from '@qauth/constants';
import { eq, lt } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool, PoolClient } from 'pg';

import {
  type AccessToken,
  accessTokens,
  type AuthorizationCode,
  authorizationCodes,
  type NewAccessToken,
  type NewAuthorizationCode,
  type NewOAuthClient,
  type NewRefreshToken,
  type NewSession,
  type NewUser,
  type OAuthClient,
  oauthClients,
  type RefreshToken,
  refreshTokens,
  type Session,
  sessions,
  type User,
  users,
} from './schema';

// =============================================================================
// Database Configuration
// =============================================================================

export interface DatabaseConfig {
  connectionString: string;
  pool?: {
    min?: number;
    max?: number;
    idleTimeoutMillis?: number;
    connectionTimeoutMillis?: number;
  };
  queryTimeout?: number;
}

// =============================================================================
// Database Client Class
// =============================================================================

export class DatabaseClient {
  private pool: Pool;
  private drizzleDb: ReturnType<typeof drizzle>;

  constructor(config: DatabaseConfig) {
    // Create connection pool with production-ready settings
    this.pool = new Pool({
      connectionString: config.connectionString,
      // Use provided pool config or defaults
      min: config.pool?.min ?? DB_POOL_CONFIG.min,
      max: config.pool?.max ?? DB_POOL_CONFIG.max,
      idleTimeoutMillis: config.pool?.idleTimeoutMillis ?? DB_POOL_CONFIG.idleTimeoutMillis,
      connectionTimeoutMillis:
        config.pool?.connectionTimeoutMillis ?? DB_POOL_CONFIG.connectionTimeoutMillis,
      // Query timeout
      query_timeout: config.queryTimeout ?? DB_QUERY_TIMEOUT,
      // Additional production settings
      keepAlive: true,
      keepAliveInitialDelayMillis: 0,
    });

    // Initialize Drizzle with the pool
    this.drizzleDb = drizzle(this.pool);

    // Handle pool errors
    this.pool.on('error', (err) => {
      console.error('Database pool error:', err);
    });

    this.pool.on('connect', (client) => {
      console.log('New database client connected');
    });

    this.pool.on('remove', (client) => {
      console.log('Database client removed from pool');
    });
  }

  // =============================================================================
  // Connection Management
  // =============================================================================

  /**
   * Get a client from the pool for transactions
   */
  async getClient(): Promise<PoolClient> {
    return this.pool.connect();
  }

  /**
   * Execute a transaction with automatic rollback on error
   */
  async transaction<T>(callback: (tx: any) => Promise<T>): Promise<T> {
    const client = await this.getClient();
    try {
      await client.query('BEGIN');
      const tx = drizzle(client);
      const result = await callback(tx);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Test database connection
   */
  async ping(): Promise<boolean> {
    try {
      const result = await this.pool.query('SELECT 1');
      return result.rows[0]?.int4 === 1;
    } catch (error) {
      console.error('Database ping failed:', error);
      return false;
    }
  }

  /**
   * Get pool statistics for monitoring
   */
  getPoolStats() {
    return {
      totalCount: this.pool.totalCount,
      idleCount: this.pool.idleCount,
      waitingCount: this.pool.waitingCount,
    };
  }

  /**
   * Gracefully close the database connection pool
   */
  async close(): Promise<void> {
    await this.pool.end();
  }

  // =============================================================================
  // Database Access (Drizzle ORM)
  // =============================================================================

  get db() {
    return this.drizzleDb;
  }

  // =============================================================================
  // Convenience Methods for Common Queries
  // =============================================================================

  /**
   * Find user by email
   */
  async findUserByEmail(email: string): Promise<User | null> {
    const result = await this.db.select().from(users).where(eq(users.email, email)).limit(1);

    return result[0] || null;
  }

  /**
   * Find user by ID
   */
  async findUserById(id: string): Promise<User | null> {
    const result = await this.db.select().from(users).where(eq(users.id, id)).limit(1);

    return result[0] || null;
  }

  /**
   * Find OAuth client by client ID
   */
  async findClientByClientId(clientId: string): Promise<OAuthClient | null> {
    const result = await this.db
      .select()
      .from(oauthClients)
      .where(eq(oauthClients.clientId, clientId))
      .limit(1);

    return result[0] || null;
  }

  /**
   * Find authorization code by code
   */
  async findAuthorizationCodeByCode(code: string): Promise<AuthorizationCode | null> {
    const result = await this.db
      .select()
      .from(authorizationCodes)
      .where(eq(authorizationCodes.code, code))
      .limit(1);

    return result[0] || null;
  }

  /**
   * Find access token by token
   */
  async findAccessTokenByToken(token: string): Promise<AccessToken | null> {
    const result = await this.db
      .select()
      .from(accessTokens)
      .where(eq(accessTokens.token, token))
      .limit(1);

    return result[0] || null;
  }

  /**
   * Find refresh token by token
   */
  async findRefreshTokenByToken(token: string): Promise<RefreshToken | null> {
    const result = await this.db
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.token, token))
      .limit(1);

    return result[0] || null;
  }

  /**
   * Find session by session ID
   */
  async findSessionBySessionId(sessionId: string): Promise<Session | null> {
    const result = await this.db
      .select()
      .from(sessions)
      .where(eq(sessions.sessionId, sessionId))
      .limit(1);

    return result[0] || null;
  }

  // =============================================================================
  // Cleanup Methods
  // =============================================================================

  /**
   * Clean up expired authorization codes
   */
  async cleanupExpiredAuthorizationCodes(): Promise<number> {
    const result = await this.db
      .delete(authorizationCodes)
      .where(lt(authorizationCodes.expiresAt, new Date()));

    return result.rowCount || 0;
  }

  /**
   * Clean up expired access tokens
   */
  async cleanupExpiredAccessTokens(): Promise<number> {
    const result = await this.db.delete(accessTokens).where(lt(accessTokens.expiresAt, new Date()));

    return result.rowCount || 0;
  }

  /**
   * Clean up expired refresh tokens
   */
  async cleanupExpiredRefreshTokens(): Promise<number> {
    const result = await this.db
      .delete(refreshTokens)
      .where(lt(refreshTokens.expiresAt, new Date()));

    return result.rowCount || 0;
  }

  /**
   * Clean up expired sessions
   */
  async cleanupExpiredSessions(): Promise<number> {
    const result = await this.db.delete(sessions).where(lt(sessions.expiresAt, new Date()));

    return result.rowCount || 0;
  }
}

// =============================================================================
// Global Database Instance
// =============================================================================

let dbClient: DatabaseClient | null = null;

/**
 * Initialize the global database client
 */
export function initializeDatabase(config: DatabaseConfig): DatabaseClient {
  if (dbClient) {
    throw new Error('Database client already initialized');
  }

  dbClient = new DatabaseClient(config);
  return dbClient;
}

/**
 * Get the global database client
 */
export function getDatabase(): DatabaseClient {
  if (!dbClient) {
    throw new Error('Database client not initialized. Call initializeDatabase() first.');
  }

  return dbClient;
}

/**
 * Close the global database client
 */
export async function closeDatabase(): Promise<void> {
  if (dbClient) {
    await dbClient.close();
    dbClient = null;
  }
}
