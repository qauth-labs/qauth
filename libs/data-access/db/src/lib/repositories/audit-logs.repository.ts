import { and, desc, eq, InferInsertModel, InferSelectModel } from 'drizzle-orm';

import { db, DbClient } from '../db';
import { auditLogs } from '../schema/audit';
import { users } from '../schema/core';

export type AuditLog = InferSelectModel<typeof auditLogs>;
export type NewAuditLog = InferInsertModel<typeof auditLogs>;

/**
 * Audit event type enum values
 */
export type AuditEventType = 'auth' | 'token' | 'client' | 'security' | 'user' | 'realm';

/**
 * Options for querying audit logs
 */
export interface FindAuditLogsOptions {
  /**
   * Maximum number of logs to return
   * @default 50
   */
  limit?: number;
  /**
   * Number of logs to skip (for pagination)
   * @default 0
   */
  offset?: number;
  /**
   * Whether to return logs in descending order (newest first)
   * @default true
   */
  descending?: boolean;
  /**
   * Filter by event type
   */
  eventType?: AuditEventType;
  /**
   * Filter by success status
   */
  success?: boolean;
}

/**
 * Factory function that creates an audit logs repository
 *
 * @param defaultDb - Default database client to use (defaults to main db instance)
 * @returns Repository object with audit log methods
 */
export function createAuditLogsRepository(defaultDb: DbClient = db) {
  return {
    /**
     * Create a new audit log entry
     *
     * @param data - Audit log data to create
     * @param tx - Optional transaction client
     * @returns Created audit log
     */
    async create(data: NewAuditLog, tx?: DbClient): Promise<AuditLog> {
      const invoker = tx ?? defaultDb;
      const [log] = await invoker.insert(auditLogs).values(data).returning();
      return log;
    },

    /**
     * Find audit logs by user ID with pagination
     *
     * @param userId - User ID
     * @param options - Query options (pagination, filters)
     * @param tx - Optional transaction client
     * @returns Array of audit logs
     */
    async findByUserId(
      userId: string,
      options: FindAuditLogsOptions = {},
      tx?: DbClient
    ): Promise<AuditLog[]> {
      const invoker = tx ?? defaultDb;
      const { limit = 50, offset = 0, descending = true, eventType, success } = options;

      const conditions = [eq(auditLogs.userId, userId)];
      if (eventType !== undefined) {
        conditions.push(eq(auditLogs.eventType, eventType));
      }
      if (success !== undefined) {
        conditions.push(eq(auditLogs.success, success));
      }

      const baseQuery = invoker
        .select()
        .from(auditLogs)
        .where(and(...conditions))
        .limit(limit)
        .offset(offset);

      if (descending) {
        return baseQuery.orderBy(desc(auditLogs.createdAt));
      }

      return baseQuery;
    },

    /**
     * Find audit logs by realm ID with pagination
     * Security: This ensures users can only access audit logs from their own realm
     *
     * @param realmId - Realm ID
     * @param options - Query options (pagination, filters)
     * @param tx - Optional transaction client
     * @returns Array of audit logs
     */
    async findByRealmId(
      realmId: string,
      options: FindAuditLogsOptions = {},
      tx?: DbClient
    ): Promise<AuditLog[]> {
      const invoker = tx ?? defaultDb;
      const { limit = 50, offset = 0, descending = true, eventType, success } = options;

      const conditions = [eq(users.realmId, realmId)];
      if (eventType !== undefined) {
        conditions.push(eq(auditLogs.eventType, eventType));
      }
      if (success !== undefined) {
        conditions.push(eq(auditLogs.success, success));
      }

      const baseQuery = invoker
        .select({ auditLog: auditLogs })
        .from(auditLogs)
        .innerJoin(users, eq(auditLogs.userId, users.id))
        .where(and(...conditions))
        .limit(limit)
        .offset(offset);

      if (descending) {
        const result = await baseQuery.orderBy(desc(auditLogs.createdAt));
        return result.map((row) => row.auditLog);
      }

      const result = await baseQuery;
      return result.map((row) => row.auditLog);
    },

    /**
     * Find audit logs by user ID within a specific realm
     * Security: This ensures users can only access audit logs from their own realm
     *
     * @param realmId - Realm ID
     * @param userId - User ID
     * @param options - Query options (pagination, filters)
     * @param tx - Optional transaction client
     * @returns Array of audit logs
     */
    async findByRealmAndUserId(
      realmId: string,
      userId: string,
      options: FindAuditLogsOptions = {},
      tx?: DbClient
    ): Promise<AuditLog[]> {
      const invoker = tx ?? defaultDb;
      const { limit = 50, offset = 0, descending = true, eventType, success } = options;

      const conditions = [eq(auditLogs.userId, userId), eq(users.realmId, realmId)];
      if (eventType !== undefined) {
        conditions.push(eq(auditLogs.eventType, eventType));
      }
      if (success !== undefined) {
        conditions.push(eq(auditLogs.success, success));
      }

      const baseQuery = invoker
        .select({ auditLog: auditLogs })
        .from(auditLogs)
        .innerJoin(users, eq(auditLogs.userId, users.id))
        .where(and(...conditions))
        .limit(limit)
        .offset(offset);

      if (descending) {
        const result = await baseQuery.orderBy(desc(auditLogs.createdAt));
        return result.map((row) => row.auditLog);
      }

      const result = await baseQuery;
      return result.map((row) => row.auditLog);
    },
  };
}

/**
 * Default audit logs repository instance
 */
export const auditLogsRepository = createAuditLogsRepository();
