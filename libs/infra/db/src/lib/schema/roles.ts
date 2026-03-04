import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  index,
  jsonb,
  pgTable,
  primaryKey,
  text,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { oauthClients, realms, users } from './core';
import { EPOCH_MS_NOW } from './sql-helpers';

export const roles = pgTable(
  'roles',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 255 }).notNull(),
    description: text('description'),
    oauthClientId: uuid('oauth_client_id').references(() => oauthClients.id, {
      onDelete: 'set null',
    }),
    enabled: boolean('enabled').notNull().default(true),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    uniqueIndex('idx_roles_realm_name_unique').on(t.realmId, t.name, t.oauthClientId),
    index('idx_roles_name').on(t.name),
    index('idx_roles_realm_id').on(t.realmId),
    index('idx_roles_oauth_client_id').on(t.oauthClientId),
  ]
);

export const userRoles = pgTable(
  'user_roles',
  {
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    roleId: uuid('role_id')
      .notNull()
      .references(() => roles.id, { onDelete: 'cascade' }),
    assignedAt: bigint('assigned_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    assignedBy: uuid('assigned_by').references(() => users.id, { onDelete: 'set null' }),
  },
  (t) => [
    primaryKey({ columns: [t.userId, t.roleId], name: 'user_roles_pk' }),
    index('idx_user_roles_user_id').on(t.userId),
    index('idx_user_roles_role_id').on(t.roleId),
  ]
);

export const rolesRelations = relations(roles, ({ one, many }) => ({
  realm: one(realms, { fields: [roles.realmId], references: [realms.id] }),
  oauthClient: one(oauthClients, {
    fields: [roles.oauthClientId],
    references: [oauthClients.id],
  }),
  userRoles: many(userRoles),
}));

export const userRolesRelations = relations(userRoles, ({ one }) => ({
  user: one(users, { fields: [userRoles.userId], references: [users.id] }),
  role: one(roles, { fields: [userRoles.roleId], references: [roles.id] }),
  assignedByUser: one(users, { fields: [userRoles.assignedBy], references: [users.id] }),
}));
