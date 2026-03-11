import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  index,
  jsonb,
  pgTable,
  text,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { GrantType, ResponseType, sslRequiredEnum, tokenEndpointAuthMethodEnum } from './enums';
import { EPOCH_MS_NOW, JSONB_EMPTY_ARRAY } from './sql-helpers';

/**
 * Password Policy Configuration
 * Defines password requirements for a realm
 */
export interface PasswordPolicy {
  minLength?: number; // Minimum password length (default: 8)
  requireUppercase?: boolean; // Require at least one uppercase letter
  requireLowercase?: boolean; // Require at least one lowercase letter
  requireDigits?: number; // Minimum number of digits required
  requireSpecialChars?: boolean; // Require at least one special character
  forbiddenPasswords?: string[]; // List of forbidden passwords (e.g., "password", "12345678")
  maxLength?: number; // Maximum password length
  preventReuse?: number; // Number of previous passwords to prevent reuse
}

export const realms = pgTable(
  'realms',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    name: varchar('name', { length: 255 }).notNull().unique(),
    enabled: boolean('enabled').notNull().default(true),
    accessTokenLifespan: bigint('access_token_lifespan', { mode: 'number' }).default(900),
    refreshTokenLifespan: bigint('refresh_token_lifespan', { mode: 'number' }).default(604800),
    sslRequired: sslRequiredEnum('ssl_required').default('external'),
    verifyEmail: boolean('verify_email').notNull().default(true),
    registrationAllowed: boolean('registration_allowed').notNull().default(false),
    loginWithEmailAllowed: boolean('login_with_email_allowed').notNull().default(true),
    duplicateEmailsAllowed: boolean('duplicate_emails_allowed').notNull().default(false),
    passwordPolicy: jsonb('password_policy').$type<PasswordPolicy | null>(),
    ssoIdleTimeout: bigint('sso_idle_timeout', { mode: 'number' }),
    ssoMaxLifespan: bigint('sso_max_lifespan', { mode: 'number' }),
    revokeRefreshToken: boolean('revoke_refresh_token').notNull().default(false),
    refreshTokenMaxReuse: bigint('refresh_token_max_reuse', { mode: 'number' }).default(0),
    defaultLocale: varchar('default_locale', { length: 10 }),
    supportedLocales: jsonb('supported_locales').default(JSONB_EMPTY_ARRAY).$type<unknown[]>(),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    index('idx_realms_enabled')
      .on(t.enabled)
      .where(sql`${t.enabled} = true`),
  ]
);

export const users = pgTable(
  'users',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    email: varchar('email', { length: 255 }).notNull(),
    emailNormalized: varchar('email_normalized', { length: 255 }).notNull(),
    passwordHash: text('password_hash').notNull(),
    emailVerified: boolean('email_verified').notNull().default(false),
    enabled: boolean('enabled').notNull().default(true),
    firstName: varchar('first_name', { length: 255 }),
    lastName: varchar('last_name', { length: 255 }),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    lastLoginAt: bigint('last_login_at', { mode: 'number' }),
    emailVerifiedAt: bigint('email_verified_at', { mode: 'number' }),
  },
  (t) => [
    uniqueIndex('idx_users_realm_email_normalized_unique').on(t.realmId, t.emailNormalized),
    index('idx_users_email').on(t.email),
    index('idx_users_realm_id').on(t.realmId),
    index('idx_users_enabled')
      .on(t.enabled)
      .where(sql`${t.enabled} = true`),
    index('idx_users_realm_email_enabled').on(t.realmId, t.emailNormalized, t.enabled),
  ]
);

export const oauthClients = pgTable(
  'oauth_clients',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    clientId: varchar('client_id', { length: 255 }).notNull(),
    clientSecretHash: text('client_secret_hash').notNull(),
    name: varchar('name', { length: 255 }).notNull(),
    description: text('description'),
    redirectUris: jsonb('redirect_uris').notNull().$type<string[]>(),
    scopes: jsonb('scopes').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    enabled: boolean('enabled').notNull().default(true),
    requirePkce: boolean('require_pkce').notNull().default(true),
    tokenEndpointAuthMethod: tokenEndpointAuthMethodEnum('token_endpoint_auth_method')
      .notNull()
      .default('client_secret_post'),
    grantTypes: jsonb('grant_types')
      .notNull()
      .default(sql`'["authorization_code","refresh_token"]'::jsonb`)
      .$type<GrantType[]>(),
    responseTypes: jsonb('response_types')
      .notNull()
      .default(sql`'["code"]'::jsonb`)
      .$type<ResponseType[]>(),
    developerId: uuid('developer_id').references(() => users.id, { onDelete: 'set null' }),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    lastUsedAt: bigint('last_used_at', { mode: 'number' }),
  },
  (t) => [
    uniqueIndex('idx_oauth_clients_realm_client_id_unique').on(t.realmId, t.clientId),
    index('idx_oauth_clients_client_id').on(t.clientId),
    index('idx_oauth_clients_realm_id').on(t.realmId),
    index('idx_oauth_clients_developer_id').on(t.developerId),
    index('idx_oauth_clients_enabled')
      .on(t.enabled)
      .where(sql`${t.enabled} = true`),
    index('idx_oauth_clients_realm_client_id_enabled').on(t.realmId, t.clientId, t.enabled),
  ]
);

export const realmsRelations = relations(realms, ({ many }) => ({
  users: many(users),
  oauthClients: many(oauthClients),
}));

export const usersRelations = relations(users, ({ one, many }) => ({
  realm: one(realms, { fields: [users.realmId], references: [realms.id] }),
  oauthClientsAsDeveloper: many(oauthClients),
}));

export const oauthClientsRelations = relations(oauthClients, ({ one }) => ({
  realm: one(realms, { fields: [oauthClients.realmId], references: [realms.id] }),
  developer: one(users, { fields: [oauthClients.developerId], references: [users.id] }),
}));
