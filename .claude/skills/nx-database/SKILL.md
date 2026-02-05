---
name: nx-database
description: Database management with Drizzle ORM. Use when modifying schemas, running migrations, or working with database operations.
---

# Database Management (Drizzle ORM)

## Location

Database infrastructure: `libs/infra/db`

```
libs/infra/db/
├── src/
│   ├── schema/           # Drizzle schemas
│   ├── migrations/       # SQL migrations
│   ├── scripts/seed.ts   # Seeder
│   └── client.ts         # Drizzle client
├── drizzle.config.ts
└── project.json
```

## Commands

```bash
pnpm nx run infra-db:db:generate   # Generate migration
pnpm nx run infra-db:db:migrate    # Run migrations
pnpm nx run infra-db:db:studio     # Drizzle Studio
pnpm nx run infra-db:db:push       # Push schema (dev)
pnpm nx run infra-db:db:seed       # Seed data
pnpm nx run infra-db:db:drop       # Drop tables (DANGER)
```

## Schema Change Workflow

```bash
# 1. Modify schema in libs/infra/db/src/schema/
# 2. Generate migration
pnpm nx run infra-db:db:generate
# 3. Review migration in libs/infra/db/src/migrations/
# 4. Apply migration
pnpm nx run infra-db:db:migrate
```

## Schema Conventions

```typescript
import { pgTable, text, bigint, uuid, jsonb } from 'drizzle-orm/pg-core';
import { uuidv7 } from 'uuidv7';

export const users = pgTable('users', {
  // UUIDv7 primary key
  id: uuid('id')
    .primaryKey()
    .$defaultFn(() => uuidv7()),

  // BIGINT epoch timestamps
  createdAt: bigint('created_at', { mode: 'number' })
    .notNull()
    .$defaultFn(() => Date.now()),

  // JSONB for metadata
  metadata: jsonb('metadata').$type<Record<string, unknown>>(),

  // Realm for multi-tenancy
  realmId: uuid('realm_id').references(() => realms.id),
});
```

## Key Patterns

- **UUIDv7**: Time-ordered primary keys
- **BIGINT epoch**: Timestamps as milliseconds
- **JSONB**: Flexible metadata
- **Realm-based**: Multi-tenancy support

## Docker Database

```bash
docker compose up -d postgres
docker compose exec postgres psql -U postgres -d qauth
```

## Environment

```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/qauth
```
