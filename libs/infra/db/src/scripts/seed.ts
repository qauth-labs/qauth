import { hash } from '@node-rs/argon2';
import * as dotenv from 'dotenv';
import { eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { join } from 'path';

import * as schema from '../lib/schema';

// Load environment variables from root .env file
dotenv.config({ path: join(__dirname, '../../../../../.env') });

const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_PORT = parseInt(process.env.DB_PORT || '5432', 10);
const DB_USER = process.env.POSTGRES_USER || 'qauth';
const DB_PASSWORD = process.env.DB_PASSWORD || 'postgres'; // Default for local dev
const DB_NAME = process.env.POSTGRES_DB || 'qauth';

const pool = new Pool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
});

const db = drizzle(pool, { schema });

async function seed() {
  console.log('🌱 Starting database seed...');

  try {
    // 1. Ensure "master" realm exists
    console.log('Checking for master realm...');
    let masterRealm = await db.query.realms.findFirst({
      where: eq(schema.realms.name, 'master'),
    });

    if (!masterRealm) {
      console.log('Creating master realm...');
      const [newRealm] = await db
        .insert(schema.realms)
        .values({
          name: 'master',
          enabled: true,
        })
        .returning();
      masterRealm = newRealm;
      console.log('✅ Master realm created:', masterRealm.id);
    } else {
      console.log('ℹ️ Master realm already exists:', masterRealm.id);
    }

    // 2. Ensure "dev-client" exists
    const clientId = 'dev-client';
    const clientSecret = 'dev-secret';
    console.log(`Checking for ${clientId}...`);

    let devClient = await db.query.oauthClients.findFirst({
      where: eq(schema.oauthClients.clientId, clientId),
    });

    if (!devClient) {
      console.log(`Creating ${clientId}...`);
      const clientSecretHash = await hash(clientSecret, {
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4,
      });

      const [newClient] = await db
        .insert(schema.oauthClients)
        .values({
          realmId: masterRealm.id,
          clientId: clientId,
          clientSecretHash,
          name: 'Development Client',
          description: 'Client for local development',
          redirectUris: ['http://localhost:4200/api/auth/callback/qauth', 'https://oauth.pstmn.io/v1/callback'], // Common callbacks
          grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
          responseTypes: ['code'],
          tokenEndpointAuthMethod: 'client_secret_post',
          requirePkce: false, // Easier for manual testing, though PKCE is recommended
          enabled: true,
        })
        .returning();
      devClient = newClient;
      console.log(`✅ ${clientId} created with secret: ${clientSecret}`);
    } else {
      console.log(`ℹ️ ${clientId} already exists`);
    }

    console.log('✨ Seeding completed successfully!');
  } catch (error) {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

seed();
