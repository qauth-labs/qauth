import { hash } from '@node-rs/argon2';
import * as dotenv from 'dotenv';
import { drizzle } from 'drizzle-orm/node-postgres';
import { reset, seed } from 'drizzle-seed';

import { oauthClients, realms } from '../lib/schema';

dotenv.config({ path: '../../../.env' });

const db = drizzle(process.env['DATABASE_URL'] || '');

async function main() {
  const clientSecretHash = await hash('dev-secret', {
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });

  try {
    await reset(db, { realms, oauthClients });

    await seed(db, { realms, oauthClients }).refine((f) => ({
      realms: {
        count: 1,
        columns: {
          name: f.default({ defaultValue: 'master' }),
        },
        with: {
          oauthClients: 1,
        },
      },
      oauthClients: {
        columns: {
          clientId: f.default({ defaultValue: 'dev-client' }),
          clientSecretHash: f.default({ defaultValue: clientSecretHash }),
          name: f.default({ defaultValue: 'Development Client' }),
          description: f.default({ defaultValue: 'Client for local development' }),
          redirectUris: f.default({
            defaultValue: [
              'http://localhost:4200/api/auth/callback/qauth',
              'https://oauth.pstmn.io/v1/callback',
            ],
          }),
          grantTypes: f.default({
            defaultValue: ['authorization_code', 'refresh_token', 'client_credentials'],
          }),
          responseTypes: f.default({ defaultValue: ['code'] }),
          tokenEndpointAuthMethod: f.default({ defaultValue: 'client_secret_post' }),
          requirePkce: f.default({ defaultValue: true }),
          // A dev fixture the operator seeds: it keeps the automatic error
          // redirects (ANT-2026-O8U3P920).
          provisionedByOperator: f.default({ defaultValue: true }),
          // Never suspended (ANT-2026-DR5XI3LV): only an operator suspends.
          suspended: f.default({ defaultValue: false }),
          suspendedAt: f.default({ defaultValue: null }),
          // No ID-JAG target (#434): the dev client cannot mint or redeem one.
          idJagTargets: f.default({ defaultValue: [] }),
          // No verified domain (#593): drizzle-seed would otherwise fill the
          // column with a random string the CHECK refuses.
          verifiedDomain: f.default({ defaultValue: null }),
        },
      },
    }));

    console.log('Seeding completed.');
  } finally {
    await db.$client.end();
  }
}

main();
