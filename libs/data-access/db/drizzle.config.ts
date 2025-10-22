import * as dotenv from 'dotenv';
import type { Config } from 'drizzle-kit';

dotenv.config({ path: '../../../.env' }); // Kök dizindeki .env dosyasını oku

export default {
  schema: './src/schemas/index.ts', // Şemaların yolu
  out: './src/migrations', // Migration dosyalarının oluşturulacağı yer
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL || '',
  },
} satisfies Config;
