import { verify } from '@node-rs/argon2';
import pg from 'pg';

/**
 * The two things the upgrade test does in the database, because no release
 * offers them over HTTP:
 *
 * - mark a client `development`, the operator step static API keys need
 *   (ADR-008 §6; the docs site's `operate/environment-authorization` page);
 * - check a stored API key against its plaintext. No release has a route that
 *   authenticates with an API key, so this reads the row the server's own
 *   `authenticateApiKey` reads and runs the same argon2id verification.
 *
 * Only columns every release since the first baseline has are named here.
 */

async function withClient<T>(
  databaseUrl: string,
  run: (client: pg.Client) => Promise<T>
): Promise<T> {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    return await run(client);
  } finally {
    await client.end();
  }
}

/**
 * Let one client mint static API keys: its realm's ceiling and the client
 * itself become `development`. The ceiling only caps how lax a client may be,
 * so every other client of the realm keeps its own (production) posture.
 */
export async function markClientDevelopment(
  databaseUrl: string,
  clientRowId: string
): Promise<void> {
  await withClient(databaseUrl, async (client) => {
    const updated = await client.query(
      `UPDATE oauth_clients SET environment = 'development' WHERE id = $1 RETURNING realm_id`,
      [clientRowId]
    );
    if (updated.rowCount !== 1) {
      throw new Error(`No oauth_clients row ${clientRowId} to mark development.`);
    }
    await client.query(`UPDATE realms SET max_environment_laxity = 'development' WHERE id = $1`, [
      updated.rows[0].realm_id,
    ]);
  });
}

/** What the database holds for an API key, and whether its plaintext still verifies. */
export interface StoredApiKey {
  readonly id: string;
  readonly clientRowId: string;
  readonly revoked: boolean;
  readonly verifies: boolean;
}

/**
 * Look an API key up by its public prefix and verify the full plaintext
 * against the stored argon2id hash, as the server does.
 *
 * @returns the row's state, or null when no row has the prefix
 */
export async function storedApiKey(databaseUrl: string, key: string): Promise<StoredApiKey | null> {
  const prefix = /^(qauth_[0-9a-f]{16})_[0-9a-f]+$/.exec(key)?.[1];
  if (!prefix) {
    throw new Error('The API key is not of the form qauth_<16 hex>_<secret>.');
  }
  return withClient(databaseUrl, async (client) => {
    const result = await client.query(
      'SELECT id, client_id, key_hash, revoked_at FROM api_keys WHERE prefix = $1',
      [prefix]
    );
    if (result.rowCount === 0) return null;
    const row = result.rows[0] as {
      id: string;
      client_id: string;
      key_hash: string;
      revoked_at: unknown;
    };
    return {
      id: row.id,
      clientRowId: row.client_id,
      revoked: row.revoked_at !== null,
      verifies: await verify(row.key_hash, key),
    };
  });
}
