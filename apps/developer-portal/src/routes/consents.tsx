import { createFileRoute } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

/**
 * Developer-portal consent revocation screen (issue #150, acceptance
 * criterion 6: "Revocation UI in developer portal").
 *
 * Minimal by design — the scope guidance was list + revoke button, no
 * polish. A user lands here from account settings, sees the apps they
 * have authorized, and can take back any grant. Revoking a row forces a
 * fresh consent prompt the next time the app tries /oauth/authorize
 * (because `findActive` will return undefined).
 *
 * Uses `credentials: 'include'` so the browser sends the
 * __Host-qauth_session cookie to the auth-server even on cross-origin
 * deployments. The auth-server checks ownership on each call; the UI is
 * not a trust boundary.
 */

export const Route = createFileRoute('/consents')({
  component: ConsentsPage,
});

interface ConsentRow {
  id: string;
  clientId: string;
  clientName: string;
  scopes: string[];
  grantedAt: number;
}

const AUTH_SERVER_URL =
  (typeof import.meta !== 'undefined' &&
    (import.meta as ImportMeta & { env?: { VITE_AUTH_SERVER_URL?: string } }).env
      ?.VITE_AUTH_SERVER_URL) ||
  '';

function ConsentsPage() {
  const [rows, setRows] = useState<ConsentRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function load() {
    try {
      const res = await fetch(`${AUTH_SERVER_URL}/consents`, {
        credentials: 'include',
      });
      if (res.status === 401) {
        setError('Please sign in to manage authorized applications.');
        setRows([]);
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as { consents: ConsentRow[] };
      setRows(body.consents);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load consents');
      setRows([]);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function revoke(id: string) {
    setBusy(id);
    try {
      const res = await fetch(`${AUTH_SERVER_URL}/consents/${id}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      if (!res.ok && res.status !== 204) {
        throw new Error(`HTTP ${res.status}`);
      }
      // Optimistic — drop the row immediately.
      setRows((current) => (current ?? []).filter((r) => r.id !== id));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to revoke consent');
    } finally {
      setBusy(null);
    }
  }

  return (
    <main style={{ maxWidth: 720, margin: '32px auto', padding: '0 16px' }}>
      <h1>Authorized applications</h1>
      <p style={{ color: '#555' }}>
        These applications can access your account. Revoking a grant forces the app to ask for
        permission again next time it tries to sign you in.
      </p>

      {error ? (
        <div
          role="alert"
          style={{
            background: '#fdecea',
            color: '#a1261b',
            padding: '10px 12px',
            borderRadius: 6,
            marginBottom: 16,
          }}
        >
          {error}
        </div>
      ) : null}

      {rows === null ? <p>Loading…</p> : null}

      {rows && rows.length === 0 && !error ? (
        <p>You have not authorized any applications yet.</p>
      ) : null}

      {rows && rows.length > 0 ? (
        <ul style={{ listStyle: 'none', padding: 0 }}>
          {rows.map((r) => (
            <li
              key={r.id}
              style={{
                border: '1px solid #e1e3ea',
                borderRadius: 8,
                padding: 16,
                marginBottom: 12,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <div style={{ fontWeight: 600 }}>{r.clientName}</div>
                <div style={{ color: '#555', fontSize: 13 }}>
                  <code>{r.clientId}</code> · granted {new Date(r.grantedAt).toLocaleString()}
                </div>
                <div style={{ color: '#555', fontSize: 13, marginTop: 4 }}>
                  Scopes: {r.scopes.length ? r.scopes.join(', ') : '(none)'}
                </div>
              </div>
              <button
                type="button"
                disabled={busy === r.id}
                onClick={() => void revoke(r.id)}
                style={{
                  background: '#e9ecf2',
                  border: 0,
                  padding: '8px 14px',
                  borderRadius: 6,
                  cursor: 'pointer',
                }}
              >
                {busy === r.id ? 'Revoking…' : 'Revoke'}
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </main>
  );
}
