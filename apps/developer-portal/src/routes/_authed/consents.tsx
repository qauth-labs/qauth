import { Button, Card, CardContent } from '@qauth-labs/ui';
import { createFileRoute, useRouter } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

import { clientErrorMessage } from '../../components/client-error';
import { listConsentsFn, revokeConsentFn } from '../../server/actions/consents';
import type { Consent } from '../../server/auth-server-client';

/**
 * Consent revocation screen (issue #150 AC 6; repaired by issue #366).
 *
 * A developer lands here from the header, sees the applications they have
 * authorized, and can take back any grant. Revoking forces a fresh consent
 * prompt the next time that app hits `/oauth/authorize`.
 *
 * This page used to be the portal's ONE exception to its own architecture: it
 * called the auth-server directly from the browser with
 * `credentials: 'include'`, expecting a `__Host-qauth_session` cookie that a
 * portal-authenticated developer never has — and that `SameSite=Lax` would not
 * have attached to a cross-origin `fetch()` anyway, behind a production CORS
 * policy that resolves `origin` to `false`. It returned 401 for its only
 * intended user. It now goes through server functions like every other portal
 * feature, so the access token stays on the server. Do not reintroduce a
 * browser-side `fetch()` here; `consents.test.tsx` fails if you do.
 */
export const Route = createFileRoute('/_authed/consents')({
  component: ConsentsPage,
});

type State =
  | { status: 'loading' }
  | { status: 'ready'; consents: Consent[] }
  | { status: 'error'; message: string };

function ConsentsPage() {
  const router = useRouter();
  const [state, setState] = useState<State>({ status: 'loading' });
  const [busy, setBusy] = useState<string | null>(null);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  async function load() {
    setState({ status: 'loading' });
    const result = await listConsentsFn();
    if (result.ok) {
      setState({ status: 'ready', consents: result.data.consents });
      return;
    }
    if (result.error.code === 'UNAUTHENTICATED') {
      await router.navigate({ to: '/login' });
      return;
    }
    setState({ status: 'error', message: clientErrorMessage(result.error) });
  }

  useEffect(() => {
    void load();
  }, []);

  async function revoke(id: string) {
    setBusy(id);
    setRevokeError(null);
    const result = await revokeConsentFn({ data: { id } });
    setBusy(null);

    if (!result.ok) {
      if (result.error.code === 'UNAUTHENTICATED') {
        await router.navigate({ to: '/login' });
        return;
      }
      // Not optimistic: the row is only dropped once the server confirms the
      // revocation. Removing it first would tell the developer a grant is gone
      // when it may still be live, which is the wrong way round for a
      // security control.
      setRevokeError(clientErrorMessage(result.error));
      return;
    }

    setState((current) =>
      current.status === 'ready'
        ? { status: 'ready', consents: current.consents.filter((c) => c.id !== id) }
        : current
    );
  }

  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-900">Authorized applications</h1>
        <p className="mt-2 text-sm text-gray-600">
          These applications can access your account. Revoking a grant forces the app to ask for
          permission again next time it tries to sign you in.
        </p>
      </div>

      {state.status === 'loading' ? <p className="text-sm text-gray-500">Loading…</p> : null}

      {state.status === 'error' ? (
        <p role="alert" className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
          {state.message}
        </p>
      ) : null}

      {revokeError ? (
        <p role="alert" className="mb-4 rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
          {revokeError}
        </p>
      ) : null}

      {state.status === 'ready' && state.consents.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-sm text-gray-600">You have not authorized any applications yet.</p>
          </CardContent>
        </Card>
      ) : null}

      {state.status === 'ready' && state.consents.length > 0 ? (
        <ul className="space-y-3">
          {state.consents.map((consent) => (
            <li key={consent.id}>
              <Card>
                <CardContent className="flex items-center justify-between gap-4 py-4">
                  <div className="min-w-0">
                    <div className="font-medium text-gray-900">{consent.clientName}</div>
                    <div className="mt-1 truncate text-sm text-gray-500">
                      <code>{consent.clientId}</code> · granted{' '}
                      {new Date(consent.grantedAt).toLocaleString()}
                    </div>
                    <div className="mt-1 text-sm text-gray-500">
                      Scopes: {consent.scopes.length ? consent.scopes.join(', ') : '(none)'}
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    disabled={busy === consent.id}
                    onClick={() => void revoke(consent.id)}
                  >
                    {busy === consent.id ? 'Revoking…' : 'Revoke'}
                  </Button>
                </CardContent>
              </Card>
            </li>
          ))}
        </ul>
      ) : null}
    </main>
  );
}
