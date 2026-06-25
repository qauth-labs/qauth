import { Button, Card, CardContent, CardHeader, CardTitle } from '@qauth-labs/ui';
import { createFileRoute, Link, useRouter } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

import { clientErrorMessage } from '../../components/client-error';
import { listClientsFn } from '../../server/actions/clients';
import type { OAuthClient } from '../../server/auth-server-client';

export const Route = createFileRoute('/_authed/clients/')({
  component: ClientListPage,
});

type State =
  | { status: 'loading' }
  | { status: 'ready'; clients: OAuthClient[] }
  | { status: 'error'; message: string };

function ClientListPage() {
  const router = useRouter();
  const [state, setState] = useState<State>({ status: 'loading' });

  async function load() {
    setState({ status: 'loading' });
    const result = await listClientsFn();
    if (result.ok) {
      setState({ status: 'ready', clients: result.data.clients });
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

  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <div className="mb-8 flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-gray-900">OAuth Clients</h1>
        <Link to="/clients/new">
          <Button type="button">New client</Button>
        </Link>
      </div>

      {state.status === 'loading' ? <p className="text-sm text-gray-500">Loading…</p> : null}

      {state.status === 'error' ? (
        <p role="alert" className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
          {state.message}
        </p>
      ) : null}

      {state.status === 'ready' && state.clients.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-sm text-gray-600">You don&apos;t have any OAuth clients yet.</p>
            <Link to="/clients/new" className="mt-4 inline-block">
              <Button type="button">Create your first client</Button>
            </Link>
          </CardContent>
        </Card>
      ) : null}

      {state.status === 'ready' && state.clients.length > 0 ? (
        <ul className="space-y-3">
          {state.clients.map((c) => (
            <li key={c.id}>
              <Link to="/clients/$clientId" params={{ clientId: c.id }} className="block">
                <Card className="transition-colors hover:border-blue-400">
                  <CardHeader className="flex-row items-center justify-between space-y-0">
                    <div>
                      <CardTitle>{c.name}</CardTitle>
                      <code className="text-xs text-gray-500">{c.clientId}</code>
                    </div>
                    <div className="text-right text-xs text-gray-500">
                      <span
                        className={
                          c.enabled
                            ? 'rounded-full bg-green-100 px-2 py-0.5 text-green-700'
                            : 'rounded-full bg-gray-100 px-2 py-0.5 text-gray-600'
                        }
                      >
                        {c.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                      <div className="mt-1">{c.redirectUris.length} redirect URI(s)</div>
                    </div>
                  </CardHeader>
                </Card>
              </Link>
            </li>
          ))}
        </ul>
      ) : null}
    </main>
  );
}
