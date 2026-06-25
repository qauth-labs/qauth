import { Card, CardContent, CardHeader, CardTitle } from '@qauth-labs/ui';
import { createFileRoute, Link, useRouter } from '@tanstack/react-router';
import { useState } from 'react';

import { clientErrorMessage } from '../../components/client-error';
import { ClientForm, type ClientFormValues } from '../../components/client-form';
import { SecretReveal } from '../../components/secret-reveal';
import { createClientFn } from '../../server/actions/clients';
import type { ClientWithSecret } from '../../server/auth-server-client';

export const Route = createFileRoute('/_authed/clients/new')({
  component: NewClientPage,
});

function NewClientPage() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>(undefined);
  // Holds the one-time secret response. Cleared (and never persisted) once the
  // developer acknowledges the secret display.
  const [created, setCreated] = useState<ClientWithSecret | null>(null);

  async function handleSubmit(values: ClientFormValues) {
    setBusy(true);
    setError(undefined);
    const result = await createClientFn({
      data: {
        name: values.name,
        description: values.description || null,
        redirectUris: values.redirectUris,
        scopes: values.scopes,
        grantTypes: values.grantTypes,
        tokenEndpointAuthMethod: values.tokenEndpointAuthMethod,
      },
    });
    setBusy(false);

    if (result.ok) {
      setCreated(result.data);
      return;
    }
    if (result.error.code === 'UNAUTHENTICATED') {
      await router.navigate({ to: '/login' });
      return;
    }
    setError(clientErrorMessage(result.error));
  }

  async function finishReveal() {
    const id = created?.id;
    setCreated(null);
    if (id) {
      await router.navigate({ to: '/clients/$clientId', params: { clientId: id } });
    } else {
      await router.navigate({ to: '/clients' });
    }
  }

  return (
    <main className="mx-auto max-w-2xl px-6 py-10">
      <div className="mb-6">
        <Link to="/clients" className="text-sm text-blue-600 hover:underline">
          ← Back to clients
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>New OAuth client</CardTitle>
        </CardHeader>
        <CardContent>
          <ClientForm
            submitLabel="Create client"
            busy={busy}
            error={error}
            onSubmit={(v) => void handleSubmit(v)}
            onCancel={() => void router.navigate({ to: '/clients' })}
          />
        </CardContent>
      </Card>

      {created ? (
        <SecretReveal
          title="Client created"
          clientId={created.clientId}
          clientSecret={created.clientSecret}
          onDone={() => void finishReveal()}
        />
      ) : null}
    </main>
  );
}
