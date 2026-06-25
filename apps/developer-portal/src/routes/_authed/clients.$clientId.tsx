import { Button, Card, CardContent, CardHeader, CardTitle } from '@qauth-labs/ui';
import { createFileRoute, Link, useRouter } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

import { clientErrorMessage } from '../../components/client-error';
import { ClientForm, type ClientFormValues } from '../../components/client-form';
import { CopyField } from '../../components/copy-field';
import { Modal } from '../../components/modal';
import { SecretReveal } from '../../components/secret-reveal';
import {
  deleteClientFn,
  getClientFn,
  regenerateSecretFn,
  updateClientFn,
} from '../../server/actions/clients';
import type { ClientWithSecret, OAuthClient } from '../../server/auth-server-client';

export const Route = createFileRoute('/_authed/clients/$clientId')({
  component: ClientDetailsPage,
});

type LoadState =
  | { status: 'loading' }
  | { status: 'ready'; client: OAuthClient }
  | { status: 'error'; message: string };

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="py-2">
      <dt className="text-xs font-medium tracking-wide text-gray-500 uppercase">{label}</dt>
      <dd className="mt-0.5 text-sm text-gray-800">{children}</dd>
    </div>
  );
}

function ClientDetailsPage() {
  const router = useRouter();
  const { clientId } = Route.useParams();

  const [load, setLoad] = useState<LoadState>({ status: 'loading' });
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | undefined>(undefined);

  // Modal state.
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmRegenerate, setConfirmRegenerate] = useState(false);
  const [actionError, setActionError] = useState<string | undefined>(undefined);
  // One-time secret from a regenerate; never persisted beyond this modal.
  const [regenerated, setRegenerated] = useState<ClientWithSecret | null>(null);

  async function refresh() {
    const result = await getClientFn({ data: { id: clientId } });
    if (result.ok) {
      setLoad({ status: 'ready', client: result.data });
      return;
    }
    if (result.error.code === 'UNAUTHENTICATED') {
      await router.navigate({ to: '/login' });
      return;
    }
    setLoad({ status: 'error', message: clientErrorMessage(result.error) });
  }

  // Reload whenever the route param changes. `refresh` closes over `clientId`,
  // so keying the effect on it is sufficient.
  useEffect(() => {
    void refresh();
  }, [clientId]);

  async function handleSave(values: ClientFormValues) {
    setBusy(true);
    setFormError(undefined);
    const result = await updateClientFn({
      data: {
        id: clientId,
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
      setLoad({ status: 'ready', client: result.data });
      setEditing(false);
      return;
    }
    if (result.error.code === 'UNAUTHENTICATED') {
      await router.navigate({ to: '/login' });
      return;
    }
    setFormError(clientErrorMessage(result.error));
  }

  async function handleDelete() {
    setBusy(true);
    setActionError(undefined);
    const result = await deleteClientFn({ data: { id: clientId } });
    setBusy(false);
    if (result.ok) {
      setConfirmDelete(false);
      await router.navigate({ to: '/clients' });
      return;
    }
    if (result.error.code === 'UNAUTHENTICATED') {
      await router.navigate({ to: '/login' });
      return;
    }
    setActionError(clientErrorMessage(result.error));
  }

  async function handleRegenerate() {
    setBusy(true);
    setActionError(undefined);
    const result = await regenerateSecretFn({ data: { id: clientId } });
    setBusy(false);
    if (result.ok) {
      setConfirmRegenerate(false);
      setRegenerated(result.data);
      return;
    }
    if (result.error.code === 'UNAUTHENTICATED') {
      await router.navigate({ to: '/login' });
      return;
    }
    setActionError(clientErrorMessage(result.error));
  }

  return (
    <main className="mx-auto max-w-2xl px-6 py-10">
      <div className="mb-6">
        <Link to="/clients" className="text-sm text-blue-600 hover:underline">
          ← Back to clients
        </Link>
      </div>

      {load.status === 'loading' ? <p className="text-sm text-gray-500">Loading…</p> : null}

      {load.status === 'error' ? (
        <p role="alert" className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
          {load.message}
        </p>
      ) : null}

      {load.status === 'ready' && !editing ? (
        <Card>
          <CardHeader className="flex-row items-start justify-between space-y-0">
            <CardTitle>{load.client.name}</CardTitle>
            <div className="flex gap-2">
              <Button type="button" variant="outline" onClick={() => setEditing(true)}>
                Edit
              </Button>
              <Button
                type="button"
                className="bg-red-600 hover:bg-red-700"
                onClick={() => {
                  setActionError(undefined);
                  setConfirmDelete(true);
                }}
              >
                Delete
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <dl className="divide-y divide-gray-100">
              <Field label="Client ID">
                <CopyField label="Client ID" value={load.client.clientId} />
              </Field>
              <Field label="Description">{load.client.description ?? '—'}</Field>
              <Field label="Redirect URIs">
                {load.client.redirectUris.length > 0 ? (
                  <ul className="list-disc space-y-0.5 pl-5">
                    {load.client.redirectUris.map((u) => (
                      <li key={u} className="font-mono text-xs break-all">
                        {u}
                      </li>
                    ))}
                  </ul>
                ) : (
                  '—'
                )}
              </Field>
              <Field label="Scopes">
                {load.client.scopes.length > 0 ? load.client.scopes.join(', ') : '—'}
              </Field>
              <Field label="Grant types">{load.client.grantTypes.join(', ')}</Field>
              <Field label="Token endpoint auth method">
                {load.client.tokenEndpointAuthMethod}
              </Field>
              <Field label="Status">{load.client.enabled ? 'Enabled' : 'Disabled'}</Field>
              <Field label="Client secret">
                <div className="flex items-center justify-between gap-4">
                  <span className="text-sm text-gray-500">
                    {load.client.tokenEndpointAuthMethod === 'none'
                      ? 'Public client — no secret.'
                      : 'Hidden. Secrets are shown only once, at creation or regeneration.'}
                  </span>
                  {load.client.tokenEndpointAuthMethod !== 'none' ? (
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => {
                        setActionError(undefined);
                        setConfirmRegenerate(true);
                      }}
                    >
                      Regenerate
                    </Button>
                  ) : null}
                </div>
              </Field>
            </dl>
          </CardContent>
        </Card>
      ) : null}

      {load.status === 'ready' && editing ? (
        <Card>
          <CardHeader>
            <CardTitle>Edit client</CardTitle>
          </CardHeader>
          <CardContent>
            <ClientForm
              initial={load.client}
              submitLabel="Save changes"
              busy={busy}
              error={formError}
              onSubmit={(v) => void handleSave(v)}
              onCancel={() => {
                setFormError(undefined);
                setEditing(false);
              }}
            />
          </CardContent>
        </Card>
      ) : null}

      {confirmDelete ? (
        <Modal
          title="Delete this client?"
          dismissible={!busy}
          onClose={() => setConfirmDelete(false)}
          footer={
            <>
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => setConfirmDelete(false)}
              >
                Cancel
              </Button>
              <Button
                type="button"
                className="bg-red-600 hover:bg-red-700"
                disabled={busy}
                onClick={() => void handleDelete()}
              >
                {busy ? 'Deleting…' : 'Delete client'}
              </Button>
            </>
          }
        >
          <p>
            This permanently deletes the client. It can no longer authenticate or start new
            authorization flows, and any dependent data is removed. This cannot be undone.
          </p>
          {actionError ? (
            <p role="alert" className="text-sm text-red-700">
              {actionError}
            </p>
          ) : null}
        </Modal>
      ) : null}

      {confirmRegenerate ? (
        <Modal
          title="Regenerate client secret?"
          dismissible={!busy}
          onClose={() => setConfirmRegenerate(false)}
          footer={
            <>
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => setConfirmRegenerate(false)}
              >
                Cancel
              </Button>
              <Button type="button" disabled={busy} onClick={() => void handleRegenerate()}>
                {busy ? 'Regenerating…' : 'Regenerate secret'}
              </Button>
            </>
          }
        >
          <p>
            The current secret is invalidated immediately. Existing integrations using the old
            secret will stop working until you update them with the new one.
          </p>
          {actionError ? (
            <p role="alert" className="text-sm text-red-700">
              {actionError}
            </p>
          ) : null}
        </Modal>
      ) : null}

      {regenerated ? (
        <SecretReveal
          title="New client secret"
          clientId={regenerated.clientId}
          clientSecret={regenerated.clientSecret}
          onDone={() => {
            setRegenerated(null);
            void refresh();
          }}
        />
      ) : null}
    </main>
  );
}
