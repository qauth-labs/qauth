import { Button, Card, CardContent, CardHeader, CardTitle, FormField, Input } from '@qauth-labs/ui';
import { useEffect, useState } from 'react';

import { createApiKeyFn, listApiKeysFn, revokeApiKeyFn } from '../server/actions/api-keys';
import type { ApiKey, ApiKeyWithSecret, OAuthClient } from '../server/auth-server-client';
import { clientErrorMessage } from './client-error';
import { CopyField } from './copy-field';
import { Modal } from './modal';

interface ApiKeysSectionProps {
  /** The client whose keys are managed. `staticApiKeysAllowed` gates the form. */
  client: OAuthClient;
  /** Called when the session has expired so the page can redirect to login. */
  onUnauthenticated: () => void;
}

type LoadState =
  | { status: 'loading' }
  | { status: 'ready'; keys: ApiKey[] }
  | { status: 'error'; message: string };

function formatTimestamp(value: number | null): string {
  if (value === null) return 'Never';
  return new Date(value).toLocaleString();
}

/**
 * API-keys management for a single OAuth client (ADR-008 §6, issue #98).
 *
 * Environment gating: the create form renders ONLY when
 * `client.staticApiKeysAllowed` is true (a `development` client). For a
 * `staging`/`production` client the form is replaced with guidance to use the
 * OAuth `client_credentials` grant. As defense-in-depth, a `403` from the mint
 * endpoint is still handled gracefully (it surfaces the same guidance), so the
 * UI stays correct even if the gate flag is stale.
 *
 * The one-time plaintext key is shown in a non-dismissible reveal modal and is
 * never persisted: it lives only in this component's transient state and is
 * dropped the moment the modal closes. The masked list (prefix…last4) is the
 * only thing rendered afterwards.
 */
export function ApiKeysSection({ client, onUnauthenticated }: ApiKeysSectionProps) {
  const [load, setLoad] = useState<LoadState>({ status: 'loading' });

  // Create form state.
  const [name, setName] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | undefined>(undefined);
  // One-time key from a create; never persisted beyond this modal.
  const [created, setCreated] = useState<ApiKeyWithSecret | null>(null);

  // Revoke state.
  const [confirmRevoke, setConfirmRevoke] = useState<ApiKey | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [revokeError, setRevokeError] = useState<string | undefined>(undefined);

  async function refresh() {
    const result = await listApiKeysFn({ data: { clientId: client.id } });
    if (result.ok) {
      setLoad({ status: 'ready', keys: result.data.apiKeys });
      return;
    }
    if (result.error.code === 'UNAUTHENTICATED') {
      onUnauthenticated();
      return;
    }
    setLoad({ status: 'error', message: clientErrorMessage(result.error) });
  }

  // Reload whenever the client changes. `refresh` closes over `client.id`.
  useEffect(() => {
    void refresh();
  }, [client.id]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (name.trim().length === 0) {
      setCreateError('Name is required.');
      return;
    }
    setCreating(true);
    setCreateError(undefined);
    const result = await createApiKeyFn({ data: { clientId: client.id, name: name.trim() } });
    setCreating(false);
    if (result.ok) {
      setCreated(result.data);
      setName('');
      return;
    }
    if (result.error.code === 'UNAUTHENTICATED') {
      onUnauthenticated();
      return;
    }
    // FORBIDDEN (the environment gate) and any other error map to a clear,
    // non-enumerating message via clientErrorMessage.
    setCreateError(clientErrorMessage(result.error));
  }

  async function handleRevoke() {
    if (!confirmRevoke) return;
    setRevoking(true);
    setRevokeError(undefined);
    const result = await revokeApiKeyFn({
      data: { clientId: client.id, keyId: confirmRevoke.id },
    });
    setRevoking(false);
    if (result.ok) {
      setConfirmRevoke(null);
      void refresh();
      return;
    }
    if (result.error.code === 'UNAUTHENTICATED') {
      onUnauthenticated();
      return;
    }
    setRevokeError(clientErrorMessage(result.error));
  }

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>API keys</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="mb-4 text-sm text-gray-600">
          Static API keys are a development convenience for authenticating this client without the
          full OAuth flow. They are environment-gated: available only for development clients.
        </p>

        {client.staticApiKeysAllowed ? (
          <form onSubmit={(e) => void handleCreate(e)} noValidate className="mb-6 space-y-3">
            {createError ? (
              <p role="alert" className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
                {createError}
              </p>
            ) : null}
            <FormField
              label="Key name"
              htmlFor="api-key-name"
              helperText="A label to recognise this key later."
            >
              <Input
                id="api-key-name"
                name="name"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={creating}
                placeholder="e.g. Local development"
              />
            </FormField>
            <div className="flex justify-end">
              <Button type="submit" disabled={creating}>
                {creating ? 'Creating…' : 'Create API key'}
              </Button>
            </div>
          </form>
        ) : (
          <div
            role="note"
            className="mb-6 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-800"
          >
            <p>
              Static API keys are disabled for <strong>{client.environment}</strong> clients. For
              machine-to-machine access in staging and production, use the OAuth{' '}
              <code className="font-mono">client_credentials</code> grant instead.
            </p>
          </div>
        )}

        {load.status === 'loading' ? <p className="text-sm text-gray-500">Loading keys…</p> : null}

        {load.status === 'error' ? (
          <p role="alert" className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
            {load.message}
          </p>
        ) : null}

        {load.status === 'ready' && load.keys.length === 0 ? (
          <p className="text-sm text-gray-500">No API keys yet.</p>
        ) : null}

        {load.status === 'ready' && load.keys.length > 0 ? (
          <ul className="divide-y divide-gray-100">
            {load.keys.map((key) => {
              const revoked = key.revokedAt !== null;
              return (
                <li key={key.id} className="flex items-start justify-between gap-4 py-3">
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-medium text-gray-800">
                      <span className="truncate">{key.name}</span>
                      {revoked ? (
                        <span className="rounded bg-gray-100 px-1.5 py-0.5 text-xs font-medium text-gray-500">
                          Revoked
                        </span>
                      ) : null}
                    </p>
                    <p className="font-mono text-xs break-all text-gray-500">
                      {key.prefix}…{key.last4}
                    </p>
                    <p className="mt-0.5 text-xs text-gray-500">
                      Created {formatTimestamp(key.createdAt)} · Last used{' '}
                      {formatTimestamp(key.lastUsedAt)}
                    </p>
                  </div>
                  {!revoked ? (
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => {
                        setRevokeError(undefined);
                        setConfirmRevoke(key);
                      }}
                    >
                      Revoke
                    </Button>
                  ) : null}
                </li>
              );
            })}
          </ul>
        ) : null}
      </CardContent>

      {confirmRevoke ? (
        <Modal
          title="Revoke this API key?"
          dismissible={!revoking}
          onClose={() => setConfirmRevoke(null)}
          footer={
            <>
              <Button
                type="button"
                variant="outline"
                disabled={revoking}
                onClick={() => setConfirmRevoke(null)}
              >
                Cancel
              </Button>
              <Button
                type="button"
                className="bg-red-600 hover:bg-red-700"
                disabled={revoking}
                onClick={() => void handleRevoke()}
              >
                {revoking ? 'Revoking…' : 'Revoke key'}
              </Button>
            </>
          }
        >
          <p>
            The key <strong>{confirmRevoke.name}</strong> is invalidated immediately. Any
            integration using it will stop working. This cannot be undone.
          </p>
          {revokeError ? (
            <p role="alert" className="text-sm text-red-700">
              {revokeError}
            </p>
          ) : null}
        </Modal>
      ) : null}

      {created ? (
        <Modal
          title="New API key"
          dismissible={false}
          onClose={() => {
            setCreated(null);
            void refresh();
          }}
          footer={
            <Button
              type="button"
              onClick={() => {
                setCreated(null);
                void refresh();
              }}
            >
              I&apos;ve stored the key
            </Button>
          }
        >
          <div
            role="alert"
            className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-800"
          >
            Copy this key now. For your security, it will <strong>not</strong> be shown again. If
            you lose it you will have to create a new one.
          </div>
          <CopyField label="API key" value={created.key} />
        </Modal>
      ) : null}
    </Card>
  );
}
