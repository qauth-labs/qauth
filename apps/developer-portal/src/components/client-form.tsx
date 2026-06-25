import { Button, FormField, Input } from '@qauth-labs/ui';
import { useState } from 'react';

import type { GrantType, OAuthClient, TokenEndpointAuthMethod } from '../server/auth-server-client';

export interface ClientFormValues {
  name: string;
  description: string;
  redirectUris: string[];
  scopes: string[];
  grantTypes: GrantType[];
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
}

interface ClientFormProps {
  /** Pre-fill values (edit mode). Omit for a blank create form. */
  initial?: Partial<OAuthClient>;
  /** Submit button label. */
  submitLabel: string;
  /** Disable inputs / show a busy state while a request is in flight. */
  busy?: boolean;
  /** Top-level error to display above the form. */
  error?: string;
  /** Hide auth-method selection in edit mode if you don't want to surface it. */
  onSubmit: (values: ClientFormValues) => void;
  onCancel?: () => void;
}

const ALL_GRANTS: { value: GrantType; label: string }[] = [
  { value: 'authorization_code', label: 'Authorization code' },
  { value: 'refresh_token', label: 'Refresh token' },
  { value: 'client_credentials', label: 'Client credentials' },
];

const AUTH_METHODS: { value: TokenEndpointAuthMethod; label: string }[] = [
  { value: 'none', label: 'None (public client + PKCE)' },
  { value: 'client_secret_post', label: 'Client secret (POST body)' },
  { value: 'client_secret_basic', label: 'Client secret (Basic auth)' },
  { value: 'private_key_jwt', label: 'Private key JWT' },
];

/** Split a textarea value into trimmed, non-empty lines. */
export function parseRedirectUris(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Split a space/comma-separated scope string into tokens. */
export function parseScopes(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Shared create/edit form for OAuth clients (#91 create, #94 edit). Redirect
 * URIs are entered one per line; scopes space-separated. Client-side checks
 * are advisory — the auth-server is authoritative and its `400`s are surfaced
 * via the `error` prop.
 */
export function ClientForm({
  initial,
  submitLabel,
  busy = false,
  error,
  onSubmit,
  onCancel,
}: ClientFormProps) {
  const [grantTypes, setGrantTypes] = useState<GrantType[]>(
    initial?.grantTypes ?? ['authorization_code', 'refresh_token']
  );
  const [authMethod, setAuthMethod] = useState<TokenEndpointAuthMethod>(
    initial?.tokenEndpointAuthMethod ?? 'none'
  );
  const [localError, setLocalError] = useState<string | null>(null);

  function toggleGrant(g: GrantType) {
    setGrantTypes((prev) => (prev.includes(g) ? prev.filter((x) => x !== g) : [...prev, g]));
  }

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const name = String(fd.get('name') ?? '').trim();
    const description = String(fd.get('description') ?? '').trim();
    const redirectUris = parseRedirectUris(String(fd.get('redirectUris') ?? ''));
    const scopes = parseScopes(String(fd.get('scopes') ?? ''));

    if (name.length === 0) {
      setLocalError('Name is required.');
      return;
    }
    const userInvolving =
      grantTypes.includes('authorization_code') || grantTypes.includes('refresh_token');
    if (userInvolving && redirectUris.length === 0) {
      setLocalError('At least one redirect URI is required for the authorization code flow.');
      return;
    }
    setLocalError(null);
    onSubmit({
      name,
      description,
      redirectUris,
      scopes,
      grantTypes,
      tokenEndpointAuthMethod: authMethod,
    });
  }

  const shownError = error ?? localError ?? undefined;

  return (
    <form onSubmit={handleSubmit} noValidate className="space-y-5">
      {shownError ? (
        <p role="alert" className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
          {shownError}
        </p>
      ) : null}

      <FormField label="Name" htmlFor="name">
        <Input id="name" name="name" required defaultValue={initial?.name ?? ''} disabled={busy} />
      </FormField>

      <FormField label="Description" htmlFor="description" helperText="Optional.">
        <Input
          id="description"
          name="description"
          defaultValue={initial?.description ?? ''}
          disabled={busy}
        />
      </FormField>

      <FormField
        label="Redirect URIs"
        htmlFor="redirectUris"
        helperText="One per line. Must be https or a loopback address."
      >
        <textarea
          id="redirectUris"
          name="redirectUris"
          rows={3}
          disabled={busy}
          defaultValue={(initial?.redirectUris ?? []).join('\n')}
          className="flex w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none disabled:opacity-50"
        />
      </FormField>

      <FormField label="Scopes" htmlFor="scopes" helperText="Space-separated, e.g. openid profile.">
        <Input
          id="scopes"
          name="scopes"
          defaultValue={(initial?.scopes ?? []).join(' ')}
          disabled={busy}
        />
      </FormField>

      <fieldset className="space-y-2" disabled={busy}>
        <legend className="text-sm font-medium text-gray-700">Grant types</legend>
        {ALL_GRANTS.map((g) => (
          <label key={g.value} className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={grantTypes.includes(g.value)}
              onChange={() => toggleGrant(g.value)}
            />
            {g.label}
          </label>
        ))}
      </fieldset>

      <FormField label="Token endpoint auth method" htmlFor="tokenEndpointAuthMethod">
        <select
          id="tokenEndpointAuthMethod"
          name="tokenEndpointAuthMethod"
          value={authMethod}
          disabled={busy}
          onChange={(e) => setAuthMethod(e.target.value as TokenEndpointAuthMethod)}
          className="flex h-9 w-full rounded-md border border-gray-300 bg-white px-3 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none disabled:opacity-50"
        >
          {AUTH_METHODS.map((m) => (
            <option key={m.value} value={m.value}>
              {m.label}
            </option>
          ))}
        </select>
      </FormField>

      <div className="flex justify-end gap-3">
        {onCancel ? (
          <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
        ) : null}
        <Button type="submit" disabled={busy}>
          {busy ? 'Saving…' : submitLabel}
        </Button>
      </div>
    </form>
  );
}
