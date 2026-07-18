# Code Examples

Copy-paste-ready client code for QAuth. All snippets target a local instance at
`http://localhost:3000` (your `JWT_ISSUER`); override with an env var for other
environments. See the [API Reference](./api-reference.md) for full endpoint
contracts and the [OAuth 2.1 Flow](./oauth-flow.md) for the protocol details.

> **Never hard-code secrets.** Client secrets and passwords below are read from
> environment variables. Public clients (SPA / native / CLI) hold no secret and
> authenticate with PKCE instead.

---

## Node.js / TypeScript

Requires **Node 20+** (global `fetch`). Run any snippet with
`npx tsx example.ts`.

### 1. First-party: register → login → call a protected endpoint

Mirrors the [first-party auth endpoints](./api-reference.md#first-party-authentication):
create a user, log in for tokens, then call a Bearer-protected endpoint
(`GET /api/clients`).

```ts
// first-party.ts
const QAUTH = process.env.QAUTH_URL ?? 'http://localhost:3000';
const email = process.env.QAUTH_EMAIL ?? 'dev@example.com';
const password = process.env.QAUTH_PASSWORD ?? 'corr3ct-h0rse-batt3ry'; // demo only

async function post(path: string, body: unknown, token?: string) {
  const res = await fetch(`${QAUTH}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${path} → ${res.status}: ${JSON.stringify(json)}`);
  return json as any;
}

async function main() {
  // 1. Register (idempotent-ish: ignore 409 if the user already exists).
  try {
    const user = await post('/auth/register', { email, password });
    console.log('registered:', user.id, user.email);
  } catch (err) {
    if (!String(err).includes('409')) throw err;
    console.log('user already exists, continuing');
  }

  // 2. Log in → tokens.
  const { access_token, refresh_token, expires_in } = await post('/auth/login', {
    email,
    password,
  });
  console.log(`logged in; access token expires in ${expires_in}s`);

  // 3. Call a protected endpoint with the bearer token.
  const res = await fetch(`${QAUTH}/api/clients`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  const data = await res.json();
  console.log(`GET /api/clients → ${res.status}`, data); // { clients: [] } for a new user

  // 4. (Later) renew the access token without re-prompting:
  const renewed = await fetch(`${QAUTH}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token }),
  }).then((r) => r.json());
  console.log('refreshed access token:', renewed.access_token?.slice(0, 12), '…');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
```

### 2. Machine-to-machine: `client_credentials` → call a resource

For service clients (no user). The token is audience-bound (RFC 8707) and useless
at any other resource server. Provision the client with the `seed-oauth-clients`
script so it has the right `scopes` + `audience` (see the
[MCP Quickstart](./mcp-quickstart.md#option-b--verify-the-handshake-with-curl-no-browser)).

```ts
// machine.ts
const QAUTH = process.env.QAUTH_URL ?? 'http://localhost:3000';
const RESOURCE = process.env.MCP_RESOURCE ?? 'http://localhost:8088';
const clientId = process.env.CLIENT_ID!; // e.g. "memory-mcp-demo"
const clientSecret = process.env.CLIENT_SECRET!; // from the seed script output

async function getToken(scope: string): Promise<string> {
  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const res = await fetch(`${QAUTH}/oauth/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${basic}`, // client_secret_basic
    },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope,
      resource: RESOURCE, // binds the token `aud` to this resource
    }),
  });
  if (!res.ok) throw new Error(`token → ${res.status}: ${await res.text()}`);
  const { access_token } = await res.json();
  return access_token;
}

async function main() {
  const token = await getToken('mcp:read');
  const res = await fetch(`${RESOURCE}/mcp/memory`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  console.log(`GET ${RESOURCE}/mcp/memory → ${res.status}`, await res.json());
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
```

```bash
CLIENT_ID=memory-mcp-demo CLIENT_SECRET=<from seed output> npx tsx machine.ts
```

---

## Browser / JavaScript — Authorization Code + PKCE

A public SPA client (no secret) using the Web Crypto API for PKCE. Register the
client first with `token_endpoint_auth_method: "none"` and your `redirect_uri`
(see the [OAuth Flow, step 0](./oauth-flow.md#0-prerequisites--a-client)).

```js
// auth.js — drop into a SPA; serves the redirect at /callback
const QAUTH = 'http://localhost:3000';
const CLIENT_ID = 'YOUR_PUBLIC_CLIENT_ID';
const REDIRECT_URI = window.location.origin + '/callback';
const SCOPE = 'openid profile email';
const RESOURCE = 'http://localhost:8088'; // optional RFC 8707 audience binding

// --- PKCE helpers (RFC 7636) ---
function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
function randomVerifier() {
  return base64url(crypto.getRandomValues(new Uint8Array(48))); // 64 chars
}
async function challengeFrom(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(digest);
}

// --- 1. Begin login: redirect to /oauth/authorize ---
async function login() {
  const verifier = randomVerifier();
  const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
  sessionStorage.setItem('pkce_verifier', verifier);
  sessionStorage.setItem('oauth_state', state);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code_challenge: await challengeFrom(verifier),
    code_challenge_method: 'S256',
    scope: SCOPE,
    state,
    resource: RESOURCE,
  });
  window.location.assign(`${QAUTH}/oauth/authorize?${params}`);
}

// --- 2. Handle the redirect back at /callback ---
async function handleCallback() {
  const url = new URL(window.location.href);
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');
  if (!code) return; // not a callback

  if (returnedState !== sessionStorage.getItem('oauth_state')) {
    throw new Error('state mismatch — possible CSRF');
  }
  const verifier = sessionStorage.getItem('pkce_verifier');

  const res = await fetch(`${QAUTH}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID, // public client: no secret
      code_verifier: verifier,
      resource: RESOURCE,
    }),
  });
  const tokens = await res.json();
  if (!res.ok) throw new Error(`token → ${res.status}: ${JSON.stringify(tokens)}`);

  sessionStorage.removeItem('pkce_verifier');
  sessionStorage.removeItem('oauth_state');
  return tokens; // { access_token, refresh_token, expires_in, token_type, scope }
}

// --- 3. Call a protected API with the access token ---
async function callApi(accessToken) {
  const res = await fetch(`${QAUTH}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  // { sub, email?, email_verified? } — email claims are OMITTED when the
  // user has no verified email attribute. Always handle absence:
  //   const { sub, email } = await callApi(token);
  //   if (email === undefined) { /* no verified email on record */ }
  return res.json();
}

// Wire up: run handleCallback() on /callback, login() on a button click.
handleCallback().then((tokens) => {
  if (tokens) callApi(tokens.access_token).then((u) => console.log('user:', u));
});
```

> **Security notes.** Always validate `state` on return (CSRF). Keep the
> `code_verifier` out of the URL and in `sessionStorage`. For production SPAs,
> prefer storing tokens in memory and renewing via the
> [`refresh_token` grant](./oauth-flow.md#refresh-token-rotation) over persisting
> long-lived tokens.

---

## See also

- [API Reference](./api-reference.md) — full endpoint contracts.
- [OAuth 2.1 Flow](./oauth-flow.md) — protocol walkthrough with `curl`.
- [`memory-mcp` example](../libs/fastify/plugins/mcp-guard/examples/memory-mcp/server.ts) —
  a runnable resource server protected by `@qauth-labs/mcp-guard`.
