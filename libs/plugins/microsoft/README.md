# @qauth-labs/plugin-microsoft

> **Experimental.** It implements the experimental AuthMethod plugin contract
> (`qauth-auth-method/1-rc.0`), which may still change in a minor release.

Sign in with Microsoft for QAuth (#671): a preset plugin on the generic upstream OpenID Connect
client (`@qauth-labs/server-upstream-oidc`), for the Microsoft identity platform's v2.0 endpoints.
A realm's admin sets the app registration and the tenant; the endpoints, the scopes and the claim
mapping are the plugin's.

The package is on the auth server's first-party list, so it loads whatever `PLUGIN_API_ENABLED`
says once the operator names it:

```sh
AUTH_METHOD_PLUGINS=@qauth-labs/plugin-microsoft
```

| What                  | Value                                                           |
| --------------------- | --------------------------------------------------------------- |
| AuthMethod id, type   | `microsoft`, `microsoft`                                        |
| Issuer                | `https://login.microsoftonline.com/<tenant>/v2.0`, by discovery |
| Scopes                | `openid email profile`                                          |
| Client authentication | `client_secret_post`                                            |
| ID token algorithms   | `RS256`                                                         |
| Origins it calls      | `login.microsoftonline.com`, `graph.microsoft.com` (https)      |

Every call goes through the egress client the plugin's context hands it, and only to those
origins. The plugin holds no key.

## The tenant

- **A tenant id** (a GUID, in lower case): only that tenant's accounts sign in. The issuer is
  `https://login.microsoftonline.com/<tenant id>/v2.0`, and an ID token any other tenant issued is
  refused.
- **`organizations`**: work or school accounts of any tenant. **`common`**: those and personal
  accounts. Their discovery document names the issuer template
  `https://login.microsoftonline.com/{tenantid}/v2.0`, and an ID token is accepted only when its
  `iss` is the template with the token's own `tid` in place: a token whose issuer names one tenant
  and whose `tid` another is refused. Each account's credential keeps its tenant's issuer, so a
  later sign-in with the same `sub` from another tenant is refused too.

A domain name (`contoso.onmicrosoft.com`) is not accepted as the tenant: the v2.0 issuer names the
tenant id, which the plugin compares. Changing the tenant changes the issuer, so the admin API asks
for the client secret again.

## Register the app

Register an application in Microsoft Entra ID, with a client secret, and add one web redirect URI
per realm:

```text
https://<realm host>/upstream/microsoft/callback
```

`microsoftRedirectUri(realmOrigin)` builds it. For the multi-tenant endpoints the app registration
must allow accounts of other tenants.

## Config

```json
{
  "tenant": "organizations",
  "clientId": "6731de76-14a6-49ae-97bc-6eba6914391e",
  "clientSecret": "…"
}
```

- `tenant`: a lower-case tenant id, `organizations` or `common`.
- `clientId`: the application (client) id, 1 to 255 characters.
- `clientSecret`: a client secret, 1 to 1024 characters. Write-only: the admin API takes it sealed
  (`secrets.seal`), stores it encrypted under the plugin's own context and never returns it.

Configure it with `plugins.update` and turn it on with `plugins.enable`, under
`/admin/v1-rc.0/realms/{realmId}/plugins/microsoft`.

## Attributes

| Attribute            | From the claim       | Verified                                   |
| -------------------- | -------------------- | ------------------------------------------ |
| `email`              | `email`              | only when `xms_edov` is the boolean `true` |
| `name`               | `name`               | never                                      |
| `given_name`         | `given_name`         | never                                      |
| `family_name`        | `family_name`        | never                                      |
| `preferred_username` | `preferred_username` | never                                      |
| `tid`                | `tid`                | never                                      |

The `email` claim is a property of the account that its tenant's admins may set to any address,
so it is unverified by default. `xms_edov` (email domain owner verified) is an optional claim: add
it to the app registration's token configuration for verified addresses. `email_verified` is not
read.

## Not yet

- No icon: the sign-in page shows the name `Microsoft`.
- Validated against a mock provider only, not against Microsoft itself.
