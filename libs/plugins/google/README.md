# @qauth-labs/plugin-google

> **Experimental.** It implements the experimental AuthMethod plugin contract
> (`qauth-auth-method/1-rc.0`), which may still change in a minor release.

Sign in with Google for QAuth (#671): a preset plugin on the generic upstream OpenID Connect client
(`@qauth-labs/server-upstream-oidc`), for Google's OpenID Provider. A realm's admin sets the OAuth
client, nothing else: the issuer, the endpoints, the scopes and the claim mapping are the plugin's.

The package is on the auth server's first-party list, so it loads whatever `PLUGIN_API_ENABLED`
says once the operator names it:

```sh
AUTH_METHOD_PLUGINS=@qauth-labs/plugin-google
```

| What                  | Value                                                        |
| --------------------- | ------------------------------------------------------------ |
| AuthMethod id, type   | `google`, `google`                                           |
| Issuer                | `https://accounts.google.com`, by discovery                  |
| Scopes                | `openid email profile`                                       |
| Client authentication | `client_secret_post`                                         |
| ID token algorithms   | `RS256`                                                      |
| Origins it calls      | `accounts.google.com`, `oauth2.googleapis.com`,              |
|                       | `www.googleapis.com`, `openidconnect.googleapis.com` (https) |

Every call goes through the egress client the plugin's context hands it, and only to those
origins: a discovery document that names an endpoint elsewhere is refused. The plugin holds no key.

## Register the client at Google

Create an OAuth client of the type "Web application" in the Google Cloud console, and register
one redirect URI per realm:

```text
https://<realm host>/upstream/google/callback
```

`googleRedirectUri(realmOrigin)` builds it.

## Config

```json
{ "clientId": "1234-abc.apps.googleusercontent.com", "clientSecret": "GOCSPX-…" }
```

- `clientId`: the OAuth client id, 1 to 255 characters.
- `clientSecret`: the client secret, 1 to 1024 characters. Write-only: the admin API takes it
  sealed (`secrets.seal`), stores it encrypted under the plugin's own context and never returns it.

No other member is accepted. Configure it with `plugins.update` and turn it on with
`plugins.enable`, under `/admin/v1-rc.0/realms/{realmId}/plugins/google`.

## Attributes

| Attribute     | From the claim | Verified                                         |
| ------------- | -------------- | ------------------------------------------------ |
| `email`       | `email`        | only when `email_verified` is the boolean `true` |
| `name`        | `name`         | never                                            |
| `given_name`  | `given_name`   | never                                            |
| `family_name` | `family_name`  | never                                            |
| `locale`      | `locale`       | never                                            |
| `hd`          | `hd`           | never                                            |

`hd`, the Google Workspace domain of the account, is kept as an attribute and nothing more: the
plugin does not restrict who signs in by it. The upstream sign-in flow stores the attributes when it
creates the account, under the source `google`.

## Not yet

- No icon: the sign-in page shows the name `Google`.
- Validated against a mock provider only, not against Google itself.
