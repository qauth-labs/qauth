# @qauth-labs/plugin-apple

> **Experimental.** It implements the experimental AuthMethod plugin contract
> (`qauth-auth-method/1-rc.0`), which may still change in a minor release.

Sign in with Apple for QAuth (#671): a preset plugin on the generic upstream OpenID Connect client
(`@qauth-labs/server-upstream-oidc`), for Apple's provider. A realm's admin sets the Services ID;
the endpoints, the scopes, the client secret and the claim mapping are the plugin's.

The package is on the auth server's first-party list, so it loads whatever `PLUGIN_API_ENABLED`
says once the operator names it:

```sh
AUTH_METHOD_PLUGINS=@qauth-labs/plugin-apple
```

| What                  | Value                                                          |
| --------------------- | -------------------------------------------------------------- |
| AuthMethod id, type   | `apple`, `apple`                                               |
| Issuer                | `https://appleid.apple.com`, by discovery                      |
| Scopes                | `openid name email`                                            |
| Response mode         | `form_post`                                                    |
| Client authentication | a client secret the signer role signs (`signed_client_secret`) |
| ID token algorithms   | `RS256`                                                        |
| Origins it calls      | `appleid.apple.com` (https)                                    |

Every call goes through the egress client the plugin's context hands it, and only to that origin.

## The client secret

Apple takes a JWT as the client secret. **The plugin holds no key**: for each token request the
signer role signs one with the realm's `upstream_client_assertion` key for the type `apple`
(ADR-019 Decision 9):

- header: `alg` `ES256`, `kid` the key's id;
- claims: `iss` the developer team's Team ID, `sub` the Services ID, `aud`
  `https://appleid.apple.com`, a fresh `jti`, `iat` now and `exp` 60 seconds later (Apple allows
  up to six months; the plugin never asks for more than a minute).

The Team ID and the Services ID come from the signer's configuration of the provider, never from
the plugin, so a plugin cannot sign a secret for another team. The key must be the one registered
at Apple, under the Key ID Apple gave it.

**Status:** the signer cannot yet take a key created at Apple, and the deployed signer has no
configuration of a plugin's provider (Team ID, Services ID). Until both exist, a sign-in with this
plugin fails at the code exchange on a real deployment; the tests run it against a test signer
that has both.

## The response, the name and the address

- **`form_post`.** Apple posts the response cross-site. The plugin's `POST /callback` bounces the
  browser to its `GET /callback` on the realm host, so it brings the flow cookie.
- **The name arrives once**, in the `user` member of the first authorization's response, never in
  the ID token. The bounce carries only the first and last name on (never the address Apple
  repeats there; the ID token's is the one read), and they become the new account's `given_name`
  and `family_name`, unverified: the browser chooses that member. A later sign-in carries no name,
  and the sign-in flow stores a provider's attributes only when it creates the account, so the
  name is never overwritten.
- **A private relay address** (`is_private_email`, or an address at `privaterelay.appleid.com`)
  forwards mail only from senders the developer team registered with Apple's private email relay
  service. Unless the realm's config says it did (`privateRelayReceivesMail`), the plugin keeps the
  address as the `private_relay_email` attribute in place of `email`, so it is never the address
  QAuth mails.

## Register the Services ID

Create a Services ID with Sign in with Apple enabled, and register one return URL per realm:

```text
https://<realm host>/upstream/apple/callback
```

`appleRedirectUri(realmOrigin)` builds it. Create a Sign in with Apple key for the team.

## Config

```json
{ "clientId": "com.example.signin", "privateRelayReceivesMail": false }
```

- `clientId`: the Services ID, 1 to 255 characters: the `client_id` of every request and the ID
  tokens' audience. It must be the Services ID the signer's configuration names.
- `privateRelayReceivesMail`: whether the team registered the realm's mail domains with the
  private email relay service. Default `false`.

The config holds no secret. Configure it with `plugins.update` and turn it on with
`plugins.enable`, under `/admin/v1-rc.0/realms/{realmId}/plugins/apple`.

## Attributes

| Attribute             | From                            | Verified                                      |
| --------------------- | ------------------------------- | --------------------------------------------- |
| `email`               | the ID token's `email`          | only when `email_verified` is `true`/`"true"` |
| `private_relay_email` | a relay address, by default     | never                                         |
| `given_name`          | the `user` member's `firstName` | never                                         |
| `family_name`         | the `user` member's `lastName`  | never                                         |

The plugin carries no logo: the sign-in page shows the provider's name, `Apple`.

## Not yet

- Apple answers a cancelled sign-in with `user_cancelled_authorize`, which ends as a failed
  sign-in, not a declined one.
- Validated against a mock provider only, not against Apple itself.
