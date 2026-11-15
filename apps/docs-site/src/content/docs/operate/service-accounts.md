---
title: Service accounts
description: Create a service account for the admin API, sign it in with client_credentials, private_key_jwt and a DPoP proof, have a human approve its security operations, and disable it.
sidebar:
  order: 16
lastVerified: '2026-11-15'
---

A **service account** is automation that calls the admin API as itself: a
CI job that imports a realm file, a relying party that closes the accounts
it owns. It lives in the operator realm
([Topology](/operate/topology/#the-operator-realm)) and is two things:

- an account, a user with no credential, which signs in nowhere. Its admin
  grants attach to this account, as a person's do, and the admin API reads
  them on every call;
- the OAuth client it signs in with. The client authenticates with
  `private_key_jwt` only, has the `client_credentials` grant only, and every
  token it gets is bound to a DPoP key.

There are no static admin keys. A service account holds a private key whose
public half its client lists, and it signs a short assertion for each token
request. Its token lives at most 15 minutes, comes with no refresh token, and
is no use without the DPoP key it is bound to.

## Create one

Run the `service-accounts` command on a host that holds the database
credentials, with `DATABASE_URL` naming a role that may write users, OAuth
clients, service accounts, admin grants and the admin audit log: the owner's,
not one service role's in a split deployment
([Service roles](/operate/service-roles/)). Give it the account's name, its
client's `client_id`, the client's public keys, and the built-in admin roles
it holds:

```console
pnpm nx run auth-server:service-accounts -- create \
  --name ci-realm-import \
  --client-id ci-realm-import \
  --jwks-uri https://ci.example.com/.well-known/jwks.json \
  --grant security-admin@*
# In the auth-server image, from /app:
tsx src/service-accounts.ts create --name ci-realm-import --client-id ci-realm-import \
  --jwks /etc/qauth/ci-realm-import.jwks.json --grant viewer@master
```

| Flag          | What it sets                                                                                                  |
| ------------- | ------------------------------------------------------------------------------------------------------------- |
| `--name`      | Lower-case words joined by hyphens, unique in the operator realm.                                             |
| `--client-id` | The `client_id` the client's assertions name: no client's in the operator realm, and not the system client's. |
| `--jwks`      | A file holding the client's public JWK Set, `{"keys": [...]}`. A key with a private member is refused.        |
| `--jwks-uri`  | An https URL that serves the client's public JWK Set. Give this or `--jwks`, not both.                        |
| `--grant`     | `viewer`, `editor` or `security-admin`, on the realm named after `@`, or on every realm with `@*`. Repeat it. |

The command writes everything in one transaction: the account, its client,
the service account, its grants, and one row of the operator realm's admin
audit log, `serviceAccounts.create`, with the actor kind `host_operator` and
the operating-system user that ran it. Creating a service account is a
security operation, and the host stands outside the approval rule, as the
break-glass command does. It makes no secret and prints none. A service
account with no grant gets no admin token.

Make the key pair where the automation runs, and give the server only its
public half. Any asymmetric algorithm the server's discovery document lists
under `token_endpoint_auth_signing_alg_values_supported` works; an EC P-256
key with `ES256` is a good default. To rotate the key, publish the new key
beside the old one at the `--jwks-uri`, switch the automation to it, then
remove the old one.

`list` shows the operator realm's service accounts; `disable --name <name>`
and `enable --name <name>` switch one.

## Get a token

The service account asks the token endpoint of the operator realm's issuer
for a `client_credentials` token, with a client assertion (RFC 7523) and a
DPoP proof (RFC 9449):

```http
POST /oauth/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: <proof for POST https://auth.example.com/oauth/token>

grant_type=client_credentials
&client_id=ci-realm-import
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<assertion>
&scope=qauth:admin:read qauth:admin:security
&resource=urn:qauth:aud:admin:v1-rc.0
```

- The assertion's `iss` and `sub` are the `client_id`, its `aud` the realm's
  issuer and nothing else, with a fresh `jti`, and it lives at most five
  minutes.
- The answer is a `DPoP` token for the admin API's audience alone. Its `sub`
  is the service account's user id, not the `client_id`; its `client_id` is
  the client's. It carries the admin scopes the account's grants reach, out
  of those asked for.
- It lives the realm's admin token lifetime, the realm policy
  `tokens.adminAccessTokenLifespanSeconds`, at most 900 seconds, and comes
  with no refresh token: ask again when it expires.
- A request without a DPoP proof is refused (`invalid_dpop_proof`), and so
  is any audience but the admin API's (`invalid_target`).

Call the admin API with the token under the `DPoP` scheme and a fresh proof
for each call, as a person's admin console does
([API conventions](/reference/api-conventions/)).

## Security operations need a human

A service account has no passkey, so it never approves a security
operation, and it never counts as one of two admins. It files the request,
and a human admin approves it:

1. It calls the operation, and is answered `403` `approval_required`.
2. It files an approval with the same operation, path parameters, query and
   body (`POST /admin/v1-rc.0/realms/<realm id>/approvals`). The approval's
   `requester.kind` is `service_account`, and the answer carries the
   approval page's URL.
3. A human admin who may approve on that realm opens the page and approves
   with a fresh passkey. Where the realm makes a second admin mandatory for
   the operation, a second, different human admin approves too. The two-admin
   rule's other conditions apply to each of them: the right to approve held
   before the request, and no new account, grant or credential change in the
   7 days before it.
4. The service account reads its approval, and once it is `approved`,
   repeats the call with `QAuth-Approval: <approval id>`.

Where no human admin could approve, the filing fails closed with `409`
`approval_unavailable`, whatever grants the service account holds.

## Disable a service account

```console
pnpm nx run auth-server:service-accounts -- disable --name ci-realm-import
```

A disabled service account gets no token (`invalid_client`), and a token it
already holds makes no admin call from the next request on. Disabling it
disables its account too, which ends every token issued to it so far: `enable`
turns it on again, and a token issued before the disable stays refused, so the
automation asks for a new one. So do a service account whose account is
disabled, whose client is disabled or suspended (`db:suspend-oauth-client`, or
the admin API's `clients.disable`, which also ends every admin token it holds),
and one whose client was changed to authenticate any other way than
`private_key_jwt`. Removing a grant takes what it gave from the next call, as
for a person.

A service account's client is not deleted while the service account binds it:
the admin API's `clients.delete` answers `409`, and the database refuses the
deletion from anywhere else. There is no removal of a service account yet, so
disable it. Being a service account is a lasting fact of its account, which a
later change never clears: an account so marked whose binding is gone gets no
token and makes no admin call, and is never taken for a person's.

Each `disable` and `enable` writes one row of the operator realm's admin audit
log in the transaction of the switch, `serviceAccounts.disable` or
`serviceAccounts.enable`, with the actor kind `host_operator` and the
operating-system user, as a creation does. A run that finds the service
account switched already is recorded too, with no change.

## What the logs show

- Each admin call's audit row names the actor kind `service_account`, its
  user id and the operator realm.
- The host command's rows, `serviceAccounts.create`, `serviceAccounts.disable`
  and `serviceAccounts.enable`, name the actor kind `host_operator` and the
  operating-system user.
- Its approvals' requester is the service account; each approval names the
  human who gave it, with the actor kind `human_admin`.
- The events its operations record, such as `user.verified`, name it as the
  `client` acting for itself, by its `client_id`.
- A refused token request records `token.request_failed` with a reason:
  `service_account_disabled`, `service_account_account_inactive`,
  `service_account_client_not_private_key_jwt`,
  `service_account_realm_not_operator` or
  `service_account_admin_audience_only`.

## No long-lived admin credential

No path stores or takes an admin credential that outlives a few minutes:

- The admin API's audience, and an admin scope, are issued only to a client
  that authenticates with `private_key_jwt`, on every grant. A client that
  authenticates with a secret, or a public client, is refused the admin
  audience (`invalid_target`) whatever its `audience` lists, and the seed
  manifest refuses such an entry. An admin console that signs people in is
  such a client too.
- A static developer API key never carries the admin audience: none is
  minted for a client that lists it, one minted earlier authenticates
  nothing, and the admin listener takes a DPoP-bound access token only.
- `client_credentials` issues no refresh token, and an admin token lives at
  most 900 seconds.

## See also

- [Topology](/operate/topology/#the-operator-realm) — the operator realm.
- [Upgrades](/operate/upgrades/#service-accounts-and-the-admin-audience-needs-private_key_jwt)
  — migration 0078, its grants, and the `private_key_jwt` rule.
- [Security operations](/reference/security-operations/) — which admin
  operations need an approval.
