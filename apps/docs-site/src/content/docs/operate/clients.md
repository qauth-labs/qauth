---
title: Clients
description: How an admin lists, registers, changes, suspends and deletes any client of a realm through the admin API, and which changes need an approval.
sidebar:
  order: 15
lastVerified: '2026-11-12'
---

The admin API manages every client of a realm, whoever owns it: a
developer's, one the operator provisioned, one that registered itself. The
developer API still lists and changes a developer's own clients only. Every
route below is experimental and lives on the admin listener
([Service roles](/operate/service-roles/)).

| Route                                                        | Operation         | Needs                              |
| ------------------------------------------------------------ | ----------------- | ---------------------------------- |
| `GET /admin/v1-rc.0/realms/<realm id>/clients`               | `clients.list`    | `clients.read`                     |
| `GET /admin/v1-rc.0/realms/<realm id>/clients/<id>`          | `clients.get`     | `clients.read`                     |
| `POST /admin/v1-rc.0/realms/<realm id>/clients`              | `clients.create`  | `clients.security` and an approval |
| `PATCH /admin/v1-rc.0/realms/<realm id>/clients/<id>`        | `clients.update`  | by field, as the table below says  |
| `POST /admin/v1-rc.0/realms/<realm id>/clients/<id>/preview` | `clients.preview` | `clients.read`                     |
| `DELETE /admin/v1-rc.0/realms/<realm id>/clients/<id>`       | `clients.delete`  | `clients.security` and an approval |
| `POST /admin/v1-rc.0/realms/<realm id>/clients/<id>/disable` | `clients.disable` | `clients.write`, or as below       |
| `POST /admin/v1-rc.0/realms/<realm id>/clients/<id>/enable`  | `clients.enable`  | `clients.security` and an approval |

`<id>` is the client's `id`, a UUID, not its `client_id`. A client of another
realm answers `404`, as one that does not exist. No answer carries the
client's secret or its hash, and a key set shows its public members only: a
change or registration that sends a private member of a key (`d`, `p`, `k`
and the rest) answers `400`.

## Read the clients

`clients.list` answers every client of the realm, newest first, one page at a
time (`limit`, `cursor`). `q` keeps the clients whose `client_id` or name
holds the text, case ignored. `clients.get` answers one client with its
`ETag`, which a change, a suspension, a deletion and lifting a suspension
name in `If-Match`.

## Change a client

A change is a JSON Merge Patch (RFC 7396) with `Content-Type:
application/merge-patch+json` and the client's `ETag` in `If-Match`. `null`
gives a field its default; `name`, `tokenEndpointAuthMethod` and
`grantTypes` have none. The change is judged field by field, on the client
the patch makes:

| A change of                                                          | Needs                              |
| -------------------------------------------------------------------- | ---------------------------------- |
| the name, the description, `backchannelLogoutSessionRequired`        | `clients.write`                    |
| a scope removed or added, a grant type or response type removed      | `clients.write`                    |
| a stricter environment, PKCE or DPoP switched on, a shorter lifetime | `clients.write`                    |
| the redirect URIs, the post-logout redirect URIs                     | `clients.security` and an approval |
| the authentication method, `jwks`, `jwksUri`                         | `clients.security` and an approval |
| first-party trust, the verified domain, the agent fields             | `clients.security` and an approval |
| a grant or response type added, a `qauth:` scope added               | `clients.security` and an approval |
| a back-channel logout URI set, the `client_credentials` list widened | `clients.security` and an approval |
| a laxer environment, PKCE or DPoP switched off, a longer lifetime    | `clients.security` and an approval |

A patch of both kinds needs both permissions, and one approval. Every patch
needs `clients.read` too: it answers the client.

A client that holds a `qauth:admin:*` scope obtains admin tokens: whoever
changes it changes who administers the realm. Every change of one, a
narrowing too, needs `clients.security` and an approval, and so does
suspending it.

A member the patch does not name is left as stored, even where the rules of
a new registration would write it otherwise. A member the patch names may
change another: removing first-party trust clears its policy and reason.
Each such change is judged as its own. The generated
[security operations](/reference/security-operations/) page lists each
operation's effects.

`clients.preview` takes the same patch and answers what the save would
change and need, without saving it: each field before and after, which way
it moves, its class, and whether the save needs an approval. File the
approval with the client's id in `params` and the patch as the body, then
send the patch with the approval:

```http
POST /admin/v1-rc.0/realms/<realm id>/approvals
Content-Type: application/json

{ "operation": "clients.update", "params": { "clientId": "<id>" },
  "body": { "redirectUris": ["https://app.example.com/callback"] },
  "reason": "The app moved to its new host." }
```

```http
PATCH /admin/v1-rc.0/realms/<realm id>/clients/<id>
Content-Type: application/merge-patch+json
If-Match: "<etag>"
QAuth-Approval: <approval id>

{ "redirectUris": ["https://app.example.com/callback"] }
```

The approval holds only for the client as it stood when it was filed: any
change in between answers `412`.

An approver is shown every change whole: a list as each entry it removes and
adds, a key set as each key, any other field beside the value it replaces.
A change that needs approval and cannot be shown that way answers `422`
before it is filed: a value longer than one line of an approval shows (about
1000 characters), or more lines than the 50 an approval holds, the
client's name and owner among them. File it as smaller changes.
A registration answers `400` for the same reason. Removing first-party trust revokes every
refresh token of the client.

### Token lifetimes

`accessTokenLifespanSeconds` and `refreshTokenLifespanSeconds` give a client
lifetimes of its own, shorter than the realm's (`422` for a longer one);
`null` takes the realm's. A move to another environment is checked against
the lifetimes of that environment's tier. The token endpoint issues the shorter of the two,
so a client never outlives a realm whose lifetimes were shortened after it.

### A CIMD client

A client registered from a Client ID Metadata Document takes its settings
from that document, and every resolution rewrites them. A change, a preview
and a deletion of one answer `409`, naming the document: change the
document. A CIMD client can still be suspended and enabled.

## Register a client

`clients.create` registers a client no developer owns, provisioned by the
operator: the server makes its `id` and `client_id`, and for
`client_secret_basic` and `client_secret_post` its secret, which the answer
carries once, as `clientSecret`. The body takes the same fields as a patch;
`name`, `tokenEndpointAuthMethod` and `grantTypes` are required. The checks
of every registration path apply, the first-party rules and the lifetimes
too.

## Suspend, enable and delete

`clients.disable` suspends the client: it obtains no token, and its owner
cannot lift the suspension. The suspension revokes every refresh token the
client holds and spends its authorization codes not yet redeemed, in the same
transaction, so lifting it brings none of them back: the client's users sign
in through it again ([Clients and realms](/operate/accounts/#clients-and-realms)).
`clients.enable` ends, as it lifts the suspension, whatever of the client a
suspension by hand left.
It only takes tokens away, so it needs no
approval, unless the client obtains admin tokens (above). It names the
client's `ETag` in `If-Match`, so the approval of such a suspension holds for
the client it was filed for. `clients.enable` lifts the suspension, and
switches on a client no developer owns; a developer's own switch stays
theirs. It needs an approval, as `clients.delete` does, which removes the
client with its authorization codes, refresh tokens, consents and API keys.

The seed manifest writes a client it provisions again on each run, and the
server gives each realm's system client what it needs as it boots: change
such a client in the manifest, or the next run may undo an admin's change.

Each change records the client's events with the admin as their actor:
`client.created` (registration `admin_api`), `client.updated`,
`client.deleted`, `client.suspended`, `client.suspension_lifted`,
`client.first_party_changed` and `client.verified_domain_changed`
([Events](/reference/events/)).
